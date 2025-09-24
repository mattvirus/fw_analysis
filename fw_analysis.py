#!/usr/bin/env python3
"""
fw_analysis.py

Expanded firmware analysis helper:
- Carves candidate blobs from BIN images (SquashFS, XZ, LZMA, gzip, JFFS2 markers)
- Attempts nested decompression (gzip, xz, lzma) in-Python (safe caps)
- If `unsquashfs` is available, unsquashes SquashFS blobs into `unsquashed/`
- Recursively scans carved blobs and extracted filesystem trees for IOCs and suspicious artifacts:
    * domains, IPv4s, URLs, emails
    * /etc/passwd, /etc/shadow-like lines
    * init.d references, service config paths
    * PEM/private key beginnings
    * telnet/ssh/dropbear mentions and updater/p2p/cloud keywords
- Writes outputs:
    OUT_DIR/
      carved/
      extracted/         (nested decompressed artifacts)
      unsquashed/        (if unsquashfs succeeds)
      iocs/              (CSV lists)
      REPORT.md

Usage:
    python3 firmware_finder_extended.py -i firmware.bin -o analysis_out

Requirements:
    - Python 3.8+ (3.10 recommended)
    - Optional: unsquashfs (squashfs-tools) on PATH to expand SquashFS blobs
"""
import argparse
import os
import io
import json
import gzip
import lzma
import shutil
import struct
import subprocess
import hashlib
import tarfile
import re
from pathlib import Path
from datetime import datetime
from typing import List, Tuple, Dict, Optional

# ---------- Config / limits ----------
STRING_MIN_LEN = 5
STRING_CAP_BYTES = 64 * 1024 * 1024   # cap string extraction to first 64 MB of a blob
NESTED_DECOMPRESS_CAP = 8 * 1024 * 1024  # cap nested decompressed output to 8 MB
CARVE_MIN_SIZE = 256 * 1024  # minimum carve size to consider standalone; else extend to EOF
MAX_CARVE_FILES = 200
# ---------- Regexes ----------
RE_DOMAIN = re.compile(r"\b(?:[a-z0-9-]{1,63}\.)+(?:[a-z]{2,63})\b", re.I)
RE_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?!$)|$)){4}\b")
RE_URL = re.compile(r"\bhttps?://[^\s\"'<>]+", re.I)
RE_EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b", re.I)
RE_SHADOW_LINE = re.compile(r"^[a-z_][a-z0-9_-]*:[^:]*:\d{1,}:", re.I | re.M)
RE_PASSWD_PATH = re.compile(r"/etc/(passwd|shadow|group)\b")
RE_INITD_PATH = re.compile(r"/etc/init\.d/[^\s\"']+")
RE_SERVICE_CFG = re.compile(r"/etc/(dnsmasq|hostapd|wpa_supplicant|network|inittab|lighttpd|nginx|dropbear)[^\s\"']*", re.I)
RE_PEM_BEGIN = re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH|PRIVATE) KEY-----")
RE_TELNET = re.compile(r"\btelnetd\b", re.I)
RE_SSH = re.compile(r"\b(dropbear|sshd)\b", re.I)
RE_UPDATER = re.compile(r"\b(ota|auto[-_]?update|update|upgrader|fwupgrade|cloud|p2p|tutk|xmeye|relay|broker|nat[-_]?traversal)\b", re.I)

# ---------- Magic signatures ----------
SIGS = {
    "gzip": b"\x1f\x8b\x08",
    "xz": b"\xfd7zXZ\x00".replace(b'7', bytes([0x37])),
    "lzma": b"\x5d\x00\x00\x80\x00",
    "squashfs_le": b"hsqs",
    "squashfs_be": b"sqsh",
    "jffs2": struct.pack(">H", 0x1985),
    "uboot": struct.pack(">I", 0x27051956),
    "ubi": b"UBI#",
    "elf": b"\x7fELF",
}

# ---------- Helper functions ----------
def sha256_bytes(b: bytes) -> str:
    h = hashlib.sha256(); h.update(b); return h.hexdigest()

def read_all(path: Path) -> bytes:
    return path.read_bytes()

def find_all(hay: bytes, needle: bytes, jffs2_aligned: bool = False) -> List[int]:
    res = []
    if jffs2_aligned:
        for i in range(0, len(hay), 4):
            if hay[i:i+2] == needle:
                res.append(i)
        return res
    off = 0
    while True:
        idx = hay.find(needle, off)
        if idx == -1:
            break
        res.append(idx)
        off = idx + 1
    return res

def extract_strings(b: bytes, min_len=STRING_MIN_LEN, cap: Optional[int] = STRING_CAP_BYTES) -> List[str]:
    if cap and len(b) > cap:
        b = b[:cap]
    result = []
    cur = []
    for byte in b:
        if 32 <= byte <= 126 or byte in (9,10,13):
            cur.append(chr(byte))
        else:
            if len(cur) >= min_len:
                result.append("".join(cur))
            cur = []
    if len(cur) >= min_len:
        result.append("".join(cur))
    return result

def try_gzip_decompress(b: bytes, cap_out=NESTED_DECOMPRESS_CAP) -> Optional[bytes]:
    try:
        bio = io.BytesIO(b)
        with gzip.GzipFile(fileobj=bio) as gz:
            out = gz.read(cap_out + 1)
            return out[:cap_out]
    except Exception:
        return None

def try_lzma_decompress(b: bytes, cap_out=NESTED_DECOMPRESS_CAP) -> Optional[bytes]:
    # try as xz/alone/auto
    for fmt in (lzma.FORMAT_XZ, lzma.FORMAT_ALONE, lzma.FORMAT_AUTO):
        try:
            out = lzma.decompress(b, format=fmt)
            if len(out) > cap_out:
                return out[:cap_out]
            return out
        exc
