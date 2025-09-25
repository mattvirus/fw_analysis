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
    python3 fw_analysis.py -i firmware.bin -o analysis_out

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
# These knobs keep processing safe and predictable for very large firmware files.
STRING_MIN_LEN = 5
STRING_CAP_BYTES = 64 * 1024 * 1024   # cap string extraction to first 64 MB of a blob
NESTED_DECOMPRESS_CAP = 8 * 1024 * 1024  # cap nested decompressed output to 8 MB
CARVE_MIN_SIZE = 256 * 1024  # minimum carve size to consider standalone; else extend to EOF
MAX_CARVE_FILES = 200
# ---------- Regexes ----------
# Patterns we search for inside text to spot indicators of compromise or interest.
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
# Short byte patterns that identify known embedded formats inside a firmware blob.
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
    """Read an entire file into memory as raw bytes."""
    return path.read_bytes()

def find_all(hay: bytes, needle: bytes, jffs2_aligned: bool = False) -> List[int]:
    """Find all positions of a short signature inside a larger byte array.

    If jffs2_aligned is True, only check every 4 bytes (JFFS2 header alignment).
    """
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
    """Extract human-readable strings from raw bytes.

    We keep it simple: any sequence of printable characters (and whitespace) of
    length >= min_len becomes a string. We also cap reading to avoid huge files.
    """
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
    """Try to decompress a gzip-compressed blob safely.

    Returns decompressed bytes (capped) or None if it doesn't look like gzip.
    """
    try:
        bio = io.BytesIO(b)
        with gzip.GzipFile(fileobj=bio) as gz:
            out = gz.read(cap_out + 1)
            return out[:cap_out]
    except Exception:
        return None

def try_lzma_decompress(b: bytes, cap_out=NESTED_DECOMPRESS_CAP) -> Optional[bytes]:
    """Try to decompress data using LZMA-based formats (xz/alone/auto).

    Returns decompressed bytes (capped) or None if not applicable.
    """
    # try as xz/alone/auto
    for fmt in (lzma.FORMAT_XZ, lzma.FORMAT_ALONE, lzma.FORMAT_AUTO):
        try:
            out = lzma.decompress(b, format=fmt)
            if len(out) > cap_out:
                return out[:cap_out]
            return out
        except Exception:
            continue
    return None

# ---------- Carving and detection ----------
def detect_segments(img: bytes) -> List[Tuple[int, str]]:
    """Find where known embedded formats start inside the firmware image.

    Returns a list of (offset, kind) pairs sorted by offset, where kind labels
    the format (e.g., gzip, xz, squashfs).
    """
    hits: List[Tuple[int, str]] = []
    for kind, sig in SIGS.items():
        jffs2_aligned = (kind == "jffs2")
        for off in find_all(img, sig, jffs2_aligned=jffs2_aligned):
            hits.append((off, kind))
    hits.sort(key=lambda x: x[0])
    return hits

def carve_segments(img: bytes) -> List[Tuple[int, int, str]]:
    """Decide which byte ranges to save out as separate files.

    We create (start, end, kind) entries using simple heuristics: we cut at the
    next signature or EOF and enforce minimum sizes so tiny false-positives do
    not overwhelm the results.
    """
    marks = detect_segments(img)
    if not marks:
        return []
    ranges: List[Tuple[int, int, str]] = []
    for idx, (start, kind) in enumerate(marks):
        # Default end is next signature offset; fallback to EOF
        end = marks[idx + 1][0] if idx + 1 < len(marks) else len(img)
        size = max(0, end - start)
        # Small blobs can still be valid; extend to EOF if below threshold
        if size < CARVE_MIN_SIZE:
            end = len(img)
            size = end - start
        if size <= 0:
            continue
        ranges.append((start, end, kind))
        if len(ranges) >= MAX_CARVE_FILES:
            break
    return ranges

def write_carved(img: bytes, out_dir: Path) -> List[Path]:
    """Write carved byte ranges to disk under out_dir/carved/.

    Filenames include an index, detected type, offsets, and a short hash to help
    humans keep track of what came from where.
    """
    carved_dir = out_dir / "carved"
    carved_dir.mkdir(parents=True, exist_ok=True)
    segments = carve_segments(img)
    written: List[Path] = []
    for i, (start, end, kind) in enumerate(segments):
        blob = img[start:end]
        sha = sha256_bytes(blob)[:16]
        path = carved_dir / f"{i:04d}_{kind}_{start:x}-{end:x}_{sha}.bin"
        try:
            path.write_bytes(blob)
            written.append(path)
        except Exception:
            continue
    return written

# ---------- Nested extraction ----------
def try_nested_extract(src_path: Path, out_dir: Path) -> Optional[Path]:
    """Try to decompress a carved file if it looks compressed (gzip/xz/lzma)."""
    data = src_path.read_bytes()
    # Try gzip
    gz = try_gzip_decompress(data)
    if gz:
        dst = out_dir / (src_path.stem + ".ungz")
        dst.write_bytes(gz)
        return dst
    # Try lzma/xz
    lz = try_lzma_decompress(data)
    if lz:
        dst = out_dir / (src_path.stem + ".unxz")
        dst.write_bytes(lz)
        return dst
    return None

def nested_extract_all(carved_paths: List[Path], out_dir: Path) -> List[Path]:
    """Run decompression attempts across all carved files and save results."""
    ext_dir = out_dir / "extracted"
    ext_dir.mkdir(parents=True, exist_ok=True)
    results: List[Path] = []
    for p in carved_paths:
        try:
            dst = try_nested_extract(p, ext_dir)
            if dst:
                results.append(dst)
        except Exception:
            continue
    return results

# ---------- SquashFS expansion ----------
def unsquash_if_available(carved_paths: List[Path], out_dir: Path) -> List[Path]:
    """If the 'unsquashfs' tool is installed, expand any SquashFS filesystems.

    Each SquashFS is extracted into its own folder so files can be searched.
    """
    unsq = shutil.which("unsquashfs")
    if not unsq:
        return []
    dest_base = out_dir / "unsquashed"
    dest_base.mkdir(parents=True, exist_ok=True)
    expanded: List[Path] = []
    for p in carved_paths:
        try:
            data = p.read_bytes()
            # Quick signature check for SquashFS
            if b"hsqs" not in data and b"sqsh" not in data:
                continue
            target_dir = dest_base / p.stem
            target_dir.mkdir(parents=True, exist_ok=True)
            # unsquashfs -d target_dir file
            cmd = [unsq, "-d", str(target_dir), str(p)]
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
            if proc.returncode == 0:
                expanded.append(target_dir)
        except Exception:
            continue
    return expanded

# ---------- IOC scanning ----------
def scan_strings_for_iocs(strings: List[str]) -> Dict[str, List[str]]:
    """Search a list of strings for domains, IPs, URLs, emails, keys, etc."""
    res: Dict[str, List[str]] = {
        "domains": [],
        "ipv4": [],
        "urls": [],
        "emails": [],
        "pem_keys": [],
        "services": [],
        "updaters": [],
        "initd": [],
        "etc_paths": [],
        "shadow_like": [],
    }
    for s in strings:
        if RE_DOMAIN.search(s):
            res["domains"].extend(RE_DOMAIN.findall(s))
        if RE_IPV4.search(s):
            res["ipv4"].extend(RE_IPV4.findall(s))
        if RE_URL.search(s):
            res["urls"].extend(RE_URL.findall(s))
        if RE_EMAIL.search(s):
            res["emails"].extend(RE_EMAIL.findall(s))
        if RE_PEM_BEGIN.search(s):
            res["pem_keys"].append(s)
        if RE_TELNET.search(s) or RE_SSH.search(s):
            res["services"].append(s)
        if RE_UPDATER.search(s):
            res["updaters"].append(s)
        if RE_INITD_PATH.search(s):
            res["initd"].extend(RE_INITD_PATH.findall(s))
        if RE_PASSWD_PATH.search(s):
            res["etc_paths"].extend(RE_PASSWD_PATH.findall(s))
        if RE_SHADOW_LINE.search(s):
            res["shadow_like"].append(s)
    # Deduplicate
    for k in res:
        res[k] = sorted(set(res[k]))
    return res

def scan_file_for_iocs(path: Path) -> Dict[str, List[str]]:
    """Read a file, extract strings, and detect indicators of interest."""
    try:
        data = path.read_bytes()
    except Exception:
        return {k: [] for k in [
            "domains", "ipv4", "urls", "emails", "pem_keys", "services",
            "updaters", "initd", "etc_paths", "shadow_like"
        ]}
    strings = extract_strings(data)
    return scan_strings_for_iocs(strings)

def scan_directory_tree(root: Path) -> Dict[str, List[str]]:
    """Walk a directory and aggregate indicators found in all files."""
    aggregate: Dict[str, List[str]] = {
        "domains": [], "ipv4": [], "urls": [], "emails": [], "pem_keys": [],
        "services": [], "updaters": [], "initd": [], "etc_paths": [], "shadow_like": []
    }
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in filenames:
            p = Path(dirpath) / fn
            res = scan_file_for_iocs(p)
            for k, vals in res.items():
                aggregate[k].extend(vals)
    for k in aggregate:
        aggregate[k] = sorted(set(aggregate[k]))
    return aggregate

def write_iocs_csv(iocs: Dict[str, List[str]], out_dir: Path, prefix: str) -> None:
    """Save each category of indicators into its own CSV file."""
    iocs_dir = out_dir / "iocs"
    iocs_dir.mkdir(parents=True, exist_ok=True)
    for k, vals in iocs.items():
        fp = iocs_dir / f"{prefix}_{k}.csv"
        with fp.open("w", encoding="utf-8") as f:
            for v in vals:
                f.write(f"{v}\n")

def build_report(counts: Dict[str, int], out_dir: Path) -> None:
    """Create a short markdown summary with counts for quick review."""
    report = out_dir / "REPORT.md"
    now = datetime.utcnow().isoformat() + "Z"
    lines = [
        f"# Firmware Analysis Report",
        "",
        f"Generated: {now}",
        "",
        "## Summary",
    ]
    for k, v in counts.items():
        lines.append(f"- {k}: {v}")
    report.write_text("\n".join(lines), encoding="utf-8")

# ---------- Orchestration / CLI ----------
def analyze_firmware(input_path: Path, out_dir: Path) -> None:
    """End-to-end flow: carve, decompress, expand filesystems, scan, and report.

    This coordinates the whole process and writes all outputs under out_dir.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    img = read_all(input_path)
    carved_paths = write_carved(img, out_dir)
    extracted_paths = nested_extract_all(carved_paths, out_dir)
    unsquashed_dirs = unsquash_if_available(carved_paths + extracted_paths, out_dir)

    # Scan: carved files
    agg_iocs: Dict[str, List[str]] = {k: [] for k in [
        "domains", "ipv4", "urls", "emails", "pem_keys", "services",
        "updaters", "initd", "etc_paths", "shadow_like"
    ]}
    for p in carved_paths + extracted_paths:
        file_iocs = scan_file_for_iocs(p)
        for k, vals in file_iocs.items():
            agg_iocs[k].extend(vals)
    # Scan: unsquashed directories
    for d in unsquashed_dirs:
        dir_iocs = scan_directory_tree(d)
        for k, vals in dir_iocs.items():
            agg_iocs[k].extend(vals)
    for k in agg_iocs:
        agg_iocs[k] = sorted(set(agg_iocs[k]))
    write_iocs_csv(agg_iocs, out_dir, prefix="all")

    counts = {
        "carved_files": len(carved_paths),
        "extracted_artifacts": len(extracted_paths),
        "unsquashed_dirs": len(unsquashed_dirs),
        "domains": len(agg_iocs["domains"]),
        "ipv4": len(agg_iocs["ipv4"]),
        "urls": len(agg_iocs["urls"]),
        "emails": len(agg_iocs["emails"]),
        "pem_keys": len(agg_iocs["pem_keys"]),
        "services": len(agg_iocs["services"]),
        "updaters": len(agg_iocs["updaters"]),
        "initd": len(agg_iocs["initd"]),
        "etc_paths": len(agg_iocs["etc_paths"]),
        "shadow_like": len(agg_iocs["shadow_like"]),
    }
    build_report(counts, out_dir)


def main() -> None:
    """Command-line interface: parse arguments and start the analysis."""
    parser = argparse.ArgumentParser(description="Firmware binary analysis helper")
    parser.add_argument("-i", "--input", required=True, help="Path to firmware image (bin)")
    parser.add_argument("-o", "--out", required=True, help="Output directory for artifacts")
    args = parser.parse_args()
    input_path = Path(args.input)
    out_dir = Path(args.out)
    analyze_firmware(input_path, out_dir)


if __name__ == "__main__":
    main()
