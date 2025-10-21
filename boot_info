#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
boot_info — Forensic MBR/GPT analyzer
Works on Ubuntu 18.04+ with Python 3 (standard library only).

Generative AI Used: ChatGPT (OpenAI, Oct 20, 2025)
Purpose: Produce a minimal-yet-complete scaffold meeting assignment I/O & parsing requirements.
Prompt: "Give me a full Python code framework for the MBR/GPT homework including hashes, JSON/text output, and partition parsing."
"""

import argparse
import csv
import json
import os
import struct
import sys
import hashlib
from typing import Dict, List, Optional, Tuple

SECTOR_SIZE = 512

# ---- Minimal built-in MBR type mapping (can be overridden by external csv/json) ----
BUILTIN_MBR_TYPES = {
    "00": "Empty",
    "01": "FAT12",
    "04": "FAT16 <32M",
    "05": "Extended",
    "06": "FAT16",
    "07": "HPFS/NTFS/exFAT",
    "0b": "W95 FAT32",
    "0c": "W95 FAT32 (LBA)",
    "0e": "W95 FAT16 (LBA)",
    "0f": "W95 Ext'd (LBA)",
    "82": "Linux swap / Solaris",
    "83": "Linux",
    "8e": "Linux LVM",
    "a5": "FreeBSD",
    "a8": "Mac OS X UFS",
    "a9": "NetBSD",
    "ab": "Mac OS X boot",
    "af": "Apple HFS/HFS+",
    "ee": "GPT Protective",
    "ef": "EFI (FAT-12/16/32)",
}

# -------------------- Utilities --------------------

def human_is_printable(b: int) -> bool:
    return 32 <= b <= 126  # basic ASCII printable

def to_ascii_line(buf: bytes) -> str:
    return " ".join(chr(b) if human_is_printable(b) else "." for b in buf)

def hexdump_inline(buf: bytes) -> str:
    return " ".join(f"{b:02x}" for b in buf)

def read_at(f, off: int, size: int) -> bytes:
    f.seek(off, os.SEEK_SET)
    return f.read(size)

def le_u16(b: bytes) -> int:
    return struct.unpack("<H", b)[0]

def le_u32(b: bytes) -> int:
    return struct.unpack("<I", b)[0]

def le_u64(b: bytes) -> int:
    return struct.unpack("<Q", b)[0]

def ensure_hash_dir():
    os.makedirs("hash_info", exist_ok=True)

def write_hash_file(algo: str, filename: str, value: str):
    # filenames like: MD5-[filename.raw].txt, SHA-256-[filename.raw].txt, SHA-512-[filename.raw].txt
    outname = f"{algo.upper()}-{os.path.basename(filename)}.txt"
    with open(os.path.join("hash_info", outname), "w") as fw:
        fw.write(value.strip() + "\n")

def compute_hashes(path: str) -> Dict[str, str]:
    """Compute MD5, SHA-256, SHA-512 in streaming fashion and write files in hash_info/."""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()

    with open(path, "rb") as fr:
        while True:
            chunk = fr.read(1024 * 1024)
            if not chunk:
                break
            md5.update(chunk)
            sha256.update(chunk)
            sha512.update(chunk)

    md5_hex = md5.hexdigest()
    sha256_hex = sha256.hexdigest()
    sha512_hex = sha512.hexdigest()

    ensure_hash_dir()
    write_hash_file("MD5", path, md5_hex)
    write_hash_file("SHA-256", path, sha256_hex)
    write_hash_file("SHA-512", path, sha512_hex)

    return {"md5": md5_hex, "sha256": sha256_hex, "sha512": sha512_hex}

def load_mbr_types_from_csv(csv_path: str) -> Dict[str, str]:
    mapping = {}
    with open(csv_path, newline="", encoding="utf-8") as fr:
        reader = csv.DictReader(fr)
        # expect columns like "hex","name" or similar
        for row in reader:
            hexv = (row.get("hex") or row.get("type") or "").strip().lower().lstrip("0x")
            name = (row.get("name") or row.get("type_name") or "").strip()
            if hexv and name:
                mapping[f"{int(hexv,16):02x}"] = name
    return mapping

def load_mbr_types_from_json(json_path: str) -> Dict[str, str]:
    mapping = {}
    with open(json_path, "r", encoding="utf-8") as fr:
        data = json.load(fr)
    # support dict {"07": "NTFS", ...} or list of {"hex":"07","name":"NTFS"}
    if isinstance(data, dict):
        for k, v in data.items():
            mapping[f"{int(k,16):02x}"] = str(v)
    elif isinstance(data, list):
        for item in data:
            hexv = str(item.get("hex", "")).strip().lower().lstrip("0x")
            name = str(item.get("name", "")).strip()
            if hexv and name:
                mapping[f"{int(hexv,16):02x}"] = name
    return mapping

def load_type_mapping(optional_path: Optional[str]) -> Dict[str, str]:
    mapping = dict(BUILTIN_MBR_TYPES)
    if optional_path and os.path.exists(optional_path):
        try:
            if optional_path.lower().endswith(".csv"):
                mapping.update(load_mbr_types_from_csv(optional_path))
            elif optional_path.lower().endswith(".json"):
                mapping.update(load_mbr_types_from_json(optional_path))
        except Exception:
            # fall back silently to built-in if parsing provided file fails
            pass
    return mapping

# -------------------- MBR Parsing --------------------

class MBRPartition:
    def __init__(self, index: int, type_hex: str, type_name: str, start_lba: int, size_sectors: int):
        self.index = index
        self.type_hex = type_hex.upper()
        self.type_name = type_name
        self.start_lba = start_lba
        self.size_sectors = size_sectors
        self.boot_bytes: Optional[Dict] = None  # filled if we read boot sector snippet

def detect_mbr_signature(first_sector: bytes) -> bool:
    return len(first_sector) >= 512 and first_sector[510:512] == b"\x55\xaa"

def parse_mbr_partitions(first_sector: bytes, type_map: Dict[str, str]) -> List[MBRPartition]:
    parts: List[MBRPartition] = []
    table_off = 446
    for i in range(4):
        entry = first_sector[table_off + i*16 : table_off + (i+1)*16]
        if len(entry) < 16:
            continue
        type_hex = f"{entry[4]:02x}"  # partition type byte
        if type_hex == "00":
            continue  # skip empty per assignment
        start_lba = le_u32(entry[8:12])
        size_sectors = le_u32(entry[12:16])
        type_name = type_map.get(type_hex, "Unknown")
        parts.append(MBRPartition(i+1, type_hex, type_name, start_lba, size_sectors))
    return parts

def read_mbr_boot_bytes(f, part: MBRPartition, raw_offset_value: int) -> Dict:
    """Read 16 bytes from partition's first sector at 'wrapped' offset (offset % 512).
       Also return original offset for JSON.
    """
    boot_lba = part.start_lba
    sector = read_at(f, boot_lba * SECTOR_SIZE, SECTOR_SIZE)
    if not sector or len(sector) < SECTOR_SIZE:
        snippet = b""
    else:
        off = raw_offset_value % SECTOR_SIZE
        # handle wrap if near end
        if off + 16 <= SECTOR_SIZE:
            snippet = sector[off:off+16]
        else:
            # wrap around inside the 512-byte sector
            part1 = sector[off:SECTOR_SIZE]
            part2 = sector[: (off + 16) - SECTOR_SIZE]
            snippet = part1 + part2

    hexline = hexdump_inline(snippet).strip() if snippet else ""
    asciiline = to_ascii_line(snippet) if snippet else ""
    return {
        "offset": raw_offset_value,
        "wrapped_offset": raw_offset_value % SECTOR_SIZE,
        "hex": hexline,
        "ascii": asciiline.replace(" ", "  "),  # match sample spacing style a bit
    }

# -------------------- GPT Parsing --------------------

class GPTPartition:
    def __init__(self, index: int, type_guid: str, start_lba: int, end_lba: int, name: str):
        self.index = index
        self.type_guid = type_guid  # 32 hex chars no dashes per example
        self.start_lba = start_lba
        self.end_lba = end_lba
        self.name = name

def is_gpt_protective_mbr(first_sector: bytes) -> bool:
    # MBR partition type 0xEE (first entry) indicates GPT protective MBR often
    table_off = 446
    e0 = first_sector[table_off:table_off+16]
    return len(e0) == 16 and e0[4] == 0xEE

def detect_gpt_header(f) -> bool:
    # GPT header at LBA 1, signature "EFI PART"
    hdr = read_at(f, 1 * SECTOR_SIZE, 92)  # first 92 bytes is enough for signature & key fields
    return len(hdr) >= 8 and hdr[:8] == b"EFI PART"

def parse_gpt_partitions(f) -> List[GPTPartition]:
    # Read GPT header
    hdr = read_at(f, 1 * SECTOR_SIZE, SECTOR_SIZE)
    if len(hdr) < 92 or hdr[:8] != b"EFI PART":
        return []

    # Offsets per UEFI spec (little-endian):
    # 0x48: Number of partition entries (uint32)
    # 0x4C: Size of a single partition entry (uint32)
    # 0x48 earlier fields include 0x48? (spec diff); using standard:
    # 0x48: Partition entry LBA (uint64) [actually at 0x48]
    # 0x50: Number of entries (uint32)
    # 0x54: Size of each entry (uint32)
    # We'll follow common layout:
    part_entry_lba = le_u64(hdr[0x48:0x50])
    num_entries    = le_u32(hdr[0x50:0x54])
    entry_size     = le_u32(hdr[0x54:0x58])

    # Safety clamps
    if entry_size < 128 or entry_size > 4096:
        return []

    # Read partition entries array (we only need until encounter all-zero type GUID)
    entries_bytes = read_at(f, part_entry_lba * SECTOR_SIZE, num_entries * entry_size)
    parts: List[GPTPartition] = []

    for i in range(num_entries):
        base = i * entry_size
        entry = entries_bytes[base : base + entry_size]
        if len(entry) < 128:
            break

        type_guid_le = entry[0:16]  # 16 bytes
        if all(b == 0 for b in type_guid_le):
            continue  # unused

        start_lba = le_u64(entry[32:40])
        end_lba   = le_u64(entry[40:48])

        # Partition name: UTF-16LE, 72 bytes at offset 56
        raw_name = entry[56:56+72]
        try:
            name = raw_name.decode("utf-16le").rstrip("\x00")
        except Exception:
            name = ""

        # Represent GUID as 32 hex chars without dashes per assignment example.
        type_guid_hex = "".join(f"{b:02x}" for b in type_guid_le)

        parts.append(GPTPartition(
            index=i+1,
            type_guid=type_guid_hex,
            start_lba=start_lba,
            end_lba=end_lba,
            name=name or "",
        ))
    return parts

# -------------------- Scheme Detection & Orchestration --------------------

def detect_scheme(f) -> str:
    first_sector = read_at(f, 0, SECTOR_SIZE)
    if not detect_mbr_signature(first_sector):
        # Could still be GPT but if MBR signature missing, treat as UNKNOWN
        return "UNKNOWN"
    # If GPT header exists at LBA1 -> GPT
    if is_gpt_protective_mbr(first_sector) and detect_gpt_header(f):
        return "GPT"
    # Otherwise MBR
    return "MBR"

# -------------------- Output --------------------

def print_text_mbr(parts: List[MBRPartition]):
    for p in parts:
        # Start Sector Address: assignment例子里像是字节地址，但题干又写“起始扇区地址（byte address）”
        # 这里保持“起始扇区号”语义与示例一致（示例里数值看起来像扇区号/或字节？官方样例如有歧义，以作业样例为准）
        print(f"({p.type_hex}), {p.type_name} , {p.start_lba}, {p.size_sectors}")
    for p in parts:
        if p.boot_bytes:
            bb = p.boot_bytes
            print(f"Partition number: {p.index}")
            print(f"16 bytes of boot record from offset {bb['offset']}: {bb['hex']}")
            # 对齐与样例接近：在 "ASCII:" 后面增加适度空格
            print(f"ASCII:                                    {bb['ascii']}")

def print_text_gpt(gparts: List[GPTPartition]):
    for p in gparts:
        print(f"Partition number: {p.index}")
        print(f"Partition Type GUID : {p.type_guid.upper()}")
        print(f"Starting LBA in hex: 0x{p.start_lba:x}")
        print(f"ending LBA in hex: 0x{p.end_lba:x}")
        print(f"starting LBA in Decimal: {p.start_lba}")
        print(f"ending LBA in Decimal: {p.end_lba}")
        print(f"Partition name: {p.name}\n")

def build_json(image: str,
               hashes: Dict[str,str],
               scheme: str,
               mbr_parts: List[MBRPartition],
               gpt_parts: List[GPTPartition]) -> Dict:
    mbr_obj = {"partitions": []}
    for p in mbr_parts:
        entry = {
            "index": p.index,
            "type_hex": p.type_hex.lower() if False else p.type_hex,  # examples show both; we keep upper
            "type_name": p.type_name,
            "start_lba": p.start_lba,
            "size_sectors": p.size_sectors,
        }
        if p.boot_bytes:
            entry["boot_bytes"] = {
                "offset": p.boot_bytes["offset"],
                "wrapped_offset": p.boot_bytes["wrapped_offset"],
                "hex": p.boot_bytes["hex"],
                "ascii": p.boot_bytes["ascii"].replace("  ", " "),  # JSON example used single spaces between dots
            }
        mbr_obj["partitions"].append(entry)

    gpt_obj = {"partitions": []}
    for p in gpt_parts:
        gpt_obj["partitions"].append({
            "index": p.index,
            "type_guid": p.type_guid,
            "start_lba_hex": f"0x{p.start_lba:x}",
            "end_lba_hex": f"0x{p.end_lba:x}",
            "start_lba": p.start_lba,
            "end_lba": p.end_lba,
            "name": p.name
        })

    return {
        "image": os.path.basename(image),
        "hashes": hashes,
        "scheme": scheme,
        "mbr": mbr_obj,
        "gpt": gpt_obj
    }

# -------------------- Main --------------------

def parse_args():
    ap = argparse.ArgumentParser(description="Analyze MBR/GPT of a raw disk image.")
    ap.add_argument("-f", "--file", required=True, help="path to raw image (e.g., sample.raw)")
    ap.add_argument("-o", "--offsets", nargs="*", type=int, default=[],
                    help="offset values (integers) for MBR partitions boot record 16-byte snippet")
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON only")
    ap.add_argument("--types", help="optional path to MBR types csv/json to override built-in")
    # Optional: verbose for debugging (bonus idea)
    ap.add_argument("--verbose", action="store_true", help="verbose diagnostic prints (bonus)")
    return ap.parse_args()

def main():
    args = parse_args()

    image_path = args.file
    if not os.path.exists(image_path):
        print(f"Error: file not found: {image_path}", file=sys.stderr)
        sys.exit(2)

    # 1) Hashes first (before analyzing image), write into hash_info/
    hashes = compute_hashes(image_path)

    # 2) Open image read-only
    with open(image_path, "rb") as f:
        # 3) Detect scheme
        scheme = detect_scheme(f)

        # 4) Load MBR type mapping
        type_map = load_type_mapping(args.types)

        mbr_parts: List[MBRPartition] = []
        gpt_parts: List[GPTPartition] = []

        if scheme == "MBR":
            first_sector = read_at(f, 0, SECTOR_SIZE)
            mbr_parts = parse_mbr_partitions(first_sector, type_map)

            # Read 16-byte snippets per partition using provided offsets
            # If fewer offsets provided than partitions, unspecified ones just won't have boot_bytes
            for idx, part in enumerate(mbr_parts):
                if idx < len(args.offsets):
                    raw_off = args.offsets[idx]
                    part.boot_bytes = read_mbr_boot_bytes(f, part, raw_off)

        elif scheme == "GPT":
            # GPT partitions ignore offsets per assignment
            gpt_parts = parse_gpt_partitions(f)

        else:
            # UNKNOWN: leave both lists empty
            pass

    # 5) Output
    if args.json:
        out = build_json(image_path, hashes, scheme, mbr_parts, gpt_parts)
        # strict: output only JSON (no extra text)
        sys.stdout.write(json.dumps(out, separators=(",", ":"), ensure_ascii=False))
        return

    # Text mode
    if scheme == "MBR":
        print_text_mbr(mbr_parts)
    elif scheme == "GPT":
        print_text_gpt(gpt_parts)
    else:
        print("UNKNOWN partitioning scheme")

if __name__ == "__main__":
    main()

