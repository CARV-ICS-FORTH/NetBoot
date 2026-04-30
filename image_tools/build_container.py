#!/usr/bin/env python3
"""
Image Container Builder

Creates a bootable image container from FSBL and DTB files according to
the format specified in img.h, with LZ4 compression and CRC32 validation.
Optionally signs the container with an Ed25519 key.
"""

import os
import struct
import sys
from pathlib import Path

try:
    import lz4.block
except ImportError:
    print("Error: lz4 module not found. Install with: pip install lz4", file=sys.stderr)
    sys.exit(1)

# CRC32 polynomial matching the implementation in image_parser.c
CRC32_POLY = 0xEDB88320
CRC32_REMAINDER = 0x2144DF1C

# Global header flags
GBL_FLAG_NO_CRYPTO = 0
GBL_FLAG_ED25519 = 1
GBL_FLAG_ECDSA384 = 2

# Image types
IMG_TYPE_BOOT_STEP = 0
IMG_TYPE_FBSL = 1
IMG_TYPE_DTB = 2

# Partition flags
PART_FLAG_UNCOMPRESSED = 0
PART_FLAG_LZ4 = 1

# Magic value for global header
MAGIC_VALUE = 0x424E  # "NB" for NetBoot

# Header version
HDR_VERSION = 0

# Key / signature sizes per algorithm
PUBKEY_SIZES = {GBL_FLAG_ED25519: 32, GBL_FLAG_ECDSA384: 96}
SIG_SIZES    = {GBL_FLAG_ED25519: 64, GBL_FLAG_ECDSA384: 96}


def init_crc32_nibbles():
    """Pre-calculate CRC32 nibble lookup table (matches imgp_init_crc32_nibbles)"""
    nibble_table = []
    for i in range(16):
        crc = i
        for _ in range(4):
            if crc & 1:
                crc = (crc >> 1) ^ CRC32_POLY
            else:
                crc >>= 1
        nibble_table.append(crc)
    return nibble_table


def crc32_update(crc, data, nibble_table):
    """Update CRC32 value with new data (matches imgp_crc32_update)"""
    for byte in data:
        # Process low nibble
        crc = (crc >> 4) ^ nibble_table[(crc ^ (byte & 0x0F)) & 0x0F]
        # Process high nibble
        crc = (crc >> 4) ^ nibble_table[(crc ^ (byte >> 4)) & 0x0F]
    return crc


def pad_to_8bytes(data):
    """Pad data to 8-byte boundary"""
    remainder = len(data) % 8
    if remainder:
        padding = 8 - remainder
        return data + b'\x00' * padding
    return data


def build_global_header(partition_count, total_size, flags=GBL_FLAG_NO_CRYPTO):
    """
    Build global header:
    [Magic (16bit)][Header version (4bit)][Partition count (4bit)][Flags (8bit)][Total size (32bit)]
    """
    version_count = (partition_count << 4) | (HDR_VERSION & 0x0F)
    return struct.pack('<HBBI', MAGIC_VALUE, version_count, flags, total_size)


def build_partition_header(release_id, img_type, unit_id, flags, image_size):
    """
    Build partition header:
    [Release ID (16bit)][Type (4bit)][Unit ID (4bit)][Flags (8bit)][Image size (32bit)]
    """
    type_unit = (unit_id << 4) | (img_type & 0x0F)
    return struct.pack('<HBBI', release_id, type_unit, flags, image_size)


def build_separator_header(next_part_size, rolling_crc):
    """
    Build separator header:
    [Next Partition size (32bit)][CRC32 so far (32bit)]
    """
    return struct.pack('<II', next_part_size, rolling_crc)


def compress_lz4(data):
    """Compress data using LZ4 high compression"""
    return lz4.block.compress(data, mode='high_compression', store_size=False)


# ---------------------------------------------------------------------------
# Ed25519 signing helpers
# ---------------------------------------------------------------------------

def load_or_generate_key(key_path):
    """
    Load an Ed25519 private key from *key_path* (PEM), or generate and save
    a new one if the file does not exist yet.  Returns (private_key, public_key_bytes).
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            load_pem_private_key, Encoding, PrivateFormat, PublicFormat,
            NoEncryption,
        )
    except ImportError:
        print("Error: 'cryptography' package not found. Install with: pip install cryptography",
              file=sys.stderr)
        sys.exit(1)

    key_path = Path(key_path)
    if key_path.exists():
        with open(key_path, 'rb') as f:
            private_key = load_pem_private_key(f.read(), password=None)
    else:
        private_key = Ed25519PrivateKey.generate()
        pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(pem)
        print(f"  Generated new Ed25519 key → {key_path}")

    pub_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return private_key, pub_bytes


def ed25519_sign(private_key, message: bytes) -> bytes:
    """Sign *message* and return the 64-byte Ed25519 signature."""
    return private_key.sign(message)


def build_container(fsbl_path, dtb_path, output_path, release_id=0x0001,
                    key_path=None):
    """Build the complete image container."""

    print("Building image container...")
    print(f"  FSBL: {fsbl_path}")
    print(f"  DTB:  {dtb_path}")

    signing = key_path is not None
    crypto_flags = GBL_FLAG_ED25519 if signing else GBL_FLAG_NO_CRYPTO
    pubkey_size  = PUBKEY_SIZES.get(crypto_flags, 0)
    sig_size     = SIG_SIZES.get(crypto_flags, 0)

    # Read input files
    with open(fsbl_path, 'rb') as f:
        fsbl_data = f.read()
    with open(dtb_path, 'rb') as f:
        dtb_data = f.read()

    print(f"  FSBL size: {len(fsbl_data)} bytes")
    print(f"  DTB size:  {len(dtb_data)} bytes")

    # Compress both images
    fsbl_compressed = compress_lz4(fsbl_data)
    dtb_compressed  = compress_lz4(dtb_data)

    fsbl_ratio = 100 * len(fsbl_compressed) / len(fsbl_data)
    dtb_ratio  = 100 * len(dtb_compressed)  / len(dtb_data)
    print(f"  FSBL compressed: {len(fsbl_compressed)} bytes ({fsbl_ratio:.1f}%)")
    print(f"  DTB compressed:  {len(dtb_compressed)} bytes ({dtb_ratio:.1f}%)")

    # Pad compressed payloads to 8-byte boundary
    fsbl_padded = pad_to_8bytes(fsbl_compressed)
    dtb_padded  = pad_to_8bytes(dtb_compressed)

    # Load / generate signing key if requested
    private_key = pub_bytes = None
    if signing:
        private_key, pub_bytes = load_or_generate_key(key_path)
        print(f"  Signing with Ed25519 key, public key: {pub_bytes.hex()}")
        assert len(pub_bytes) == pubkey_size

    # Build partition payloads (header + compressed data)
    # sep_hdr reports: part_hdr + payload + optional sig
    part1_header = build_partition_header(
        release_id=release_id, img_type=IMG_TYPE_FBSL,
        unit_id=0, flags=PART_FLAG_LZ4, image_size=len(fsbl_data))
    part2_header = build_partition_header(
        release_id=release_id, img_type=IMG_TYPE_DTB,
        unit_id=0, flags=PART_FLAG_LZ4, image_size=len(dtb_data))

    part1_payload_size = len(part1_header) + len(fsbl_padded)
    part2_payload_size = len(part2_header) + len(dtb_padded)
    part1_size = part1_payload_size + sig_size
    part2_size = part2_payload_size + sig_size

    # Calculate total size:
    #   global_hdr + pubkey + global_sig + sep1 + part1 + sep2 + part2 + sep_final
    total_size = (
        8 + pubkey_size + sig_size +   # global header + optional cert material
        8 + part1_size +               # sep1 + partition 1
        8 + part2_size +               # sep2 + partition 2
        8                              # final sep header
    )

    # Build global header
    global_header = build_global_header(
        partition_count=2, total_size=total_size, flags=crypto_flags)

    # --- Compute signatures if signing ---
    global_sig = part1_sig = part2_sig = b''
    if signing:
        # Global sig: ed25519(global_hdr only).
        # The pubkey is already bound via Ed25519's A term in SHA-512(R||A||M),
        # so including it in M is redundant.
        global_sig = ed25519_sign(private_key, global_header)
        assert len(global_sig) == sig_size, f"sig size mismatch: {len(global_sig)} != {sig_size}"

        # Partition sigs: ed25519(part_hdr || uncompressed_data)
        part1_sig = ed25519_sign(private_key, part1_header + fsbl_data)
        part2_sig = ed25519_sign(private_key, part2_header + dtb_data)
        assert len(part1_sig) == sig_size
        assert len(part2_sig) == sig_size

        print(f"  Global sig:  {global_sig.hex()[:32]}...")
        print(f"  Part1 sig:   {part1_sig.hex()[:32]}...")
        print(f"  Part2 sig:   {part2_sig.hex()[:32]}...")

    # --- Assemble container ---
    nibble_table = init_crc32_nibbles()
    crc = 0xFFFFFFFF
    container = bytearray()

    def append(data):
        nonlocal crc
        container.extend(data)
        crc = crc32_update(crc, data, nibble_table)

    def append_sep(next_part_size):
        nonlocal crc
        crc_with_size = crc32_update(crc, struct.pack('<I', next_part_size), nibble_table)
        sep = build_separator_header(next_part_size, ~crc_with_size & 0xFFFFFFFF)
        append(sep)

    # Global header
    append(global_header)

    # Public key (optional)
    if signing:
        append(pub_bytes)
        # Pad pubkey to 8-byte boundary (ed25519 key is 32 B, already aligned)
        pad = pad_to_8bytes(pub_bytes)[len(pub_bytes):]
        if pad:
            append(pad)

    # Global signature (optional)
    if signing:
        append(global_sig)

    # Partition 1  (layout: part_hdr | sig | padded_payload)
    append_sep(part1_size)
    append(part1_header)
    if signing:
        append(part1_sig)
    append(fsbl_padded)

    # Partition 2  (layout: part_hdr | sig | padded_payload)
    append_sep(part2_size)
    append(part2_header)
    if signing:
        append(part2_sig)
    append(dtb_padded)

    # Final separator
    crc_with_size = crc32_update(crc, struct.pack('<I', 0), nibble_table)
    sep_final = build_separator_header(0, ~crc_with_size & 0xFFFFFFFF)
    container.extend(sep_final)

    # Write output
    with open(output_path, 'wb') as f:
        f.write(container)

    print("\nContainer built successfully!")
    print(f"  Output: {output_path}")
    print(f"  Total size: {len(container)} bytes")
    print(f"  Signed: {signing}")

    # Verify the final CRC gives the expected remainder
    crc_check = crc32_update(crc, sep_final, nibble_table)
    ok = (~crc_check & 0xFFFFFFFF) == CRC32_REMAINDER
    print(f"  CRC check: {'OK' if ok else 'FAIL'} (0x{(~crc_check & 0xFFFFFFFF):08X})")
    if not ok:
        print("  WARNING: CRC mismatch!", file=sys.stderr)


def keygen(key_path):
    """Generate and save a new Ed25519 key pair."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PrivateFormat, PublicFormat, NoEncryption,
        )
    except ImportError:
        print("Error: 'cryptography' package not found. Install with: pip install cryptography",
              file=sys.stderr)
        sys.exit(1)

    private_key = Ed25519PrivateKey.generate()
    pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    pub = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    key_path = Path(key_path)
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(pem)

    pub_path = key_path.with_suffix('.pub')
    with open(pub_path, 'wb') as f:
        f.write(pub)

    print("Generated Ed25519 key pair:")
    print(f"  Private key: {key_path}")
    print(f"  Public key:  {pub_path}  ({pub.hex()})")


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Build a NetBoot image container with optional Ed25519 signing")
    parser.add_argument("fsbl", nargs="?", help="FSBL/boot binary path")
    parser.add_argument("dtb",  nargs="?", help="Device tree blob path")
    parser.add_argument("output", nargs="?", default="boot.img",
                        help="Output file (default: boot.img)")
    parser.add_argument("--sign", metavar="KEY.pem",
                        help="Sign with Ed25519 key (generates key if file does not exist)")
    parser.add_argument("--keygen", metavar="KEY.pem",
                        help="Generate a new Ed25519 key pair and exit")
    parser.add_argument("--release-id", type=lambda x: int(x, 0), default=0x0001,
                        metavar="ID", help="Release ID (default: 0x0001)")
    args = parser.parse_args()

    if args.keygen:
        keygen(args.keygen)
        return

    if not args.fsbl or not args.dtb:
        parser.print_help()
        print("\nError: fsbl and dtb arguments are required", file=sys.stderr)
        sys.exit(1)

    fsbl_path = Path(args.fsbl)
    dtb_path  = Path(args.dtb)

    if not fsbl_path.exists():
        print(f"Error: FSBL file not found: {fsbl_path}", file=sys.stderr)
        sys.exit(1)
    if not dtb_path.exists():
        print(f"Error: DTB file not found: {dtb_path}", file=sys.stderr)
        sys.exit(1)

    build_container(fsbl_path, dtb_path, Path(args.output),
                    release_id=args.release_id,
                    key_path=args.sign)


if __name__ == '__main__':
    main()
