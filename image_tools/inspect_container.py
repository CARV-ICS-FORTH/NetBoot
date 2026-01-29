#!/usr/bin/env python3
"""
Image Container Inspector

Inspects a NetBoot image container and validates structure according to img.h spec.
"""

import struct
import sys
from pathlib import Path

# CRC32 constants
CRC32_POLY = 0xEDB88320
CRC32_REMAINDER = 0x2144DF1C

# Image types
IMG_TYPES = {0: "BOOT_STEP", 1: "FSBL", 2: "DTB"}

# Flags
PART_FLAGS = {0: "UNCOMPRESSED", 1: "LZ4"}
GBL_FLAGS = {0: "NO_CRYPTO", 1: "ED25519", 2: "ECDSA384"}


def init_crc32_nibbles():
    """Pre-calculate CRC32 nibble lookup table"""
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
    """Update CRC32 value with new data"""
    for byte in data:
        # Process low nibble
        crc = (crc >> 4) ^ nibble_table[(crc ^ (byte & 0x0F)) & 0x0F]
        # Process high nibble
        crc = (crc >> 4) ^ nibble_table[(crc ^ (byte >> 4)) & 0x0F]
    return crc


def inspect_container(file_path):
    """Inspect image container and validate structure"""

    print(f"Inspecting: {file_path}\n")

    with open(file_path, 'rb') as f:
        data = f.read()

    print(f"Total file size: {len(data)} bytes\n")

    # Initialize CRC32
    nibble_table = init_crc32_nibbles()
    crc = 0xFFFFFFFF

    offset = 0

    # Parse global header
    print("=== Global Header (8 bytes) ===")
    print(f"Offset: 0x{offset:08X}")
    global_hdr = data[offset:offset+8]
    magic, version_count, flags, total_size = struct.unpack('<HBBI', global_hdr)
    hdr_version = version_count & 0x0F
    part_count = (version_count >> 4) & 0x0F

    print(f"  Magic:         0x{magic:04X} ({''.join(chr(b) for b in struct.pack('<H', magic))})")
    print(f"  Hdr Version:   {hdr_version}")
    print(f"  Part Count:    {part_count}")
    print(f"  Flags:         {flags} ({GBL_FLAGS.get(flags, 'UNKNOWN')})")
    print(f"  Total Size:    {total_size} bytes")
    print(f"  Hex: {global_hdr.hex()}")

    crc = crc32_update(crc, global_hdr, nibble_table)
    offset += 8

    partition_num = 0

    while offset < len(data):
        # Parse separator header
        print(f"\n=== Separator Header {partition_num + 1} (8 bytes) ===")
        print(f"Offset: 0x{offset:08X}")
        sep_hdr = data[offset:offset+8]
        next_part_size, rolling_crc = struct.unpack('<II', sep_hdr)

        print(f"  Next Part Size: {next_part_size} bytes")
        print(f"  Rolling CRC32:  0x{rolling_crc:08X}")
        print(f"  Hex: {sep_hdr.hex()}")

        # Add separator to CRC
        crc = crc32_update(crc, sep_hdr, nibble_table)

        # Verify CRC remainder after processing separator
        crc_remainder = ~crc & 0xFFFFFFFF
        print(f"  CRC after sep:  0x{crc_remainder:08X}")
        if crc_remainder == CRC32_REMAINDER:
            print(f"  CRC Status:     ✓ VALID (magic remainder)")
        else:
            print(f"  CRC Status:     ✗ FAIL (expected 0x{CRC32_REMAINDER:08X})")

        offset += 8

        # Check if final separator
        if next_part_size == 0:
            print(f"\n=== Final Separator (partition count complete) ===")
            print(f"Final CRC remainder: 0x{(~crc & 0xFFFFFFFF):08X}")
            print(f"Expected remainder:  0x{CRC32_REMAINDER:08X}")
            if (~crc & 0xFFFFFFFF) == CRC32_REMAINDER:
                print("CRC validation:      ✓ PASS")
            else:
                print("CRC validation:      ✗ FAIL")
            break

        partition_num += 1

        # Parse partition header
        print(f"\n=== Partition {partition_num} Header (8 bytes) ===")
        print(f"Offset: 0x{offset:08X}")
        part_hdr = data[offset:offset+8]
        release_id, type_unit, part_flags, image_size = struct.unpack('<HBBI', part_hdr)
        img_type = type_unit & 0x0F
        unit_id = (type_unit >> 4) & 0x0F

        print(f"  Release ID:    0x{release_id:04X}")
        print(f"  Type:          {img_type} ({IMG_TYPES.get(img_type, 'UNKNOWN')})")
        print(f"  Unit ID:       {unit_id}")
        print(f"  Flags:         {part_flags} ({PART_FLAGS.get(part_flags, 'UNKNOWN')})")
        print(f"  Image Size:    {image_size} bytes (uncompressed)")
        print(f"  Hex: {part_hdr.hex()}")

        crc = crc32_update(crc, part_hdr, nibble_table)
        offset += 8

        # Calculate payload size (includes padding)
        payload_size = next_part_size - 8  # Subtract partition header
        padded_size = ((payload_size + 7) // 8) * 8  # Should already be aligned

        print(f"\n=== Partition {partition_num} Payload ===")
        print(f"Offset: 0x{offset:08X}")
        print(f"  Payload Size:  {payload_size} bytes")
        print(f"  Padded Size:   {padded_size} bytes")

        # Verify 8-byte alignment
        if padded_size % 8 == 0:
            print(f"  Alignment:     ✓ 8-byte aligned")
        else:
            print(f"  Alignment:     ✗ NOT 8-byte aligned")

        # Read payload and update CRC
        payload = data[offset:offset+payload_size]
        crc = crc32_update(crc, payload, nibble_table)

        # Show first 64 bytes of payload
        preview_len = min(64, len(payload))
        print(f"  First {preview_len} bytes: {payload[:preview_len].hex()}")

        offset += payload_size

    print(f"\n=== Summary ===")
    print(f"Total partitions: {partition_num}")
    print(f"Bytes processed:  {offset}")
    print(f"File size:        {len(data)}")
    if offset == len(data):
        print(f"File parsing:     ✓ Complete")
    else:
        print(f"File parsing:     ✗ Incomplete ({len(data) - offset} bytes remaining)")


def main():
    if len(sys.argv) < 2:
        print("Usage: inspect_container.py <image.img>", file=sys.stderr)
        sys.exit(1)

    img_path = Path(sys.argv[1])

    if not img_path.exists():
        print(f"Error: File not found: {img_path}", file=sys.stderr)
        sys.exit(1)

    inspect_container(img_path)


if __name__ == '__main__':
    main()
