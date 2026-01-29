#!/usr/bin/env python3
"""
Image Container Builder

Creates a bootable image container from FSBL and DTB files according to
the format specified in img.h, with LZ4 compression and CRC32 validation.
"""

import struct
import sys
import os
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

# Magic value for global header (you may want to define this)
MAGIC_VALUE = 0x424E  # "NB" for NetBoot

# Header version
HDR_VERSION = 0


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
    # Pack header version (4bit) and partition count (4bit) into one byte
    # Header version in lower 4 bits, partition count in upper 4 bits (matches C bitfield order)
    version_count = (partition_count << 4) | (HDR_VERSION & 0x0F)

    # Little-endian: uint16_t, uint8_t, uint8_t, uint32_t
    return struct.pack('<HBBI', MAGIC_VALUE, version_count, flags, total_size)


def build_partition_header(release_id, img_type, unit_id, flags, image_size):
    """
    Build partition header:
    [Release ID (16bit)][Type (4bit)][Unit ID (4bit)][Flags (8bit)][Image size (32bit)]
    """
    # Pack type (4bit) and unit_id (4bit) into one byte
    # Type in lower 4 bits, unit_id in upper 4 bits (matches C bitfield order)
    type_unit = (unit_id << 4) | (img_type & 0x0F)

    # Little-endian: uint16_t, uint8_t, uint8_t, uint32_t
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


def build_container(fsbl_path, dtb_path, output_path, release_id=0x0001):
    """Build the complete image container"""

    print(f"Building image container...")
    print(f"  FSBL: {fsbl_path}")
    print(f"  DTB:  {dtb_path}")

    # Read input files
    with open(fsbl_path, 'rb') as f:
        fsbl_data = f.read()
    with open(dtb_path, 'rb') as f:
        dtb_data = f.read()

    print(f"  FSBL size: {len(fsbl_data)} bytes")
    print(f"  DTB size:  {len(dtb_data)} bytes")

    # Compress both images
    fsbl_compressed = compress_lz4(fsbl_data)
    dtb_compressed = compress_lz4(dtb_data)

    print(f"  FSBL compressed: {len(fsbl_compressed)} bytes ({100*len(fsbl_compressed)/len(fsbl_data):.1f}%)")
    print(f"  DTB compressed:  {len(dtb_compressed)} bytes ({100*len(dtb_compressed)/len(dtb_data):.1f}%)")

    # Pad compressed payloads to 8-byte boundary
    fsbl_padded = pad_to_8bytes(fsbl_compressed)
    dtb_padded = pad_to_8bytes(dtb_compressed)

    # Build partition 1 (FSBL)
    part1_header = build_partition_header(
        release_id=release_id,
        img_type=IMG_TYPE_FBSL,
        unit_id=0,
        flags=PART_FLAG_LZ4,
        image_size=len(fsbl_data)  # Uncompressed size
    )
    part1_size = len(part1_header) + len(fsbl_padded)  # No signature

    # Build partition 2 (DTB)
    part2_header = build_partition_header(
        release_id=release_id,
        img_type=IMG_TYPE_DTB,
        unit_id=0,
        flags=PART_FLAG_LZ4,
        image_size=len(dtb_data)  # Uncompressed size
    )
    part2_size = len(part2_header) + len(dtb_padded)  # No signature

    # Calculate total size
    total_size = (
        8 +  # Global header
        8 +  # Sep header 1
        part1_size +
        8 +  # Sep header 2
        part2_size +
        8    # Sep header 3 (final)
    )

    # Build global header
    global_header = build_global_header(
        partition_count=2,
        total_size=total_size,
        flags=GBL_FLAG_NO_CRYPTO
    )

    # Initialize CRC32
    nibble_table = init_crc32_nibbles()
    crc = 0xFFFFFFFF

    # Build container
    container = bytearray()

    # Add global header
    container.extend(global_header)
    crc = crc32_update(crc, global_header, nibble_table)

    # Sep header 1
    # CRC includes size field but not the rolling_crc field itself
    crc_with_size = crc32_update(crc, struct.pack('<I', part1_size), nibble_table)
    sep1 = build_separator_header(part1_size, ~crc_with_size & 0xFFFFFFFF)
    container.extend(sep1)
    crc = crc32_update(crc, sep1, nibble_table)

    # Partition 1
    container.extend(part1_header)
    crc = crc32_update(crc, part1_header, nibble_table)
    container.extend(fsbl_padded)
    crc = crc32_update(crc, fsbl_padded, nibble_table)

    # Sep header 2
    crc_with_size = crc32_update(crc, struct.pack('<I', part2_size), nibble_table)
    sep2 = build_separator_header(part2_size, ~crc_with_size & 0xFFFFFFFF)
    container.extend(sep2)
    crc = crc32_update(crc, sep2, nibble_table)

    # Partition 2
    container.extend(part2_header)
    crc = crc32_update(crc, part2_header, nibble_table)
    container.extend(dtb_padded)
    crc = crc32_update(crc, dtb_padded, nibble_table)

    # Final separator (size=0, final CRC)
    crc_with_size = crc32_update(crc, struct.pack('<I', 0), nibble_table)
    sep_final = build_separator_header(0, ~crc_with_size & 0xFFFFFFFF)
    container.extend(sep_final)

    # Write output
    with open(output_path, 'wb') as f:
        f.write(container)

    print(f"\nContainer built successfully!")
    print(f"  Output: {output_path}")
    print(f"  Total size: {len(container)} bytes")
    print(f"  Final CRC32: 0x{(~crc & 0xFFFFFFFF):08X}")

    # Verify the final CRC should give the expected remainder
    crc_with_final = crc32_update(crc, sep_final, nibble_table)
    print(f"  CRC with final sep: 0x{(~crc_with_final & 0xFFFFFFFF):08X} (expected: 0x{CRC32_REMAINDER:08X})")


def main():
    if len(sys.argv) < 3:
        print("Usage: build_container.py <boot.bin> <boot.dtb> [output.img]", file=sys.stderr)
        print("\nBuilds a NetBoot image container with LZ4-compressed FSBL and DTB")
        sys.exit(1)

    fsbl_path = Path(sys.argv[1])
    dtb_path = Path(sys.argv[2])
    output_path = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("boot.img")

    if not fsbl_path.exists():
        print(f"Error: FSBL file not found: {fsbl_path}", file=sys.stderr)
        sys.exit(1)

    if not dtb_path.exists():
        print(f"Error: DTB file not found: {dtb_path}", file=sys.stderr)
        sys.exit(1)

    build_container(fsbl_path, dtb_path, output_path)


if __name__ == '__main__':
    main()
