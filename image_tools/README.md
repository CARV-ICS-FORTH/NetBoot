# NetBoot Image Tools

Tools for building and manipulating NetBoot image containers.

## build_container.py

Creates a bootable image container from FSBL and DTB files according to the format specified in `img.h`.

### Features
- LZ4 high compression for both images
- CRC32 validation at each partition boundary
- No signature support (uses `GBL_FLAG_NO_CRYPTO`)
- Automatic 8-byte alignment and padding

### Requirements

```bash
pip install lz4
```

### Usage

```bash
./build_container.py <boot.bin> <boot.dtb> [output.img]
```

**Arguments:**
- `boot.bin` - FSBL/firmware/kernel image (will be compressed)
- `boot.dtb` - Device Tree Blob (will be compressed)
- `output.img` - Output container file (default: `boot.img`)

### Example

```bash
./build_container.py ../build/boot.bin ../build/boot.dtb boot.img
```

### Output Format

The generated container follows this structure:

```
<Global header>         (8 bytes)
<Separator header 1>    (8 bytes)
<Partition 1 header>    (8 bytes) - FSBL, LZ4 compressed
<Partition 1 payload>   (variable, padded to 8-byte boundary)
<Separator header 2>    (8 bytes)
<Partition 2 header>    (8 bytes) - DTB, LZ4 compressed
<Partition 2 payload>   (variable, padded to 8-byte boundary)
<Separator header 3>    (8 bytes) - Final CRC32
```

Each separator header contains:
- Next partition size (32-bit)
- Rolling CRC32 checksum (32-bit)

The parser validates the CRC32 at each separator to detect corruption early.
