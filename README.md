# NetBoot

A lightweight bare-metal network bootloader that implements DHCP and TFTP protocols for embedded systems.

## Overview

NetBoot is a minimal network bootloader designed to run on bare-metal embedded systems. It enables devices to bootstrap themselves over a network using DHCP for network configuration and TFTP for image retrieval. The bootloader supports multiple network interface controllers and can load compressed images.

## Features

- **Network Protocols**
  - DHCP client implementation for automatic network configuration
  - TFTP client for fetching boot images

- **Hardware Support**
  - Xilinx EthernetLite (emaclite)
  - Xilinx AXI DMA
  - VirtIO-Net MMIO (for virtual machines)
  - Raw socket interface (for host testing)

- **Image Format**
  - LZ4-compressed multi-partition container
  - Rolling CRC32 validated at every separator (streaming-friendly)
  - Optional Ed25519 signatures verified per partition before decompress

- **Build Targets**
  - Bare-metal cross-compilation for embedded targets
  - Host test mode for development and debugging on Linux

## Prerequisites

- **For Bare-Metal Builds:**
  - BareMetal SDK (set `SDK_DIR` environment variable or use default `../BareMetal/sdk`)
  - Cross-compilation toolchain (configured in SDK)

- **For Host Builds:**
  - GCC or compatible compiler
  - Linux system with raw socket support
  - Root privileges for network access

## Building

### Bare-Metal Build

Build for the default target (QEMU):
```bash
make
```

Build for a specific target:
```bash
make TARGET=<target>
```

### Host Test Build

Build the host version for local testing:
```bash
make host
```

Run the host version (requires root for raw sockets):
```bash
sudo ./build/netboot_host
```

### Available Make Targets

- `make all` - Build netboot application (default: TARGET=qemu)
- `make host` - Build host test version
- `make clean` - Clean netboot build artifacts
- `make host-clean` - Clean host test build artifacts
- `make test` - Build and run on QEMU with TFTP support
- `make help` - Show help message

## Configuration

### Environment Variables

- `SDK_DIR` - Path to BareMetal SDK (default: `../BareMetal/sdk`)
- `TARGET` - Hardware target for bare-metal builds (default: `qemu`)
- `HOST_CC` - Host compiler (default: `gcc`)
- `V=1` - Enable verbose build output

### Creating Boot Images

Boot images are built with `nbimgt`, a single C tool under [image_tools/](image_tools/):

```bash
cd image_tools && make
```

Requires `liblz4-dev` and `libssl-dev`.

#### Building a Boot Image

```bash
# Unsigned image
./image_tools/nbimgt build boot.bin boot.dtb tftp-root/boot.img

# Signed image (generates an Ed25519 key on first use)
./image_tools/nbimgt build --sign signing_key.pem \
    boot.bin boot.dtb tftp-root/boot.img
```

**Input files:**
- `boot.bin` - Firmware payload (e.g., fw_payload.bin from OpenSBI/yarvt)
- `boot.dtb` - Device tree blob for the target platform

**Output:**
- `tftp-root/boot.img` - LZ4-compressed container with CRC32 and, when
  `--sign` is used, per-partition Ed25519 signatures

#### Inspecting a Boot Image

```bash
./image_tools/nbimgt verify tftp-root/boot.img
```

This validates the global header, all signatures (if signed), CRC32
checksums at every separator, and decompresses each payload. Signature
verification cross-checks the built-in Ed25519 implementation against
OpenSSL to catch divergence.

See [image_tools/README.md](image_tools/README.md) for full documentation
of `nbimgt`, key management (`pinentry`, `memfd_secret`-backed key storage),
and the container layout.

Place the resulting `boot.img` in [tftp-root/](tftp-root/) for TFTP serving
during testing.

## Project Structure

```
NetBoot/
├── src/
│   ├── main.c              # Main entry point (DHCP → TFTP → parse → jump)
│   ├── image_parser.c      # Streaming container parser (CRC + sig + LZ4)
│   ├── lz4.c               # Streaming LZ4 decompressor
│   ├── net/                # Network protocol implementations
│   │   ├── net.c           # ARP, IPv4, UDP send/receive
│   │   ├── dhcp.c          # DHCP client state machine
│   │   ├── dhcp_options.c  # DHCP option parsing/building
│   │   └── tftp.c          # TFTP client with blksize/tsize/windowsize
│   ├── ether/              # NIC drivers (out of scope for this overview)
│   ├── crypto/             # Built-in crypto for signature verification
│   │   ├── sha512.c        # SHA-512 (FIPS 180-4)
│   │   └── ed25519.c       # Ed25519 verify (SUPERCOP ref10) + self-test
│   ├── units/              # Per-unit handlers (selected via section table)
│   │   └── self.c          # Unit 0: this device — region layout + jump
│   └── include/            # Public headers (img.h, crypto.h, net.h, …)
├── image_tools/            # nbimgt: build / sign / verify containers
├── tftp-root/              # Test TFTP root (boot.bin, boot.dtb, boot.img)
├── build/                  # Build output directory
├── Makefile                # Build system
└── unit_sections.ld        # Linker script for units (REGISTER_UNIT_CB table)
```

## Testing

Run the netboot application in QEMU with TFTP support:
```bash
make TARGET=qemu test
```

This will:
1. Build the netboot binary for QEMU
2. Start QEMU with network support
3. Launch a TFTP server serving files from [tftp-root/](tftp-root/)

## Development

### Debug Mode

Debug mode is enabled by default. To disable, remove `-DDEBUG` from the CFLAGS in the Makefile.

### Adding New Network Drivers

1. Create a new driver file in [src/ether/](src/ether/)
2. Implement the NIC interface functions
3. Add the driver to the build system

### Adding New Units

1. Create a new unit file in [src/units/](src/units/)
2. Define unit metadata and handlers
3. The linker script will automatically place it in the correct section

## License

```
SPDX-License-Identifier: Apache-2.0

Copyright 2026 Nick Kossifidis <mick@ics.forth.gr>
Copyright 2026 ICS/FORTH
```

Individual files may have different copyright years reflecting their actual development history.

## Contributing

This SDK is developed as part of research at the Institute of Computer Science, Foundation for Research and Technology - Hellas (ICS-FORTH). Contributions are welcome. Please ensure code follows the existing style and passes all tests.
