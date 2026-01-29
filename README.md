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

NetBoot uses a custom container format with LZ4 compression and CRC32 validation. Use the provided tools to build and inspect boot images.

#### Building a Boot Image

```bash
# Install Python dependencies
pip install lz4

# Create boot.img from boot.bin and boot.dtb
./image_tools/build_container.py boot.bin boot.dtb tftp-root/boot.img
```

**Input files:**
- `boot.bin` - Firmware payload (e.g., fw_payload.bin from OpenSBI/yarvt)
- `boot.dtb` - Device tree blob for the target platform

**Output:**
- `tftp-root/boot.img` - LZ4-compressed container with CRC32 validation

The tool automatically compresses both files with LZ4 and packages them with partition headers and rolling CRC32 checksums for corruption detection.

#### Inspecting a Boot Image

Verify the structure and integrity of a boot image:

```bash
./image_tools/inspect_container.py tftp-root/boot.img
```

This tool will:
- Display the global header (magic, version, partition count, flags)
- Show each partition header (type, unit ID, compression, sizes)
- Validate CRC32 checksums at each separator
- Verify 8-byte alignment and padding
- Report any corruption or format errors

Place the resulting `boot.img` in [tftp-root/](tftp-root/) for TFTP serving during testing.

## Project Structure

```
NetBoot/
├── src/
│   ├── main.c              # Main entry point
│   ├── net/                # Network protocol implementations
│   │   ├── dhcp.c          # DHCP client
│   │   ├── dhcp_options.c  # DHCP option parsing
│   │   ├── tftp.c          # TFTP client
│   │   └── net.c           # Network utilities
│   ├── ether/              # Network driver implementations
│   │   ├── emaclite_nic.c  # Xilinx EthernetLite
│   │   ├── axidma_nic.c    # Xilinx AXI DMA
│   │   ├── virtionet_mmio_nic.c  # VirtIO-Net
│   │   └── rawsock_nic.c   # Raw socket (host)
│   ├── units/              # Modular unit implementations
│   │   └── self.c          # Self-test unit
│   ├── include/            # Header files
│   ├── lz4.c               # LZ4 decompression
│   └── image_parser.c      # Image format parser
├── image_tools/            # Image manipulation tools
├── tftp-root/              # TFTP server root directory
├── build/                  # Build output directory
├── Makefile                # Build system
└── unit_sections.ld        # Linker script for units
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
