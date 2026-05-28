# NetBoot Image Tools

`nbimgt` — build, sign, and verify NetBoot image containers (`.img` format).

## Building

```bash
make
```

Requires: `gcc`, `liblz4-dev`, `libssl-dev`.

## Commands

### build

Packs an FSBL binary and a DTB into a compressed, optionally signed container.

```bash
./nbimgt build [-s KEY.pem] [-r ID] FSBL DTB [OUTPUT]
```

| Argument | Description |
|---|---|
| `FSBL` | Path to the FSBL / boot binary |
| `DTB` | Path to the device tree blob |
| `OUTPUT` | Output file (default: `boot.img`) |
| `-s, --sign KEY.pem` | Sign with an Ed25519 key; generates the key if the file does not exist |
| `-r, --release-id ID` | Release identifier, hex or decimal (default: `0x0001`) |

Both partitions are LZ4-compressed. If `--sign` is given, the global header, each partition header, and the final trailer are all individually signed so the streaming TFTP parser can authenticate as it receives data.

### verify

Reads a container, runs the crypto self-test, verifies all signatures and checksums, and optionally decompresses the payloads.

```bash
./nbimgt verify [-d] [-t] [IMAGE]
```

| Argument | Description |
|---|---|
| `IMAGE` | Container file (default: `../tftp-root/boot.img`) |
| `-d, --dump` | Decompress partitions to `/tmp/part0.bin`, `/tmp/part1.bin` |
| `-t, --test-parser` | Feed the image through the streaming TFTP parser instead of the direct reader |

### keygen

Generates an Ed25519 key pair. The private key is stored as an encrypted PKCS#8 PEM file; the public key is written to `<KEY>.pub`.

```bash
./nbimgt keygen KEY.pem
```

Passphrase entry is handled via `pinentry` (gpg-agent's pinentry program). The private key is only decrypted in memory during signing and is kept on a `mprotect(PROT_NONE)`-guarded page between uses.

## Key management

- Private keys are PKCS#8 PEM files encrypted with the passphrase you supply at generation time.
- At runtime the passphrase is collected via `pinentry` over an Assuan pipe; it is never written to disk or passed through the environment.
- The decoded private key lives on a dedicated `mmap` page that is marked `PROT_NONE` when not actively signing. Any failure to restore the guard aborts immediately after zeroing the key material.
- `PR_SET_DUMPABLE` is set at startup so the process cannot be core-dumped or ptrace-attached.
- OpenSSL's secure heap (`CRYPTO_secure_malloc_init`) is used for all sensitive allocations.

## Container format

```
[ global_hdr_t  ]  flags, release-id, algo, public-key, signature
[ sep_hdr_t     ]  next-partition size, rolling CRC32
[ part_hdr_t    ]  type (FSBL), flags (LZ4), uncompressed size, signature
[ payload       ]  LZ4-compressed FSBL, 8-byte aligned
[ sep_hdr_t     ]  next-partition size, rolling CRC32
[ part_hdr_t    ]  type (DTB),  flags (LZ4), uncompressed size, signature
[ payload       ]  LZ4-compressed DTB,  8-byte aligned
[ sep_hdr_t     ]  size=0 (end), final CRC32
```

The streaming TFTP parser validates the CRC32 at each separator and — when the image is signed — verifies each signature before decompressing the corresponding payload.

## Makefile targets

| Target | Description |
|---|---|
| `make` | Build `nbimgt` |
| `make test` | Build an unsigned `../tftp-root/boot.img` and run it through the streaming parser, then print MD5 checksums comparing the original files with the decompressed output |
| `make test-signed` | Generate a throw-away key, build a signed image, verify it, run it through the parser, and print checksums |
| `make clean` | Remove the binary, test keys, and generated images |
