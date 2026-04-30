/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2026 Nick Kossifidis <mick@ics.forth.gr>
 * SPDX-FileCopyrightText: 2026 ICS/FORTH
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * NetBoot container inspector and parser test harness.
 *
 * Default mode: mmap the image, walk the format directly, decompress each
 * LZ4 partition, and verify CRC + Ed25519 signatures using both the built-in
 * crypto implementation and OpenSSL as an independent cross-check.
 *
 * -t / --test-parser: feed the image through imgp_tftp_handler in 512-byte
 * chunks, verifying the streaming state-machine parser end-to-end.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#include <img.h>
#include <crypto.h>
#include <utils.h>

/* From units/self.c — only used in parser test mode */
extern size_t test_get_partition_size(int part_id);

/* crypto_selftest() is provided by src/crypto/ed25519.c */

/********\
* CRC32  *
\********/

#define CRC32_POLY      0xEDB88320U
#define CRC32_REMAINDER 0x2144DF1CU

static void crc32_init_table(uint32_t table[16])
{
	for (int i = 0; i < 16; i++) {
		uint32_t crc = i;
		for (int j = 0; j < 4; j++)
			crc = (crc & 1) ? ((crc >> 1) ^ CRC32_POLY) : (crc >> 1);
		table[i] = crc;
	}
}

static uint32_t crc32_feed(uint32_t crc, const uint8_t *data, size_t len,
			    const uint32_t *table)
{
	for (size_t i = 0; i < len; i++) {
		crc = (crc >> 4) ^ table[(crc ^ (data[i] & 0x0F)) & 0x0F];
		crc = (crc >> 4) ^ table[(crc ^ (data[i] >> 4)) & 0x0F];
	}
	return crc;
}

/************************************\
* Ed25519 dual verification helper   *
\************************************/

/*
 * Verify an Ed25519 signature using both the built-in implementation and
 * OpenSSL as an independent cross-check.  The message is split into a
 * uint64_t header (8 bytes, fed first) and an optional body, matching the
 * internal convention of crypto_verify_signature().  For OpenSSL, the two
 * parts are concatenated into a temporary buffer so it sees one flat message.
 * Returns 0 if both pass, -1 otherwise.
 */
static int crypto_verify_both(const uint8_t *pk,
			      const uint8_t *sig, size_t sig_size,
			      uint64_t hdr,
			      const void *body, size_t body_len,
			      const char *label)
{
	/* Builtin: create a throw-away context so the persistent cctx isn't
	 * disturbed (crypto_verify_signature clears the sig buffer on return). */
	crypto_ctx_t *ctx = crypto_init(CRYPTO_ALGO_ED25519);
	int builtin_ok = 0;
	if (ctx) {
		crypto_set_pubkey(ctx, pk, 32);
		crypto_set_signature(ctx, sig, sig_size);
		builtin_ok = (crypto_verify_signature(ctx, hdr, body, body_len) == 0);
		crypto_exit(ctx);
	}
	INF("  builtin : %s\n", builtin_ok ? "PASS" : "FAIL");

	/* OpenSSL: flatten hdr_bytes || body into one contiguous buffer. */
	size_t msg_len = 8 + body_len;
	uint8_t *msg = malloc(msg_len);
	int openssl_ok = 0;
	if (msg) {
		memcpy(msg, &hdr, 8);
		if (body_len > 0)
			memcpy(msg + 8, body, body_len);

		EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,
							      NULL, pk, 32);
		EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
		int ssl_ret = -1;
		if (pkey && mdctx &&
		    EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pkey) == 1)
			ssl_ret = EVP_DigestVerify(mdctx, sig, sig_size, msg, msg_len);
		EVP_MD_CTX_free(mdctx);
		EVP_PKEY_free(pkey);
		free(msg);
		openssl_ok = (ssl_ret == 1);
	}
	INF("  openssl : %s\n", openssl_ok ? "PASS" : "FAIL");

	if (builtin_ok != openssl_ok)
		WRN("%s — implementations disagree!\n", label);

	return (builtin_ok && openssl_ok) ? 0 : -1;
}

/****************************\
* Direct inspection (mmap)   *
\****************************/

static const char *gbl_flag_str[] = {
	[GBL_FLAG_NO_CRYPTO] = "NO_CRYPTO",
	[GBL_FLAG_ED25519]   = "ED25519",
	[GBL_FLAG_ECDSA384]  = "ECDSA384",
};

static int inspect_container(const char *path, int do_dump)
{
	int ret = 0;

	int fd = open(path, O_RDONLY);
	if (fd < 0) { ERR("open: %s\n", strerror(errno)); return -1; }

	struct stat st;
	if (fstat(fd, &st) < 0) {
		ERR("fstat: %s\n", strerror(errno));
		close(fd); return -1;
	}
	size_t file_size = (size_t)st.st_size;

	const uint8_t *file = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);
	if (file == MAP_FAILED) { ERR("mmap: %s\n", strerror(errno)); return -1; }

	ANN("\n=== Container: %s (%zu bytes) ===\n\n", path, file_size);

	uint32_t crc_table[16];
	crc32_init_table(crc_table);
	uint32_t crc = 0xFFFFFFFF;
	size_t offset = 0;

	/* ---- Global header ---- */
	if (offset + 8 > file_size) {
		ERR("Truncated: no global header\n");
		ret = -1; goto out;
	}
	const global_hdr_t *ghdr = (const global_hdr_t *)(file + offset);

	if (ghdr->magic != IMG_MAGIC_NB) {
		ERR("Bad magic: 0x%04X (expected 0x%04X)\n",
		    ghdr->magic, IMG_MAGIC_NB);
		ret = -1; goto out;
	}

	if (ghdr->hdr_version != 0) {
		ERR("Unsupported header version: %u\n", ghdr->hdr_version);
		ret = -1; goto out;
	}

	INF("[Global Header]\n");
	INF("  Magic      : 0x%04X (%c%c)\n", ghdr->magic,
	       ghdr->magic & 0xFF, (ghdr->magic >> 8) & 0xFF);
	INF("  Version    : %u\n", ghdr->hdr_version);
	INF("  Partitions : %u\n", ghdr->part_count);
	INF("  Crypto     : %s\n",
	       ghdr->flags < 3 ? gbl_flag_str[ghdr->flags] : "UNKNOWN");
	INF("  Total size : %u bytes\n\n", ghdr->total_size);

	crc = crc32_feed(crc, file + offset, 8, crc_table);
	offset += 8;

	size_t pubkey_size = 0, sig_size = 0;
	switch (ghdr->flags) {
	case GBL_FLAG_ED25519:  pubkey_size = 32; sig_size = 64; break;
	case GBL_FLAG_ECDSA384: pubkey_size = 96; sig_size = 96; break;
	default: break;
	}

	const uint8_t *pubkey = NULL;

	/* ---- Public key ---- */
	if (pubkey_size > 0) {
		if (offset + pubkey_size > file_size) {
			ERR("Truncated: public key\n");
			ret = -1; goto out;
		}
		pubkey = file + offset;
		INF("[Public Key — %s, %zu bytes]\n",
		       gbl_flag_str[ghdr->flags], pubkey_size);
		INF("  ");
		for (size_t i = 0; i < pubkey_size; i++)
			INF("%02x", pubkey[i]);
		INF("\n\n");
		crc = crc32_feed(crc, pubkey, pubkey_size, crc_table);
		offset += pubkey_size;
	}

	/* ---- Global signature ---- */
	if (sig_size > 0) {
		if (offset + sig_size > file_size) {
			ERR("Truncated: global signature\n");
			ret = -1; goto out;
		}
		const uint8_t *global_sig = file + offset;
		INF("[Global Signature — %zu bytes]\n  ", sig_size);
		for (size_t i = 0; i < sig_size; i++)
			INF("%02x", global_sig[i]);
		INF("\n");

		if (ghdr->flags == GBL_FLAG_ED25519) {
			/* Message is just the global_hdr (8 bytes); pubkey is bound
			 * implicitly via Ed25519's A term in SHA-512(R || A || M). */
			if (crypto_verify_both(pubkey, global_sig, sig_size,
					       ghdr->raw, NULL, 0,
					       "global cert") != 0)
				ret = -1;
		}
		INF("\n");
		crc = crc32_feed(crc, global_sig, sig_size, crc_table);
		offset += sig_size;
	}

	/* ---- Separator / partition loop ---- */
	int part_num = 0;
	int all_ok = 1;

	while (offset < file_size) {
		if (offset + 8 > file_size) {
			ERR("Truncated: separator header\n");
			ret = -1; goto out;
		}
		const sep_hdr_t *sep = (const sep_hdr_t *)(file + offset);
		crc = crc32_feed(crc, file + offset, 8, crc_table);
		offset += 8;

		int crc_ok = (~crc) == CRC32_REMAINDER;
		if (crc_ok)
			INF("[Separator %d]  next=%u bytes  CRC: PASS\n",
			    part_num + 1, sep->next_part_size);
		else {
			ERR("[Separator %d]  next=%u bytes  CRC: FAIL\n",
			    part_num + 1, sep->next_part_size);
			ret = -1; all_ok = 0;
		}

		if (sep->next_part_size == 0)
			break;

		part_num++;
		size_t part_size = sep->next_part_size;

		/* ---- Partition header ---- */
		if (offset + 8 > file_size) {
			ERR("Truncated: partition header\n");
			ret = -1; goto out;
		}
		const part_hdr_t *phdr = (const part_hdr_t *)(file + offset);
		const char *type_str =
			phdr->type == IMG_TYPE_FBSL     ? "FSBL" :
			phdr->type == IMG_TYPE_DTB      ? "DTB"  :
			phdr->type == IMG_TYPE_BOOT_STEP? "BOOT_STEP" : "?";
		INF("\n[Partition %d: %s  unit=%u  release=0x%04X  %s]\n",
		       part_num, type_str, phdr->unit_id, phdr->version,
		       phdr->flags == PART_FLAG_LZ4 ? "LZ4" : "UNCOMPRESSED");

		crc = crc32_feed(crc, file + offset, 8, crc_table);
		offset += 8;

		/* ---- Partition signature (before payload) ---- */
		const uint8_t *part_sig = NULL;
		if (sig_size > 0) {
			if (offset + sig_size > file_size) {
				ERR("Truncated: partition signature\n");
				ret = -1; goto out;
			}
			part_sig = file + offset;
			INF("[Partition %d Signature — %zu bytes]\n  ",
			       part_num, sig_size);
			for (size_t i = 0; i < sig_size; i++)
				INF("%02x", part_sig[i]);
			INF("\n");
			crc = crc32_feed(crc, part_sig, sig_size, crc_table);
			offset += sig_size;
		}

		size_t payload_size = part_size - 8 - sig_size;
		size_t image_size   = phdr->image_size;

		if (offset + payload_size > file_size) {
			ERR("Truncated: partition payload\n");
			ret = -1; goto out;
		}
		const uint8_t *payload = file + offset;
		crc = crc32_feed(crc, payload, payload_size, crc_table);
		offset += payload_size;

		INF("  Compressed  : %zu bytes\n", payload_size);
		INF("  Uncompressed: %zu bytes\n", image_size);

		/*
		 * Decompress (if needed) and verify the partition signature.
		 *
		 * crypto_verify_signature() takes the 8-byte part_hdr separately
		 * as a uint64_t and the decompressed payload as body — no need to
		 * concatenate them into one buffer for the builtin path.
		 *
		 * For the OpenSSL cross-check in crypto_verify_both(), the helper
		 * allocates its own [8 + body_len] buffer internally.
		 *
		 * LZ4 without --dump: anon mmap of image_size for the decompressed
		 * output; passed directly as body to crypto_verify_both().
		 *
		 * LZ4 with --dump: file-backed MAP_SHARED mmap for the output;
		 * ftruncate trims to actual decompressed size after verification.
		 *
		 * Uncompressed: payload points into the file mmap; passed directly.
		 */
		uint8_t *anon_buf     = MAP_FAILED;
		size_t   anon_size    = 0;
		uint8_t *out_map      = MAP_FAILED;
		size_t   out_map_size = 0;
		int      out_fd       = -1;
		const void *verify_body = NULL;

		if (phdr->flags == PART_FLAG_LZ4) {
			struct lz4_ctx lz4;

			if (do_dump) {
				char out_path[32];
				snprintf(out_path, sizeof(out_path),
					 "/tmp/part%d.bin", part_num - 1);
				out_fd = open(out_path,
					      O_RDWR|O_CREAT|O_TRUNC, 0644);
				if (out_fd < 0) {
					ERR("open %s: %s\n", out_path, strerror(errno));
					ret = -1; all_ok = 0; goto part_done;
				}
				if (ftruncate(out_fd, (off_t)image_size) < 0) {
					ERR("ftruncate %s: %s\n", out_path, strerror(errno));
					ret = -1; all_ok = 0; goto part_done;
				}
				out_map = mmap(NULL, image_size,
					       PROT_READ|PROT_WRITE,
					       MAP_SHARED, out_fd, 0);
				if (out_map == MAP_FAILED) {
					ERR("mmap %s: %s\n", out_path, strerror(errno));
					ret = -1; all_ok = 0; goto part_done;
				}
				out_map_size = image_size;

				lz4_init(&lz4, out_map, image_size);
				lz4_process_chunk(&lz4, payload, payload_size);

				if (lz4.total_written != image_size) {
					ERR("  Decompress  : FAIL (got %zu, expected %zu)\n",
					       lz4.total_written, image_size);
					ret = -1; all_ok = 0; goto part_done;
				}
				INF("  Decompress  : OK (%zu bytes) → %s\n",
				       lz4.total_written, out_path);
				if (ftruncate(out_fd,
					      (off_t)lz4.total_written) < 0) {
					ERR("ftruncate trim %s: %s\n",
					       out_path, strerror(errno));
					ret = -1; all_ok = 0; goto part_done;
				}
				verify_body = out_map;
			} else {
				anon_size = image_size;
				anon_buf = mmap(NULL, anon_size,
						PROT_READ|PROT_WRITE,
						MAP_PRIVATE|MAP_ANONYMOUS,
						-1, 0);
				if (anon_buf == MAP_FAILED) {
					ERR("mmap anon: %s\n", strerror(errno));
					ret = -1; all_ok = 0; goto part_done;
				}

				lz4_init(&lz4, anon_buf, image_size);
				lz4_process_chunk(&lz4, payload, payload_size);

				if (lz4.total_written != image_size) {
					ERR("  Decompress  : FAIL (got %zu, expected %zu)\n",
					       lz4.total_written, image_size);
					ret = -1; all_ok = 0; goto part_done;
				}
				INF("  Decompress  : OK (%zu bytes)\n",
				       lz4.total_written);
				verify_body = anon_buf;
			}
		} else {
			INF("  Decompress  : N/A (uncompressed)\n");
			if (do_dump) {
				char out_path[32];
				snprintf(out_path, sizeof(out_path),
					 "/tmp/part%d.bin", part_num - 1);
				out_fd = open(out_path,
					      O_RDWR|O_CREAT|O_TRUNC, 0644);
				if (out_fd < 0) {
					ERR("open %s: %s\n", out_path, strerror(errno));
					ret = -1; all_ok = 0; goto part_done;
				}
				if (ftruncate(out_fd, (off_t)image_size) < 0) {
					ERR("ftruncate %s: %s\n", out_path, strerror(errno));
					ret = -1; all_ok = 0; goto part_done;
				}
				out_map = mmap(NULL, image_size,
					       PROT_READ|PROT_WRITE,
					       MAP_SHARED, out_fd, 0);
				if (out_map == MAP_FAILED) {
					ERR("mmap %s: %s\n", out_path, strerror(errno));
					ret = -1; all_ok = 0; goto part_done;
				}
				out_map_size = image_size;
				memcpy(out_map, payload, image_size);
				INF("  Dumped      : %s\n", out_path);
			}
			verify_body = payload;
		}

		/* ---- Partition signature verification ---- */
		if (part_sig && pubkey && ghdr->flags == GBL_FLAG_ED25519) {
			if (crypto_verify_both(pubkey, part_sig, sig_size,
					       phdr->raw, verify_body, image_size,
					       "partition sig") != 0) {
				ret = -1; all_ok = 0;
			}
		}
		if (sig_size > 0)
			INF("\n");

	part_done:
		if (anon_buf != MAP_FAILED) munmap(anon_buf, anon_size);
		if (out_map  != MAP_FAILED) munmap(out_map,  out_map_size);
		if (out_fd   >= 0)          close(out_fd);
		if (ret < 0) goto out;
	}

	if (all_ok && ret == 0)
		ANN("=== %d partition(s), all checks PASSED ===\n", part_num);
	else
		ERR("=== %d partition(s), checks FAILED ===\n", part_num);

out:
	munmap((void *)file, file_size);
	return ret;
}

/************************************\
* Parser test (chunk-by-chunk mode)  *
\************************************/

#define CHUNK_SIZE 512

static int test_parser(const char *path)
{
	ANN("=== Image Parser Test ===\n");
	INF("Input file: %s\n", path);
	INF("Chunk size: %d bytes\n\n", CHUNK_SIZE);

	FILE *fp = fopen(path, "rb");
	if (!fp) { ERR("fopen %s: %s\n", path, strerror(errno)); return -1; }

	fseek(fp, 0, SEEK_END);
	long file_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	INF("File size: %ld bytes\n\n", file_size);

	ImgpState *imgp = imgp_init_state();
	if (!imgp) {
		ERR("Failed to initialize parser state\n");
		fclose(fp);
		return -1;
	}

	uint8_t buffer[CHUNK_SIZE];
	size_t total_read = 0, chunk_num = 0;
	int ret = 0;

	INF("Processing chunks:\n");
	while (!feof(fp)) {
		size_t bytes_read = fread(buffer, 1, CHUNK_SIZE, fp);
		if (bytes_read == 0) break;

		total_read += bytes_read;
		chunk_num++;
		INF("\033[FChunk %zu: %zu bytes (total: %zu/%ld)\033[K\n",
		       chunk_num, bytes_read, total_read, file_size);

		ret = imgp_tftp_handler(imgp, buffer, bytes_read);
		if (ret < 0) {
			ERR("\nParser error: %d (%s)\n",
				ret, strerror(-ret));
			fclose(fp);
			imgp_clear_state();
			return -1;
		}
	}
	fclose(fp);
	ret = imgp_tftp_handler(imgp, NULL, 0);
	imgp_clear_state();

	ANN("\n=== Parsing Complete ===\n");
	INF("Total chunks : %zu\n", chunk_num);
	INF("Total bytes  : %zu\n", total_read);
	INF("Bytes written: %d\n", ret);

	size_t part0_size = test_get_partition_size(0);
	size_t part1_size = (size_t)ret - part0_size;

	INF("\nTruncating output files:\n");
	INF("  /tmp/part0.bin: %zu bytes\n", part0_size);
	INF("  /tmp/part1.bin: %zu bytes\n", part1_size);

	if (part0_size > 0 && truncate("/tmp/part0.bin", (off_t)part0_size) < 0) {
		ERR("truncate /tmp/part0.bin: %s\n", strerror(errno));
		return -1;
	}
	if (part1_size > 0 && truncate("/tmp/part1.bin", (off_t)part1_size) < 0) {
		ERR("truncate /tmp/part1.bin: %s\n", strerror(errno));
		return -1;
	}

	INF("\nVerify with:\n");
	INF("  md5sum ../tftp-root/boot.bin /tmp/part0.bin\n");
	INF("  md5sum ../tftp-root/boot.dtb /tmp/part1.bin\n");
	return 0;
}

/********\
* main   *
\********/

int main(int argc, char *argv[])
{
	const char *img_path = "../tftp-root/boot.img";
	int do_test_parser = 0;
	int do_dump = 0;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-t") == 0 ||
		    strcmp(argv[i], "--test-parser") == 0)
			do_test_parser = 1;
		else if (strcmp(argv[i], "-d") == 0 ||
			 strcmp(argv[i], "--dump") == 0)
			do_dump = 1;
		else
			img_path = argv[i];
	}

	if (crypto_selftest() != 0) {
		ERR("Crypto self-test failed\n");
		return 1;
	}
	ANN("[SELFTEST] PASSED\n\n");

	if (do_test_parser)
		return test_parser(img_path) < 0 ? 1 : 0;
	else
		return inspect_container(img_path, do_dump) < 0 ? 1 : 0;
}
