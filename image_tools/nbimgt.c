/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2026 Nick Kossifidis <mick@ics.forth.gr>
 * SPDX-FileCopyrightText: 2026 ICS/FORTH
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * nbimgt — NetBoot Image Tool
 *
 * Build and verify NetBoot image containers (img.h format).
 *
 * Usage:
 *   nbimgt build  [--sign KEY.pem] [--release-id ID] FSBL DTB [OUTPUT]
 *   nbimgt verify [--dump] [--test-parser] IMAGE
 *   nbimgt keygen KEY.pem
 */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <getopt.h>
#include <sys/prctl.h>
#include <sys/stat.h>

#include <openssl/crypto.h>

#include <img.h>
#include <crypto.h>
#include <utils.h>
#include "res.h"
#include "crypto_ops.h"
#include "container.h"

/* Forward-declare for max_size estimation in cmd_build */
extern int LZ4_compressBound(int inputSize);

#define CHUNK_SIZE 512

/* From units/self.c — only used in test-parser mode */
extern size_t test_get_partition_size(int part_id);


/*********\
* Helpers *
\*********/

static void
print_help(const char *prog)
{
	INF("Usage:\n");
	INF("  %s build  [-s KEY.pem] [-r ID] FSBL DTB [OUTPUT]\n", prog);
	INF("  %s verify [-d] [-t] [IMAGE]\n", prog);
	INF("  %s keygen KEY.pem\n", prog);
	INF("\n");
	INF("Commands:\n");
	INF("  build   Build a container from FSBL and DTB binaries\n");
	INF("  verify  Inspect and cryptographically verify a container\n");
	INF("  keygen  Generate an Ed25519 key pair\n");
	INF("\n");
	INF("Options for build:\n");
	INF("  FSBL                   Path to the FSBL/boot binary\n");
	INF("  DTB                    Path to the device tree blob\n");
	INF("  OUTPUT                 Output file (default: boot.img)\n");
	INF("  -s, --sign KEY.pem     Sign with Ed25519 key"
	    " (generates if missing)\n");
	INF("  -r, --release-id ID    Release ID, hex or decimal"
	    " (default: 0x0001)\n");
	INF("\n");
	INF("Options for verify:\n");
	INF("  IMAGE                  Container image"
	    " (default: ../tftp-root/boot.img)\n");
	INF("  -d, --dump             Decompress partitions to /tmp/partN.bin\n");
	INF("  -t, --test-parser      Feed through the streaming TFTP parser\n");
}


/****************************\
* Streaming parser test mode *
\****************************/

static int
test_parser(const char *path)
{
	ImgpState *imgp = NULL;
	FILE *fp = NULL;
	uint8_t buffer[CHUNK_SIZE];
	size_t bytes_read = 0, total_read = 0, chunk_num = 0;
	size_t part0_size = 0, part1_size = 0;
	long file_size = 0;
	int ret = 0;

	ANN("=== Image Parser Test ===\n");
	INF("Input file : %s\n", path);
	INF("Chunk size : %d bytes\n\n", CHUNK_SIZE);

	fp = fopen(path, "rb");
	if (!fp) {
		ERR("fopen %s: %s\n", path, strerror(errno));
		return -1;
	}
	fseek(fp, 0, SEEK_END);
	file_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	INF("File size  : %ld bytes\n\n", file_size);

	imgp = imgp_init_state();
	if (!imgp) {
		ERR("Failed to initialise parser state\n");
		fclose(fp);
		return -1;
	}

	INF("Processing chunks:\n");
	while (!feof(fp)) {
		bytes_read = fread(buffer, 1, CHUNK_SIZE, fp);
		if (bytes_read == 0)
			break;
		total_read += bytes_read;
		chunk_num++;
		INF("\033[FChunk %zu: %zu bytes (total: %zu/%ld)\033[K\n",
		    chunk_num, bytes_read, total_read, file_size);
		ret = imgp_tftp_handler(imgp, buffer, bytes_read);
		if (ret < 0) {
			ERR("\nParser error: %d (%s)\n", ret, strerror(-ret));
			fclose(fp);
			imgp_clear_state();
			return -1;
		}
	}
	fclose(fp);

	ret = imgp_tftp_handler(imgp, NULL, 0);
	imgp_clear_state();

	if (ret < 0) {
		ERR("\nParser error on flush: %d (%s)\n", ret, strerror(-ret));
		return -1;
	}

	ANN("\n=== Parsing Complete ===\n");
	INF("Total chunks : %zu\n", chunk_num);
	INF("Total bytes  : %zu\n", total_read);
	INF("Bytes written: %d\n", ret);

	part0_size = test_get_partition_size(0);
	if (part0_size > (size_t)ret) {
		ERR("Partition 0 size (%zu) exceeds total written (%d)\n",
		    part0_size, ret);
		return -1;
	}
	part1_size = (size_t)ret - part0_size;

	INF("\nTruncating output files:\n");
	INF("  /tmp/part0.bin: %zu bytes\n", part0_size);
	INF("  /tmp/part1.bin: %zu bytes\n", part1_size);

	if (part0_size > 0 &&
	    truncate("/tmp/part0.bin", (off_t)part0_size) < 0) {
		ERR("truncate /tmp/part0.bin: %s\n", strerror(errno));
		return -1;
	}
	if (part1_size > 0 &&
	    truncate("/tmp/part1.bin", (off_t)part1_size) < 0) {
		ERR("truncate /tmp/part1.bin: %s\n", strerror(errno));
		return -1;
	}
	INF("\nVerify with:\n");
	INF("  md5sum ../tftp-root/boot.bin /tmp/part0.bin\n");
	INF("  md5sum ../tftp-root/boot.dtb /tmp/part1.bin\n");
	return 0;
}


/*******************\
* Build sub-command *
\*******************/

static int
cmd_build(const char *fsbl_path, const char *dtb_path,
	  const char *out_path, uint16_t release_id, const char *key_path)
{
	struct res_t    *fsbl_res = NULL, *dtb_res = NULL;
	struct cont_ctx *cont = NULL;
	struct cops_ctx *cops = NULL;
	size_t pub_sz = 0, sig_sz = 0, max_size = 0;
	int ret = -1;

	ANN("Building image container...\n");
	INF("  FSBL: %s\n", fsbl_path);
	INF("  DTB:  %s\n", dtb_path);

	fsbl_res = res_from_file(fsbl_path, 0);
	if (!fsbl_res)
		goto cleanup;

	dtb_res = res_from_file(dtb_path, 0);
	if (!dtb_res)
		goto cleanup;

	INF("  FSBL size: %zu bytes\n", fsbl_res->size);
	INF("  DTB  size: %zu bytes\n", dtb_res->size);

	if (key_path) {
		cops = cops_init(key_path, 0);
		if (!cops)
			goto cleanup;

		INF("  Public key: ");
		{
			uint8_t pub[CRYPTO_MAX_PUBKEY_SIZE];
			size_t  pub_len = sizeof(pub);

			if (cops_get_pubkey(cops, pub, &pub_len) == 0) {
				for (size_t i = 0; i < pub_len; i++)
					INF("%02x", pub[i]);
			}
		}
		INF("\n");
	}

	if (fsbl_res->size > (size_t)INT_MAX || dtb_res->size > (size_t)INT_MAX) {
		ERR("Input too large for LZ4\n");
		goto cleanup;
	}

	pub_sz = cops_pub_size(cops);
	sig_sz = cops_sig_size(cops);

	max_size = sizeof(global_hdr_t) + pub_sz + sig_sz
		 + sizeof(sep_hdr_t) + sizeof(part_hdr_t) + sig_sz
		 + (size_t)LZ4_compressBound((int)fsbl_res->size) + 8
		 + sizeof(sep_hdr_t) + sizeof(part_hdr_t) + sig_sz
		 + (size_t)LZ4_compressBound((int)dtb_res->size)  + 8
		 + sizeof(sep_hdr_t) + 64;

	cont = container_open(out_path, max_size);
	if (!cont)
		goto cleanup;

	if (container_new(cont, cops, release_id) < 0)
		goto cleanup;

	/* container_add_partition takes ownership of the resource */
	if (container_add_partition(cont, fsbl_res,
				    UNIT_ID_SELF, IMG_TYPE_FBSL,
				    PART_FLAG_LZ4) < 0)
		goto cleanup;
	fsbl_res = NULL;

	if (container_add_partition(cont, dtb_res,
				    UNIT_ID_SELF, IMG_TYPE_DTB,
				    PART_FLAG_LZ4) < 0)
		goto cleanup;
	dtb_res = NULL;

	if (container_finalize(cont) < 0)
		goto cleanup;

	ANN("  Output : %s  (%zu bytes, %s)\n",
	    out_path, cont->size, cops ? "signed" : "unsigned");
	ret = 0;

cleanup:
	container_close(cont);
	cops_exit(cops);
	res_release(fsbl_res);
	res_release(dtb_res);
	return ret;
}


/********************\
* Verify sub-command *
\********************/

static int
cmd_verify(const char *path, int do_dump, int do_test_parser)
{
	struct cont_ctx *cont = NULL;
	int ret = 0;

	if (crypto_selftest() != 0) {
		ERR("Crypto self-test failed\n");
		return -1;
	}
	ANN("[SELFTEST] PASSED\n\n");

	if (do_test_parser)
		return test_parser(path);

	cont = container_open(path, 0);
	if (!cont)
		return -1;

	ret = container_verify(cont, do_dump);
	container_close(cont);
	return ret;
}


/********\
* Keygen *
\********/

static int
cmd_keygen(const char *path)
{
	struct cops_ctx *cops = NULL;

	cops = cops_init(path, COPS_KEY_NEW);
	if (!cops)
		return -1;
	cops_exit(cops);
	return 0;
}


/******\
* main *
\******/

int
main(int argc, char *argv[])
{
	const char *cmd = NULL;
	int c = 0, ret = 1;

	prctl(PR_SET_DUMPABLE, 0);
	CRYPTO_secure_malloc_init(65536, 16);

	if (argc < 2) {
		print_help(argv[0]);
		goto out;
	}

	cmd = argv[1];

	if (strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0) {
		print_help(argv[0]);
		ret = 0;
		goto out;
	}

	/* ---- build ---- */
	if (strcmp(cmd, "build") == 0) {
		static const struct option build_opts[] = {
			{ "sign",       required_argument, NULL, 's' },
			{ "release-id", required_argument, NULL, 'r' },
			{ "help",       no_argument,       NULL, 'h' },
			{ NULL, 0, NULL, 0 }
		};
		const char *fsbl_path = NULL;
		const char *dtb_path  = NULL;
		const char *out_path  = "boot.img";
		const char *key_path  = NULL;
		uint16_t release_id   = 0x0001;

		optind = 2;
		while ((c = getopt_long(argc, argv, "s:r:h",
					build_opts, NULL)) != -1) {
			switch (c) {
			case 's': key_path = optarg; break;
			case 'r': {
				char *end = NULL;
				unsigned long v = strtoul(optarg, &end, 0);

				if (!*optarg || *end || v > 0xFFFFUL) {
					ERR("build: invalid release-id '%s'"
					    " (must be 0..0xFFFF)\n", optarg);
					goto out;
				}
				release_id = (uint16_t)v;
				break;
			}
			case 'h': print_help(argv[0]); ret = 0; goto out;
			default:  goto usage;
			}
		}
		fsbl_path = (optind < argc) ? argv[optind++] : NULL;
		dtb_path  = (optind < argc) ? argv[optind++] : NULL;
		if (!fsbl_path || !dtb_path) {
			ERR("build: FSBL and DTB paths are required\n");
			goto usage;
		}
		if (optind < argc)
			out_path = argv[optind];
		ret = cmd_build(fsbl_path, dtb_path, out_path,
				release_id, key_path) < 0 ? 1 : 0;
		goto out;
	}

	/* ---- verify ---- */
	if (strcmp(cmd, "verify") == 0) {
		static const struct option verify_opts[] = {
			{ "dump",        no_argument, NULL, 'd' },
			{ "test-parser", no_argument, NULL, 't' },
			{ "help",        no_argument, NULL, 'h' },
			{ NULL, 0, NULL, 0 }
		};
		const char *img_path   = "../tftp-root/boot.img";
		int do_dump        = 0;
		int do_test_parser = 0;

		optind = 2;
		while ((c = getopt_long(argc, argv, "dth",
					verify_opts, NULL)) != -1) {
			switch (c) {
			case 'd': do_dump        = 1; break;
			case 't': do_test_parser = 1; break;
			case 'h': print_help(argv[0]); ret = 0; goto out;
			default:  goto usage;
			}
		}
		if (optind < argc)
			img_path = argv[optind];
		ret = cmd_verify(img_path, do_dump, do_test_parser) < 0 ? 1 : 0;
		goto out;
	}

	/* ---- keygen ---- */
	if (strcmp(cmd, "keygen") == 0) {
		static const struct option keygen_opts[] = {
			{ "help", no_argument, NULL, 'h' },
			{ NULL, 0, NULL, 0 }
		};
		const char *key_path = NULL;

		optind = 2;
		while ((c = getopt_long(argc, argv, "h",
					keygen_opts, NULL)) != -1) {
			switch (c) {
			case 'h': print_help(argv[0]); ret = 0; goto out;
			default:  goto usage;
			}
		}
		key_path = (optind < argc) ? argv[optind] : NULL;
		if (!key_path) {
			ERR("keygen: key path is required\n");
			goto usage;
		}
		ret = cmd_keygen(key_path) < 0 ? 1 : 0;
		goto out;
	}

	ERR("Unknown command: %s\n", cmd);

usage:
	print_help(argv[0]);

out:
	CRYPTO_secure_malloc_done();
	return ret;
}
