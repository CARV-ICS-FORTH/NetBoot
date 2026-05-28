/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2026 Nick Kossifidis <mick@ics.forth.gr>
 * SPDX-FileCopyrightText: 2026 ICS/FORTH
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Container build and verify operations.
 *
 * Build path:
 *	container_open(path, max_sz) → container_new(keyp, ver)
 *	container_add_partition() × N → container_finalize()
 *	container_close()
 *
 * Verify path:
 *	container_open(path, 0) → container_verify(do_dump) → container_close()
 */
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <img.h>
#include <crypto.h>
#include <utils.h>
#include "res.h"
#include "crypto_ops.h"
#include "partition.h"
#include "container.h"

/* ghdr.flags is round-tripped through (crypto_algo_t) — values must match */
_Static_assert((int)CRYPTO_ALGO_NONE     == (int)GBL_FLAG_NO_CRYPTO,
	       "CRYPTO_ALGO_NONE / GBL_FLAG_NO_CRYPTO mismatch");
_Static_assert((int)CRYPTO_ALGO_ED25519  == (int)GBL_FLAG_ED25519,
	       "CRYPTO_ALGO_ED25519 / GBL_FLAG_ED25519 mismatch");
_Static_assert((int)CRYPTO_ALGO_ECDSA384 == (int)GBL_FLAG_ECDSA384,
	       "CRYPTO_ALGO_ECDSA384 / GBL_FLAG_ECDSA384 mismatch");


/********\
* CRC32  *
\********/

#define CRC32_POLY	0xEDB88320U
#define CRC32_REMAINDER	0x2144DF1CU

static void
crc32_init_table(uint32_t table[16])
{
	int i = 0, j = 0;
	uint32_t crc = 0;

	for (i = 0; i < 16; i++) {
		crc = (uint32_t)i;
		for (j = 0; j < 4; j++) {
			if (crc & 1)
				crc = (crc >> 1) ^ CRC32_POLY;
			else
				crc >>= 1;
		}
		table[i] = crc;
	}
}

static uint32_t
crc32_feed(uint32_t crc, const uint8_t *data, size_t len, const uint32_t *table)
{
	size_t i = 0;

	for (i = 0; i < len; i++) {
		crc = (crc >> 4) ^ table[(crc ^ (data[i] & 0x0F)) & 0x0F];
		crc = (crc >> 4) ^ table[(crc ^ (data[i] >> 4)) & 0x0F];
	}
	return crc;
}


/****************\
* String helpers *
\****************/

static const char *
flag_str(uint8_t flags)
{
	switch (flags) {
	case GBL_FLAG_NO_CRYPTO:
		return "NO_CRYPTO";
	case GBL_FLAG_ED25519:
		return "ED25519";
	case GBL_FLAG_ECDSA384:
		return "ECDSA384";
	default:
		return "UNKNOWN";
	}
}

static const char *
img_type_str(uint8_t type)
{
	switch (type) {
	case IMG_TYPE_BOOT_STEP:
		return "BOOT_STEP";
	case IMG_TYPE_FBSL:
		return "FSBL";
	case IMG_TYPE_DTB:
		return "DTB";
	default:
		return "?";
	}
}


/***********\
* Lifecycle *
\***********/

struct cont_ctx *
container_open(const char *file_path, size_t max_size)
{
	struct cont_ctx *cont = NULL;

	cont = malloc(sizeof(struct cont_ctx));
	if (!cont)
		return NULL;
	memset(cont, 0, sizeof(struct cont_ctx));

	cont->res = res_from_file(file_path, max_size);
	if (!cont->res) {
		free(cont);
		return NULL;
	}

	cont->buf       = cont->res->buf;
	cont->max_size  = cont->res->max_size;
	cont->read_only = (max_size == 0);

	if (cont->read_only)
		cont->size = cont->res->size;

	return cont;
}

int
container_new(struct cont_ctx *cont, struct cops_ctx *cops, uint16_t version)
{
	size_t pub_sz = 0, sig_sz = 0;

	if (!cont || cont->read_only)
		return -1;

	cont->cops    = cops;
	cont->version = version;

	pub_sz = cops_pub_size(cops);
	sig_sz = cops_sig_size(cops);

	/* Reserve space for global header + pubkey + global sig */
	cont->hdr_end = sizeof(global_hdr_t) + pub_sz + sig_sz;
	cont->size    = cont->hdr_end;
	return 0;
}

int
container_set_cops(struct cont_ctx *cont, struct cops_ctx *cops)
{
	if (!cont || cont->read_only || cont->finalized)
		return -1;
	cont->cops = cops;
	return 0;
}

void
container_close(struct cont_ctx *cont)
{
	if (!cont)
		return;
	res_release(cont->res);
	free(cont);
}


/*******\
* Build *
\*******/

int
container_add_partition(struct cont_ctx *cont, struct res_t *res,
			uint8_t unit_id, uint8_t type, uint8_t flags)
{
	struct part_t *part = NULL;
	sep_hdr_t *sep = NULL;

	if (!cont || cont->read_only || cont->finalized)
		return -1;

	INF("  Adding partition: unit=%u type=%u\n", unit_id, type);

	part = part_new(unit_id, type, cont->version, flags, cont->cops, res);
	if (!part)
		return -1;

	if (part_sign(part) < 0) {
		part_free(part);
		return -1;
	}
	if (part_finalize(part) < 0) {
		part_free(part);
		return -1;
	}

	if (cont->size + sizeof(sep_hdr_t) + part->size > cont->max_size) {
		ERR("Container too small for partition (need %zu, have %zu)\n",
		    cont->size + sizeof(sep_hdr_t) + part->size, cont->max_size);
		part_free(part);
		return -1;
	}

	/* Write separator with next_part_size; rolling_crc patched at finalize */
	sep = (sep_hdr_t *)(cont->buf + cont->size);
	sep->next_part_size = (uint32_t)part->size;
	sep->rolling_crc    = 0;
	cont->size += sizeof(sep_hdr_t);

	memcpy(cont->buf + cont->size, part->buf, part->size);
	cont->size += part->size;

	cont->part_count++;
	part_free(part);
	return 0;
}

/*
 * Walk the buffer and patch each separator's rolling_crc field.
 *
 * The CRC32 check property: after feeding next_part_size || ~CRC(prev||nps),
 * the running CRC always equals ~CRC32_REMAINDER. So every separator
 * independently satisfies the verifier's creader_crc_ok() check.
 */
static void
patch_crcs(uint8_t *buf, size_t hdr_end, size_t total_size,
	   const uint32_t *crc_table)
{
	uint32_t crc = 0, crc_ns = 0;
	sep_hdr_t *sep = NULL;
	size_t off = 0;

	crc = 0xFFFFFFFF;
	crc = crc32_feed(crc, buf, hdr_end, crc_table);

	off = hdr_end;
	while (off + sizeof(sep_hdr_t) <= total_size) {
		sep = (sep_hdr_t *)(buf + off);

		crc_ns = crc32_feed(crc, (const uint8_t *)&sep->next_part_size,
				    sizeof(sep->next_part_size), crc_table);
		sep->rolling_crc = ~crc_ns & 0xFFFFFFFFU;

		/* Advance CRC over the full separator (both fields) */
		crc = crc32_feed(crc_ns,
				 (const uint8_t *)&sep->rolling_crc,
				 sizeof(sep->rolling_crc), crc_table);
		off += sizeof(sep_hdr_t);

		if (sep->next_part_size == 0)
			break;

		if (off + sep->next_part_size > total_size)
			break;

		crc = crc32_feed(crc, buf + off, sep->next_part_size, crc_table);
		off += sep->next_part_size;
	}
}

int
container_finalize(struct cont_ctx *cont)
{
	global_hdr_t ghdr;
	uint32_t crc_table[16];
	sep_hdr_t *final_sep = NULL;
	size_t pub_sz = 0, sig_sz = 0;

	if (!cont || cont->read_only || cont->finalized)
		return -1;

	if (cont->size + sizeof(sep_hdr_t) > cont->max_size) {
		ERR("No space for final separator\n");
		return -1;
	}

	/* Write final separator (next_part_size = 0) */
	final_sep = (sep_hdr_t *)(cont->buf + cont->size);
	final_sep->next_part_size = 0;
	final_sep->rolling_crc    = 0;
	cont->size += sizeof(sep_hdr_t);

	pub_sz = cops_pub_size(cont->cops);
	sig_sz = cops_sig_size(cont->cops);

	/* Build and write global header */
	memset(&ghdr, 0, sizeof(global_hdr_t));
	ghdr.magic       = IMG_MAGIC_NB;
	ghdr.hdr_version = 0;
	ghdr.part_count  = cont->part_count;
	ghdr.flags       = cont->cops ? (uint8_t)cops_algo(cont->cops)
				      : GBL_FLAG_NO_CRYPTO;
	ghdr.total_size  = (uint32_t)cont->size;
	memcpy(cont->buf, &ghdr.raw, sizeof(global_hdr_t));

	/* Write public key */
	if (pub_sz > 0) {
		uint8_t pub_buf[CRYPTO_MAX_PUBKEY_SIZE];
		size_t  pub_buf_len = sizeof(pub_buf);

		if (cops_get_pubkey(cont->cops, pub_buf, &pub_buf_len) < 0)
			return -1;
		memcpy(cont->buf + sizeof(global_hdr_t), pub_buf, pub_sz);
	}

	/* Sign the global header and write the signature */
	if (sig_sz > 0) {
		if (cops_sign(cont->cops, (const uint8_t *)&ghdr.raw,
			      sizeof(global_hdr_t),
			      cont->buf + sizeof(global_hdr_t) + pub_sz) < 0)
			return -1;
		INF("  Global sig: %02x%02x%02x%02x...\n",
		    cont->buf[sizeof(global_hdr_t) + pub_sz],
		    cont->buf[sizeof(global_hdr_t) + pub_sz + 1],
		    cont->buf[sizeof(global_hdr_t) + pub_sz + 2],
		    cont->buf[sizeof(global_hdr_t) + pub_sz + 3]);
	}

	crc32_init_table(crc_table);
	patch_crcs(cont->buf, cont->hdr_end, cont->size, crc_table);

	cont->res->size = cont->size;
	cont->finalized = 1;

	ANN("\nContainer built successfully: %zu bytes, %u partition(s), %s\n",
	    cont->size, cont->part_count,
	    cont->cops ? "signed" : "unsigned");
	return 0;
}


/********\
* Verify *
\********/

/*
 * Sequential-read context for walking the container buffer.
 * Advances offset and accumulates CRC as data is consumed.
 */
struct vctx {
	const uint8_t *buf;
	size_t         size;
	size_t         off;
	uint32_t       crc;
	uint32_t       crc_table[16];
};

static const void *
vctx_read(struct vctx *vc, size_t len)
{
	const void *p = NULL;

	if (vc->off > vc->size || len > vc->size - vc->off)
		return NULL;
	p = vc->buf + vc->off;
	vc->crc = crc32_feed(vc->crc, p, len, vc->crc_table);
	vc->off += len;
	return p;
}

/* Thin wrapper: annotates label and delegates to cops_verify. */
static int
verify_sig(crypto_algo_t algo,
	   const uint8_t *pub, size_t pub_len,
	   const uint8_t *sig, size_t sig_len,
	   uint64_t hdr_raw,
	   const void *body, size_t body_len,
	   const char *label)
{
	int ret = cops_verify(algo, pub, pub_len, sig, sig_len,
			      hdr_raw, body, body_len);

	if (ret != 0)
		WRN("%s — FAILED\n", label);
	return ret;
}

/*
 * Process one partition after its separator has been consumed.
 * Reads part header, signature (if any), and payload via vctx_read.
 * Decompresses for signature check and optional dump.
 * Returns 0 on success, -1 on hard error (truncation, OOM).
 * Sets *all_ok = 0 on soft verification failures.
 */
static int
verify_one_partition(struct vctx *vc, uint32_t part_size, size_t sig_sz,
		     uint8_t crypto_flags,
		     const uint8_t *pub, size_t pub_len,
		     int part_num, int do_dump, uint16_t *version_out)
{
	const part_hdr_t *phdr = NULL;
	const uint8_t *part_sig = NULL, *payload = NULL;
	uint8_t *decomp = NULL;
	size_t payload_size = 0, image_size = 0;
	struct lz4_ctx lz4 = {0};
	char out_path[32];
	FILE *fp = NULL;
	int ok = 1;

	/* ---- Partition header ---- */
	phdr = (const part_hdr_t *)vctx_read(vc, sizeof(part_hdr_t));
	if (!phdr) {
		ERR("Truncated: partition header\n");
		return -1;
	}

	INF("\n[Partition %d: %s  unit=%u  release=0x%04X  %s]\n",
	    part_num, img_type_str(phdr->type), phdr->unit_id,
	    phdr->version,
	    phdr->flags == PART_FLAG_LZ4 ? "LZ4" : "UNCOMPRESSED");

	if (version_out)
		*version_out = phdr->version;

	/* ---- Partition signature ---- */
	if (sig_sz > 0) {
		part_sig = (const uint8_t *)vctx_read(vc, sig_sz);
		if (!part_sig) {
			ERR("Truncated: partition signature\n");
			return -1;
		}
		INF("[Partition %d Signature — %zu bytes]\n  ", part_num, sig_sz);
		for (size_t i = 0; i < sig_sz; i++)
			INF("%02x", part_sig[i]);
		INF("\n");
	}

	/* ---- Payload ---- */
	if ((size_t)part_size < sizeof(part_hdr_t) + sig_sz) {
		ERR("Part size %u too small for header+sig\n", part_size);
		return -1;
	}
	payload_size = (size_t)part_size - sizeof(part_hdr_t) - sig_sz;
	image_size   = (size_t)phdr->image_size;

	if (image_size == 0) {
		ERR("Partition %d: image_size is zero\n", part_num);
		return -1;
	}

	payload = (const uint8_t *)vctx_read(vc, payload_size);
	if (!payload) {
		ERR("Truncated: partition payload\n");
		return -1;
	}

	INF("  Compressed  : %zu bytes\n", payload_size);
	INF("  Uncompressed: %zu bytes\n", image_size);

	/* ---- Decompress + verify signature (or just dump) ---- */
	if ((part_sig && pub && crypto_flags == GBL_FLAG_ED25519) || do_dump) {
		decomp = malloc(image_size);
		if (!decomp) {
			ERR("malloc %zu: %s\n", image_size, strerror(errno));
			return -1;
		}

		if (phdr->flags == PART_FLAG_LZ4) {
			lz4_init(&lz4, decomp, image_size);
			lz4_process_chunk(&lz4, payload, payload_size);
			if (lz4.total_written != image_size) {
				ERR("  Decompress: FAIL (got %zu, expected %zu)\n",
				    lz4.total_written, image_size);
				free(decomp);
				return -1;
			}
			INF("  Decompress  : OK (%zu bytes)\n", lz4.total_written);
		} else {
			memcpy(decomp, payload, image_size);
			INF("  Decompress  : N/A (uncompressed)\n");
		}

		if (part_sig && pub && crypto_flags == GBL_FLAG_ED25519) {
			if (verify_sig((crypto_algo_t)crypto_flags,
				       pub, pub_len,
				       part_sig, sig_sz,
				       phdr->raw, decomp, image_size,
				       "partition sig") != 0)
				ok = 0;
			INF("\n");
		}

		if (do_dump) {
			snprintf(out_path, sizeof(out_path),
				 "/tmp/part%d.bin", part_num - 1);
			fp = fopen(out_path, "wb");
			if (fp) {
				fwrite(decomp, 1, image_size, fp);
				fclose(fp);
				INF("  Dumped      : %s\n", out_path);
			}
		}

		free(decomp);
		decomp = NULL;
	} else if (phdr->flags == PART_FLAG_LZ4) {
		INF("  (skip decompress — no sig check, no dump)\n");
	}

	return ok ? 0 : -1;
}

int
container_verify(struct cont_ctx *cont, int do_dump)
{
	const global_hdr_t *ghdr = NULL;
	const sep_hdr_t *sep = NULL;
	const uint8_t *pubkey_bytes = NULL, *global_sig = NULL;
	struct vctx vc = {0};
	uint32_t crc_ns = 0, expected_rcrc = 0;
	size_t pub_sz = 0, sig_sz = 0;
	int part_num = 0, ret = 0, all_ok = 1;
	uint16_t first_version = 0, this_version = 0;
	int have_first_version = 0;

	if (!cont || !cont->read_only)
		return -1;

	vc.buf  = cont->buf;
	vc.size = cont->size;
	vc.crc  = 0xFFFFFFFF;
	crc32_init_table(vc.crc_table);

	ANN("\n=== Container: %zu bytes ===\n\n", cont->size);

	/* ---- Global header ---- */
	ghdr = (const global_hdr_t *)vctx_read(&vc, sizeof(global_hdr_t));
	if (!ghdr) {
		ERR("Truncated: no global header\n");
		return -1;
	}

	if (ghdr->magic != IMG_MAGIC_NB) {
		ERR("Bad magic: 0x%04X (expected 0x%04X)\n",
		    ghdr->magic, IMG_MAGIC_NB);
		return -1;
	}
	if (ghdr->hdr_version != 0) {
		ERR("Unsupported header version: %u\n", ghdr->hdr_version);
		return -1;
	}

	if ((size_t)ghdr->total_size != cont->size)
		WRN("total_size field (%u) != file size (%zu)\n",
		    ghdr->total_size, cont->size);

	INF("[Global Header]\n");
	INF("  Magic      : 0x%04X (%c%c)\n", ghdr->magic,
	    ghdr->magic & 0xFF, (ghdr->magic >> 8) & 0xFF);
	INF("  Version    : %u\n",  ghdr->hdr_version);
	INF("  Partitions : %u\n",  ghdr->part_count);
	INF("  Crypto     : %s\n",  flag_str(ghdr->flags));
	INF("  Total size : %u bytes\n\n", ghdr->total_size);

	pub_sz = cops_pubkey_size_for_algo((crypto_algo_t)ghdr->flags);
	sig_sz = cops_sig_size_for_algo((crypto_algo_t)ghdr->flags);

	/* ---- Public key ---- */
	if (pub_sz > 0) {
		pubkey_bytes = (const uint8_t *)vctx_read(&vc, pub_sz);
		if (!pubkey_bytes) {
			ERR("Truncated: public key\n");
			return -1;
		}

		INF("[Public Key — %s, %zu bytes]\n  ",
		    flag_str(ghdr->flags), pub_sz);
		for (size_t i = 0; i < pub_sz; i++)
			INF("%02x", pubkey_bytes[i]);
		INF("\n\n");
	}

	/* ---- Global signature ---- */
	if (sig_sz > 0) {
		global_sig = (const uint8_t *)vctx_read(&vc, sig_sz);
		if (!global_sig) {
			ERR("Truncated: global signature\n");
			ret = -1;
			goto out;
		}

		INF("[Global Signature — %zu bytes]\n  ", sig_sz);
		for (size_t i = 0; i < sig_sz; i++)
			INF("%02x", global_sig[i]);
		INF("\n");

		if (ghdr->flags == GBL_FLAG_ED25519) {
			if (verify_sig((crypto_algo_t)ghdr->flags,
				       pubkey_bytes, pub_sz,
				       global_sig, sig_sz,
				       ghdr->raw, NULL, 0,
				       "global sig") != 0) {
				ret    = -1;
				all_ok = 0;
			}
		}
		INF("\n");
	}

	/* ---- Separator / partition loop ---- */
	part_num = 0;

	while (vc.off < vc.size) {
		int crc_ok = 0;

		if (vc.off + sizeof(sep_hdr_t) > vc.size) {
			ERR("Truncated: separator header\n");
			ret = -1;
			goto out;
		}

		/*
		 * Separator CRC is asymmetric: we feed only next_part_size into
		 * a temporary crc_ns to derive the expected rolling_crc, then
		 * advance vc.crc over the full separator manually.
		 */
		sep = (const sep_hdr_t *)(vc.buf + vc.off);
		crc_ns = crc32_feed(vc.crc, (const uint8_t *)&sep->next_part_size,
				    sizeof(sep->next_part_size), vc.crc_table);
		expected_rcrc = ~crc_ns & 0xFFFFFFFFU;
		crc_ok = (sep->rolling_crc == expected_rcrc);

		/* Advance CRC over full separator (both fields) */
		vc.crc = crc32_feed(crc_ns, (const uint8_t *)&sep->rolling_crc,
				    sizeof(sep->rolling_crc), vc.crc_table);
		vc.off += sizeof(sep_hdr_t);

		if (crc_ok) {
			INF("[Separator %d]  next=%u bytes  CRC: PASS\n",
			    part_num + 1, sep->next_part_size);
		} else {
			ERR("[Separator %d]  next=%u bytes  CRC: FAIL"
			    " (got 0x%08X, expected 0x%08X)\n",
			    part_num + 1, sep->next_part_size,
			    expected_rcrc, sep->rolling_crc);
			ret    = -1;
			all_ok = 0;
		}

		if (sep->next_part_size == 0)
			break;

		part_num++;
		this_version = 0;

		if (verify_one_partition(&vc, sep->next_part_size, sig_sz,
					 ghdr->flags,
					 pubkey_bytes, pub_sz,
					 part_num, do_dump,
					 &this_version) < 0) {
			/* Hard error — truncation or OOM */
			if (crc_ok) {
				/* CRC was fine, this is structural damage */
				ret = -1;
			}
			goto out;
		}

		/* Version consistency check */
		if (part_num == 1) {
			first_version      = this_version;
			have_first_version = 1;
		} else if (have_first_version && this_version != first_version) {
			WRN("Partition %d version 0x%04X differs from"
			    " partition 1 version 0x%04X\n",
			    part_num, this_version, first_version);
		}
	}

	if (part_num != (int)ghdr->part_count)
		WRN("part_count field (%u) != partitions found (%d)\n",
		    ghdr->part_count, part_num);

	if (all_ok && ret == 0)
		ANN("=== %d partition(s), all checks PASSED ===\n", part_num);
	else
		ERR("=== %d partition(s), checks FAILED ===\n", part_num);

out:
	return ret;
}
