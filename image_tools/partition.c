/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2026 Nick Kossifidis <mick@ics.forth.gr>
 * SPDX-FileCopyrightText: 2026 ICS/FORTH
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

#include <img.h>
#include <utils.h>
#include "res.h"
#include "crypto_ops.h"
#include "partition.h"

/*
 * Forward-declare the liblz4-hc functions we need.  Including <lz4hc.h>
 * directly conflicts with src/include/lz4.h at the same include path.
 */
extern int LZ4_compress_HC(const char *src, char *dst, int srcSize,
			    int dstCapacity, int compressionLevel);
extern int LZ4_compressBound(int inputSize);
#define LZ4HC_CLEVEL_MAX 12

static inline size_t
pad8(size_t n)
{
	return (n + 7) & ~(size_t)7;
}

struct part_t *
part_new(uint8_t unit_id, uint8_t type, uint16_t version,
	 uint8_t flags, struct cops_ctx *cops, struct res_t *res)
{
	struct part_t *part = NULL;
	size_t sig_sz = 0, cmp_size = 0, pad_size = 0, alloc_sz = 0;
	int bound = 0;

	part = malloc(sizeof(struct part_t));
	if (!part)
		return NULL;
	memset(part, 0, sizeof(struct part_t));

	part->cops = cops;
	part->orig = res;

	part->hdr.raw        = 0;
	part->hdr.version    = version;
	part->hdr.type       = type;
	part->hdr.unit_id    = unit_id;
	part->hdr.flags      = flags;
	part->hdr.image_size = (uint32_t)res->size;

	sig_sz = cops_sig_size(cops);

	if (flags == PART_FLAG_LZ4) {
		if (res->size > (size_t)INT_MAX) {
			ERR("Input too large for LZ4: %zu bytes\n", res->size);
			goto cleanup;
		}
		bound    = LZ4_compressBound((int)res->size);
		alloc_sz = sizeof(part_hdr_t) + sig_sz + (size_t)bound + 8;
		part->buf = calloc(alloc_sz, 1);
		if (!part->buf)
			goto cleanup;

		cmp_size = (size_t)LZ4_compress_HC(
			(const char *)res->buf,
			(char *)(part->buf + sizeof(part_hdr_t) + sig_sz),
			(int)res->size, bound, LZ4HC_CLEVEL_MAX);
		if (!cmp_size) {
			ERR("LZ4 compression failed\n");
			goto cleanup;
		}
		part->payload_size = cmp_size;
		INF("  Compressed: %zu -> %zu bytes (%.1f%%)\n",
		    res->size, cmp_size, 100.0 * cmp_size / res->size);
	} else {
		part->payload_size = res->size;
		pad_size  = pad8(res->size);
		alloc_sz  = sizeof(part_hdr_t) + sig_sz + pad_size;
		part->buf = calloc(alloc_sz, 1);
		if (!part->buf)
			goto cleanup;
		memcpy(part->buf + sizeof(part_hdr_t) + sig_sz, res->buf, res->size);
	}

	/* Zero padding bytes (calloc'd, but be explicit after LZ4 path) */
	pad_size = pad8(part->payload_size);
	memset(part->buf + sizeof(part_hdr_t) + sig_sz + part->payload_size, 0,
	       pad_size - part->payload_size);
	part->size = sizeof(part_hdr_t) + sig_sz + pad_size;
	return part;

cleanup:
	free(part->buf);
	free(part);
	return NULL;
}

int
part_sign(struct part_t *part)
{
	size_t sig_sz = cops_sig_size(part->cops);
	size_t msg_len = 0;
	uint8_t *msg = NULL;
	int ret = 0;

	if (!part->cops || sig_sz == 0)
		return 0;

	/* Signature covers part_hdr.raw || original uncompressed data */
	msg_len = sizeof(part_hdr_t) + part->orig->size;
	msg = malloc(msg_len);
	if (!msg)
		return -1;

	memcpy(msg, &part->hdr.raw, sizeof(part_hdr_t));
	memcpy(msg + sizeof(part_hdr_t), part->orig->buf, part->orig->size);

	ret = cops_sign(part->cops, msg, msg_len, part->buf + sizeof(part_hdr_t));
	free(msg);

	if (ret == 0)
		INF("  Partition sig: %02x%02x%02x%02x...\n",
		    part->buf[sizeof(part_hdr_t)],
		    part->buf[sizeof(part_hdr_t) + 1],
		    part->buf[sizeof(part_hdr_t) + 2],
		    part->buf[sizeof(part_hdr_t) + 3]);
	return ret;
}

int
part_finalize(struct part_t *part)
{
	/* Write the completed header into buf[0..sizeof(part_hdr_t)-1] */
	memcpy(part->buf, &part->hdr.raw, sizeof(part_hdr_t));

	res_release(part->orig);
	part->orig = NULL;
	return 0;
}

void
part_free(struct part_t *part)
{
	free(part->buf);
	free(part);
}
