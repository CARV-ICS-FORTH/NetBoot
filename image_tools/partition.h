/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2026 Nick Kossifidis <mick@ics.forth.gr>
 * SPDX-FileCopyrightText: 2026 ICS/FORTH
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Internal partition API — only included from container.c.
 *
 * A partition's on-disk layout is a single flat buffer:
 *   [part_hdr (8)] [signature (sig_sz)] [payload_padded]
 *
 * part_new    — compress into buf, take ownership of res
 * part_sign   — write signature into buf+8
 * part_finalize — write hdr into buf[0..7], zero pad, release orig res
 * part_free   — free buf and part
 */
#ifndef _PARTITION_H
#define _PARTITION_H

#include <stdint.h>
#include <stddef.h>
#include <img.h>
#include "res.h"
#include "crypto_ops.h"

struct part_t {
	part_hdr_t        hdr;
	struct cops_ctx  *cops;		/* borrowed ref; NULL if unsigned */
	struct res_t     *orig;		/* uncompressed original; freed at finalize */
	uint8_t          *buf;		/* [hdr(8)][sig(sig_sz)][payload_padded] */
	size_t            payload_size;	/* actual compressed (or raw) size */
	size_t            size;		/* total = 8 + sig_sz + pad8(payload_size) */
};

struct part_t *part_new(uint8_t unit_id, uint8_t type, uint16_t version,
			uint8_t flags, struct cops_ctx *cops,
			struct res_t *res);
int  part_sign(struct part_t *part);
int  part_finalize(struct part_t *part);
void part_free(struct part_t *part);

#endif /* _PARTITION_H */
