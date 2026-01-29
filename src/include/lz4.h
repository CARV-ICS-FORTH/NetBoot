/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2026 Nick Kossifidis <mick@ics.forth.gr>
 * SPDX-FileCopyrightText: 2026 ICS/FORTH
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _LZ4_H
#define _LZ4_H
#include <stdint.h>	/* For typed ints */
#include <net.h>	/* For ssize_t */
#include <string.h>	/* For memset */

typedef enum {
	LZ4_PHASE_CMD  = 0,	/* Waiting for 1-byte Token (L-bits/M-bits) */
	LZ4_PHASE_LIT_LEN,	/* Accumulating extended literal length */
	LZ4_PHASE_LITS,		/* Copying literal bytes from packet to DRAM */
	LZ4_PHASE_OFF_LO,	/* Waiting for low byte of 16-bit offset */
	LZ4_PHASE_OFF_HI,	/* Waiting for high byte of 16-bit offset */
	LZ4_PHASE_MAT_LEN,	/* Accumulating extended match length */
	LZ4_PHASE_EXEC_MATCH	/* Copying match from DRAM history (RLE) */
} lz4_phase_t;

struct lz4_ctx {
	lz4_phase_t phase;
	uint8_t *dest_ptr;	/* Current write cursor in DRAM */
	uint32_t count;		/* Count for literals or matches */
	uint16_t match_dist;	/* The 'look-back' distance */
	uint8_t  match_len_low;	/* Stores 4-bit match length from token */
	uint8_t  off_lo;	/* Temporary storage for split offset bytes */
	uint32_t total_written;	/* Progress tracker */
	uint32_t max_output;	/* Expected size from partition header */
};

static inline void
lz4_init(struct lz4_ctx *lz4_ctx, uint8_t *dest_ptr, size_t max_output)
{
	memset(lz4_ctx, 0, sizeof(struct lz4_ctx));
	lz4_ctx->dest_ptr = dest_ptr;
	lz4_ctx->max_output = max_output;
}

ssize_t lz4_process_chunk(struct lz4_ctx *ctx, const uint8_t *src, size_t len);
#endif /* _LZ4_H */