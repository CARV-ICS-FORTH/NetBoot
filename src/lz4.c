/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2026 Nick Kossifidis <mick@ics.forth.gr>
 * SPDX-FileCopyrightText: 2026 ICS/FORTH
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <lz4.h>
#include <string.h>	/* For memcpy */
#include <errno.h>	/* For error codes */

ssize_t
lz4_process_chunk(struct lz4_ctx *ctx, const uint8_t *src, size_t len)
{
	const uint8_t *src_end = src + len;
	size_t total_written_on_entry = ctx->total_written;

	while (src < src_end) {

		/* Exit as soon as we reach decompressed size, don't
		 * attempt to process any extra input bytes after that
		 * since they'll probably be padding. */
		if (ctx->total_written >= ctx->max_output)
			goto done;

		switch (ctx->phase) {
		case LZ4_PHASE_CMD: {
			uint8_t token = *src++;
			ctx->match_len_low = (token & 0x0F);
			ctx->count = (token >> 4);

			if (ctx->count == 15)
				ctx->phase = LZ4_PHASE_LIT_LEN;
			else
				ctx->phase = LZ4_PHASE_LITS;
			break;
		}
		case LZ4_PHASE_LIT_LEN: {
			uint8_t s = *src++;
			ctx->count += s;
			/* Length extension ends when byte < 255 */
			if (s != 255)
				ctx->phase = LZ4_PHASE_LITS;
			break;
		}
		case LZ4_PHASE_LITS: {
			if (ctx->count > 0) {
				uint32_t avail = (uint32_t)(src_end - src);
				uint32_t to_copy = (ctx->count < avail) ? 
						   ctx->count : avail;

				/* Prevent DRAM buffer overflow */
				if (ctx->total_written + to_copy > ctx->max_output)
					return -ENOBUFS;

				/* Literal copy: dest and src never overlap */
				memcpy(ctx->dest_ptr, src, to_copy);

				ctx->dest_ptr += to_copy;
				src += to_copy;

				ctx->total_written += to_copy;
				ctx->count -= to_copy;
			}
			/* Once all literals are copied, move to the match offset */
			if (ctx->count == 0)
				ctx->phase = LZ4_PHASE_OFF_LO;
			break;
		}
		case LZ4_PHASE_OFF_LO: {
			ctx->off_lo = *src++;
			ctx->phase = LZ4_PHASE_OFF_HI;
			break;
		}
		case LZ4_PHASE_OFF_HI: {
			uint16_t dist = ((uint16_t)(*src++) << 8) | ctx->off_lo;

			/* Security: Check for invalid offset or OOB read */
			if (dist == 0 || dist > ctx->total_written)
				return -EOVERFLOW;

			ctx->match_dist = dist;
			ctx->count = (uint32_t)ctx->match_len_low;

			/* If match_len is 15, length is extended by next bytes */
			if (ctx->count == 15) {
				ctx->phase = LZ4_PHASE_MAT_LEN;
			} else {
				/* LZ4 min match is 4 bytes */
				ctx->count += 4;
				ctx->phase = LZ4_PHASE_EXEC_MATCH;
			}
			break;
		}
		case LZ4_PHASE_MAT_LEN: {
			uint8_t s = *src++;
			ctx->count += s;
			if (s != 255) {
				ctx->count += 4;
				ctx->phase = LZ4_PHASE_EXEC_MATCH;
			}
			break;
		}
		case LZ4_PHASE_EXEC_MATCH: {
				/* match_ptr points to previous data in DRAM */
				uint8_t *m_src = ctx->dest_ptr - ctx->match_dist;

				while (ctx->count > 0) {
					if (ctx->total_written >= ctx->max_output)
						goto done;

					/* * Byte-by-byte copy is MANDATORY for:
					 * 1. RLE propagation (dist < length), source
					 *    is changing while writing destination.
					 * 2. Alignment safety on RISC-V
					 */
					*ctx->dest_ptr++ = *m_src++;
					ctx->total_written++;
					ctx->count--;
				}
				ctx->phase = LZ4_PHASE_CMD;
				break;
		}
		}
	}
 done:
	return ctx->total_written - total_written_on_entry;
}