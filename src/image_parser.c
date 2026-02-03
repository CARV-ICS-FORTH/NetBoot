/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2026 Nick Kossifidis <mick@ics.forth.gr>
 * SPDX-FileCopyrightText: 2026 ICS/FORTH
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <img.h>
#include <lz4.h>	/* For lz4_init/lz4_process_chunk*/
#include <stdlib.h>	/* For malloc/free */
#include <errno.h>	/* For error codes */
#include <string.h>	/* For memcpy/memset */
#include <utils.h>	/* For console output */

static ImgpState *imgp = NULL;

/*********\
* Helpers *
\*********/

/* Get key/signatue sizes from global header's flags */

static inline size_t
imgp_get_pubkey_size(uint8_t flags)
{
	switch(flags) {
		case GBL_FLAG_ED25519:
			return 32;
		case GBL_FLAG_ECDSA384:
			return 96;
		case GBL_FLAG_NO_CRYPTO:
		default:
			return 0;
	}
}

static inline size_t
imgp_get_signature_size(uint8_t flags)
{
	switch(flags) {
		case GBL_FLAG_ED25519:
			return 64;
		case GBL_FLAG_ECDSA384:
			return 96;
		case GBL_FLAG_NO_CRYPTO:
		default:
			return 0;
	}
}

/* Get unit handler from unit id */

#ifndef HOST_TEST
extern struct uid_cb_map __start_rodata_uid_cbs[];
extern struct uid_cb_map __stop_rodata_uid_cbs[];

static unit_handler_fn
imgp_get_unit_handler(uint32_t unit_id)
{
	struct uid_cb_map *entry = __start_rodata_uid_cbs;
	struct uid_cb_map *end = __stop_rodata_uid_cbs;

	while (entry < end) {
		if (entry->uid == unit_id)
			return entry->cb;
		entry++;
	}

	return NULL;
}
#else
/* In HOST_TEST mode, make this weak so test code can override it
 * We don't have uid_cbs in host build, so we override this to
 * return the callback for id 0 directly. */
__attribute__((weak)) unit_handler_fn
imgp_get_unit_handler(uint32_t unit_id)
{
	(void)unit_id;
	return NULL;
}
#endif

/* Validate partition header */
static inline int
imgp_validate_part_hdr(uint64_t part_hdr_raw)
{
	/* TODO: Implement version/consistency validation logic */
	(void)part_hdr_raw;
	return 0;
}

/* CRC32 Implementation */

#define CRC32_POLYNOMIAL	0xEDB88320
#define CRC32_REMAINDER		0x2144DF1C
/*
 * Pre-calculate all 4bit patterns so that we don't go bit by bit
 * but instead do 4bits (a nibble) at a time.
 */
static void
imgp_init_crc32_nibbles(uint32_t *nibble_table)
{
	for (int i = 0; i < 16; i++) {
		uint32_t crc = i;
		for (int j = 0; j < 4; j++) {
			if (crc & 1)
				crc = (crc >> 1) ^ CRC32_POLYNOMIAL;
			else
				crc >>= 1;
		}
		nibble_table[i] = crc;
	}
}

/*
 * Per-nibble CRC32 calculation using the standard polynomial
 * Note: Pass current_crc by value since it'll end up in a register anyway
 */
static void
imgp_crc32_update(struct img_parser_state *imgp,
		  const void *data, size_t len)
{
	const uint8_t *p = data;
	uint32_t *nibble_table = imgp->crc32_nibbles;
	uint32_t crc = imgp->crc32_val;

	for (size_t i = 0; i < len; i++) {
		/* Process low nibble: (crc ^ (p[i] & 0x0F)) & 0x0F isolates the index */
		crc = (crc >> 4) ^ nibble_table[(crc ^ (p[i] & 0x0F)) & 0x0F];

		/* Process high nibble: (crc ^ (p[i] >> 4)) & 0x0F isolates the index */
		crc = (crc >> 4) ^ nibble_table[(crc ^ (p[i] >> 4)) & 0x0F];
	}

	imgp->crc32_val = crc;
}

ImgpState*
imgp_init_state(void)
{
	if (!imgp) {
		imgp = malloc(sizeof(struct img_parser_state));
		if (!imgp)
			return NULL;
		imgp_init_crc32_nibbles(imgp->crc32_nibbles);
	}
	imgp->global_hdr.raw = 0;
	imgp->last_sep_hdr.raw = 0;
	imgp->cur_part_hdr.raw = 0;
	imgp->crc32_val = 0xFFFFFFFF;
	imgp->total_bytes_out = 0;
	imgp->state = IMGP_STATE_GLOBAL_HDR;
	imgp->chunk = 0;
	imgp->chunks_to_skip = 0;
	imgp->remaining_chunk_bytes = 8;
	imgp->remaining_part_chunks = 0;
	imgp->out_ptr = 0;
	imgp->cur_handler = NULL;
	imgp->part_count = 0;
	return imgp;
}

void
imgp_clear_state(void)
{
	if(imgp) {
		free(imgp);
		imgp = NULL;
	}
}

int
imgp_tftp_handler(void* out_ctx, const uint8_t *in_buff, uint32_t in_buff_len)
{
	int ret;
	size_t offset = 0;

	/* Validate context */
	if (!out_ctx)
		return -EINVAL;

	ImgpState* imgp = (ImgpState*)out_ctx;

	/* Check if caller indicates we reached the end of input/transmission. */
	if (!in_buff || !in_buff_len) {
		DBG("[IMGP] end of input reached, state: %i\n", imgp->state);
		return imgp->total_bytes_out;
	}

	/* Process input in 8-byte chunks */
	while (imgp->state != IMGP_STATE_DONE) {
		/* Fill in current 8byte chunk */
		while(imgp->remaining_chunk_bytes && (offset < in_buff_len))
			imgp->chunk_bytes[8 - imgp->remaining_chunk_bytes--] = in_buff[offset++];
		/* Chunk is split between packets, continue filling it in
		 * the next packet. */
		if (imgp->remaining_chunk_bytes)
			break;

		/* Got a chunk add it to the checksum and
		 * prepare for the next one. */
		imgp_crc32_update(imgp, (uint8_t *)&imgp->chunk, 8);
		imgp->remaining_chunk_bytes = 8;

		/* Process based on state */
		switch (imgp->state) {
		case IMGP_STATE_GLOBAL_HDR:
			imgp->global_hdr.raw = imgp->chunk;

			/* Validate magic number */
			if (imgp->global_hdr.magic != IMG_MAGIC_NB) {
				ERR("[IMGP] Bad magic: expected 0x%04X, got 0x%04X\n",
				    IMG_MAGIC_NB, imgp->global_hdr.magic);
				return -EBADMSG;
			}

			/* Validate header version */
			if (imgp->global_hdr.hdr_version != 0)
				return -EPROTO;

			/* Do we have a public key following or we just skip to the sep_hdr ? */
			const size_t pubkey_size = imgp_get_pubkey_size(imgp->global_hdr.flags);
			if (pubkey_size > 0) {
				/* Note: public key sizes are always a multiple of 8bytes */
				imgp->chunks_to_skip = pubkey_size / 8;
				imgp->state = IMGP_STATE_PUBKEY;
			} else
				imgp->state = IMGP_STATE_SEP_HDR;
			break;
		case IMGP_STATE_PUBKEY:
			/* TODO: Store public key */
			imgp->chunks_to_skip--;
			/* We expect the signature of global_hdr + pubkey when done */
			if (imgp->chunks_to_skip == 0) {
				const size_t sig_size = imgp_get_signature_size(imgp->global_hdr.flags);
				if (sig_size > 0) {
					/* Note: signature sizes are always a multiple of 8bytes */
					imgp->chunks_to_skip = sig_size / 8;
					imgp->state = IMGP_STATE_SIG_GLOBAL;
					break;
				} else
					return -EPROTO;
			}
			break;
		case IMGP_STATE_SIG_GLOBAL:
		case IMGP_STATE_SIG_PART:
			/* TODO: Check signature using pubkey */
			imgp->chunks_to_skip--;
			/* When done with signature we expect a sep_hdr */
			if (imgp->chunks_to_skip == 0)	
				imgp->state = IMGP_STATE_SEP_HDR;
			break;
		case IMGP_STATE_SEP_HDR:
			imgp->last_sep_hdr.raw = imgp->chunk;

			/* Validate CRC before moving on */
			if (~imgp->crc32_val != CRC32_REMAINDER)
				return -EBADMSG;

			/* Check if done */
			if (imgp->last_sep_hdr.next_part_size == 0) {
				/* Verify partition count */
				if (imgp->part_count != (uint8_t)imgp->global_hdr.part_count)
					return -EPROTO;
				imgp->state = IMGP_STATE_DONE;
				break;
			}

			/* Setup remaining chunks for partition, round up to the
			 * next chunk to also include padding. */
			imgp->remaining_part_chunks = (imgp->last_sep_hdr.next_part_size + 7) / 8;
			imgp->state = IMGP_STATE_PART_HDR;
			break;
		case IMGP_STATE_PART_HDR:
			/* Save previous image's size in case unit handler requires it
			 * to determine the base addres for the new partiion. */
			size_t prev_img_size = imgp->cur_part_hdr.image_size;

			imgp->cur_part_hdr.raw = imgp->chunk;
			imgp->remaining_part_chunks--;
			imgp->part_count++;

			/* Validate partition header */
			ret = imgp_validate_part_hdr(imgp->cur_part_hdr.raw);
			if (ret < 0)
				return ret;

			/* Get unit handler */
			imgp->cur_handler = imgp_get_unit_handler(imgp->cur_part_hdr.unit_id);
			if (!imgp->cur_handler) {
				ERR("[IMGP] No handler for unit_id=%u\n", imgp->cur_part_hdr.unit_id);
				return -EINVAL;
			}

			/* Get output region */
			size_t max_size = prev_img_size;
			uintptr_t type_and_base = imgp->cur_part_hdr.type;
			ret = imgp->cur_handler(UNIT_CMD_GET_REGION, &type_and_base, &max_size);
			if (ret < 0)
				return ret;
			imgp->out_ptr = type_and_base;

			/* Check if image will fit in region */
			if (max_size < imgp->cur_part_hdr.image_size)
				return -ENOSPC;

			/* Setup for payload */
			if (imgp->cur_part_hdr.flags == PART_FLAG_LZ4)
				lz4_init(&imgp->lz4_ctx, (uint8_t*)imgp->out_ptr, imgp->cur_part_hdr.image_size);

			/* TODO: Start SHA with imgp->cur_part_hdr, for the signature check */

			imgp->state = IMGP_STATE_PAYLOAD;
			break;

		case IMGP_STATE_PAYLOAD:
			/* TODO: Add payload to SHA for signature check */
			if (imgp->cur_part_hdr.flags == PART_FLAG_LZ4) {
				/* Compressed: Feed chunks to LZ4 decompressor which manages
				 * output pointer internally and stops at max_output, ignoring
				 * any padding. */
				ssize_t decomp_bytes = lz4_process_chunk(&imgp->lz4_ctx, (uint8_t *)&imgp->chunk, 8);
				if (decomp_bytes < 0)
					return decomp_bytes;
				imgp->total_bytes_out += decomp_bytes;
				imgp->remaining_part_chunks--;

				/* Drain remaining chunks in packet for efficiency */
				const size_t remaining_input_chunks = (in_buff_len - offset) / 8;
				const size_t input_chunks = (remaining_input_chunks < imgp->remaining_part_chunks) ?
							     remaining_input_chunks : imgp->remaining_part_chunks;
				if (input_chunks > 0) {
					const uint8_t *in_start = in_buff + offset;
					const size_t in_bytes = input_chunks * 8;
					decomp_bytes = lz4_process_chunk(&imgp->lz4_ctx, in_start, in_bytes);
					if (decomp_bytes < 0)
						return decomp_bytes;
					imgp->total_bytes_out += decomp_bytes;
					imgp_crc32_update(imgp, in_start, in_bytes);
					offset += in_bytes;
					imgp->remaining_part_chunks -= input_chunks;
				}

				/* Check if partition complete */
				if (imgp->remaining_part_chunks == 0) {
					/* Verify we got the expected uncompressed size */
					if (imgp->lz4_ctx.total_written != imgp->cur_part_hdr.image_size)
						return -EBADMSG;

					size_t sig_size = imgp_get_signature_size(imgp->global_hdr.flags);
					if (sig_size > 0) {
						imgp->chunks_to_skip = sig_size / 8;
						imgp->state = IMGP_STATE_SIG_PART;
					} else
						imgp->state = IMGP_STATE_SEP_HDR;
				}
			} else {
				/* Uncompressed: Copy 8-byte chunks directly, including padding.
				 * We already verified the full partition fits in the output region. */
				memcpy((void *)imgp->out_ptr, &imgp->chunk, 8);
				imgp->out_ptr += 8;
				imgp->total_bytes_out += 8;
				imgp->remaining_part_chunks--;

				/* Batch copy remaining chunks in packet for efficiency */
				const size_t remaining_input_chunks = (in_buff_len - offset) / 8;
				const size_t input_chunks = (remaining_input_chunks < imgp->remaining_part_chunks) ?
							     remaining_input_chunks : imgp->remaining_part_chunks;
				if (input_chunks > 0) {
					const uint8_t *in_start = in_buff + offset;
					const size_t in_bytes = input_chunks * 8;
					memcpy((void *)imgp->out_ptr, in_start, in_bytes);
					imgp->out_ptr += in_bytes;
					imgp->total_bytes_out += in_bytes;
					imgp_crc32_update(imgp, in_start, in_bytes);
					offset += in_bytes;
					imgp->remaining_part_chunks -= input_chunks;
				}

				/* Check if partition complete */
				if (imgp->remaining_part_chunks == 0) {
					size_t sig_size = imgp_get_signature_size(imgp->global_hdr.flags);
					if (sig_size > 0) {
						imgp->chunks_to_skip = sig_size / 8;
						imgp->state = IMGP_STATE_SIG_PART;
					} else
						imgp->state = IMGP_STATE_SEP_HDR;
				}
			}
			break;
		case IMGP_STATE_DONE:
			break;
		}
	}

	return imgp->total_bytes_out;
}