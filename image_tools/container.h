/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2026 Nick Kossifidis <mick@ics.forth.gr>
 * SPDX-FileCopyrightText: 2026 ICS/FORTH
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _CONTAINER_H
#define _CONTAINER_H

#include <stdint.h>
#include <stddef.h>
#include "res.h"
#include "crypto_ops.h"

struct cont_ctx {
	struct res_t    *res;
	uint8_t         *buf;
	size_t           size;		/* current write position */
	size_t           max_size;
	struct cops_ctx *cops;		/* borrowed ref; NULL if unsigned */
	uint16_t         version;
	uint8_t          part_count;
	size_t           hdr_end;	/* offset where sep/part data begins */
	int              read_only;
	int              finalized;
};

/*
 * Open an existing container for reading (max_size == 0) or create a new
 * writable container pre-extended to max_size bytes (max_size > 0).
 */
struct cont_ctx *container_open(const char *file_path, size_t max_size);

/*
 * Initialise a writable container.  Reserves space for the global header
 * section (global_hdr + pubkey + global_sig); that section is filled at
 * container_finalize().
 */
int container_new(struct cont_ctx *cont, struct cops_ctx *cops,
		  uint16_t version);

int container_set_cops(struct cont_ctx *cont, struct cops_ctx *cops);

/*
 * Add a partition.  Takes ownership of res; caller must not use res after
 * this returns.  Internally calls part_new → part_sign → part_finalize.
 */
int container_add_partition(struct cont_ctx *cont, struct res_t *res,
			    uint8_t unit_id, uint8_t type, uint8_t flags);

/*
 * Finalise: write global header section, patch rolling_crc fields, update
 * res->size.  Must be called before container_close on write containers.
 */
int container_finalize(struct cont_ctx *cont);

/*
 * Walk the container buffer, verify CRC at every separator, decompress
 * payloads, and cross-check signatures with the built-in and OpenSSL
 * implementations.  do_dump != 0 writes decompressed parts to
 * /tmp/partN.bin.
 */
int container_verify(struct cont_ctx *cont, int do_dump);

void container_close(struct cont_ctx *cont);

#endif /* _CONTAINER_H */
