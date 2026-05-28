/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2026 Nick Kossifidis <mick@ics.forth.gr>
 * SPDX-FileCopyrightText: 2026 ICS/FORTH
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _RES_H
#define _RES_H

#include <stdint.h>
#include <stddef.h>

enum res_type {
	RES_TYPE_FILE,
	RES_TYPE_MEM,
};

struct res_t {
	uint8_t      *buf;
	size_t        size;		/* actual data size; caller updates before release */
	size_t        max_size;		/* mmap/alloc extent */
	int           fd;
	enum res_type type;
	int           writable;
};

/*
 * Open an existing file read-only (max_size == 0) or create a new writable
 * file pre-extended to max_size bytes (max_size > 0).
 */
struct res_t *res_from_file(const char *path, size_t max_size);

/* Wrap a caller-owned malloc'd buffer; res_release frees it. */
struct res_t *res_from_mem(uint8_t *buf, size_t size);

/*
 * Release a resource.  For writable file resources, ftruncates to res->size
 * before msync + munmap + close.
 */
void res_release(struct res_t *res);

#endif /* _RES_H */
