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
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <utils.h>
#include "res.h"

struct res_t *
res_from_file(const char *path, size_t max_size)
{
	struct res_t *res = NULL;
	struct stat st;
	int prot, flags;

	res = malloc(sizeof(struct res_t));
	if (!res)
		return NULL;
	memset(res, 0, sizeof(struct res_t));
	res->fd = -1;

	res->type = RES_TYPE_FILE;

	if (max_size > 0) {
		res->writable = 1;
		res->max_size = max_size;
		res->fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
		if (res->fd < 0) {
			ERR("open %s: %s\n", path, strerror(errno));
			goto cleanup;
		}
		if (ftruncate(res->fd, (off_t)max_size) < 0) {
			ERR("ftruncate %s: %s\n", path, strerror(errno));
			goto cleanup;
		}
		prot  = PROT_READ | PROT_WRITE;
		flags = MAP_SHARED;
	} else {
		res->writable = 0;
		res->fd = open(path, O_RDONLY);
		if (res->fd < 0) {
			ERR("open %s: %s\n", path, strerror(errno));
			goto cleanup;
		}
		if (fstat(res->fd, &st) < 0) {
			ERR("fstat %s: %s\n", path, strerror(errno));
			goto cleanup;
		}
		if (st.st_size == 0) {
			ERR("empty file: %s\n", path);
			goto cleanup;
		}
		res->size     = (size_t)st.st_size;
		res->max_size = res->size;
		prot  = PROT_READ;
		flags = MAP_PRIVATE;
	}

	res->buf = mmap(NULL, res->max_size, prot, flags, res->fd, 0);
	if (res->buf == MAP_FAILED) {
		ERR("mmap %s: %s\n", path, strerror(errno));
		res->buf = NULL;
		goto cleanup;
	}

	madvise(res->buf, res->max_size, MADV_SEQUENTIAL);
	if (!res->writable)
		madvise(res->buf, res->max_size, MADV_WILLNEED);

	return res;

cleanup:
	if (res->fd >= 0)
		close(res->fd);
	free(res);
	return NULL;
}

struct res_t *
res_from_mem(uint8_t *buf, size_t size)
{
	struct res_t *res = NULL;

	res = malloc(sizeof(struct res_t));
	if (!res)
		return NULL;
	memset(res, 0, sizeof(struct res_t));
	res->fd = -1;

	res->type     = RES_TYPE_MEM;
	res->buf      = buf;
	res->size     = size;
	res->max_size = size;
	res->writable = 1;
	return res;
}

void
res_release(struct res_t *res)
{
	if (!res)
		return;

	if (res->type == RES_TYPE_FILE && res->buf) {
		if (res->writable) {
			if (res->size > 0 && res->size < res->max_size) {
				int r = ftruncate(res->fd, (off_t)res->size);
				(void)r;
			}
			msync(res->buf, res->max_size, MS_SYNC);
		}
		munmap(res->buf, res->max_size);
		if (res->fd >= 0)
			close(res->fd);
	} else if (res->type == RES_TYPE_MEM) {
		free(res->buf);
	}
	free(res);
}
