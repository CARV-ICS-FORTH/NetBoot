/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2026 Nick Kossifidis <mick@ics.forth.gr>
 * SPDX-FileCopyrightText: 2026 ICS/FORTH
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _IMG_H
#define _IMG_H
#include <stdint.h>	/* For typed ints */
#include <stddef.h>	/* For size_t */
#include <lz4.h>	/* For lz4_ctx */

/**************\
* Image format *
\**************/

/*
 * Overview:
 *
 * What we get is an image container, that may include different image types
 * (e.g. FSBL, Firmware, DTB), for different unit ids (e.g. this device -that
 * always maps to unit id 0-, an FPGA, another microcontroller in the system).
 * Each image in the container is associated with a release id, we may have a
 * range of release ids inside the container, but the idea is that they follow
 * a versioning scheme based on date/time so that they are always increasing
 * in a similar manner. This allows the platform to apply flexible anti-rollback
 * policies, either per unit/type pair, or in general (e.g. anything older than
 * x).
 *
 * The container may be re-used by the next boot stage, and e.g. have ZSBL only
 * parse parts of it and handle a specific set of unit/type pairs. That means
 * we need to have enough info to be able to skip a partition if needed. Also
 * for unit id 0, type 0 means an executable that will run before proceeding to
 * the next image, and will only be processed by ZSBL. This may be used for running
 * unit pre-initialization code (e.g. to bring up the DRAM controller before
 * trying to put the next image in DRAM), small update commands (e.g. to advance
 * the anti-rollback counter to the version of the including partition -so next time
 * the container is parsed the command will be skipped-), quick tests etc.
 *
 * Regarding integrity/authenticity, since we'll process images/partitions as they
 * arrive, we can't wait to reach the end of the container to e.g. get a signature
 * for the whole thing, also since signature checking is expensive, if there is any
 * error in the received image, we should fail fast, so we need an extra/quick test
 * on top, that may also be used in case we don't have crypto available.
 *
 * So here we go:
 *
 * - The global header:
 *   [Magic value (16bit)][Header version (4bit)][Partition count (4bit)][Flags (8bit)]
 *   [Total size (32bit)]
 *
 * - The separator header:
 *   [Next Partition size (32bit)]
 *   [CRC32 so far (32bit)]
 *
 * - The partition header:
 *   [Release ID (16bit)][Type (4bit)][Unit ID (4bit)][Flags (8bit)]
 *   [Image size (32bit)]
 *
 * Each header can fit in a uint64_t and we can easily carry it around while processing
 * partitions, without wasting too much space. If signatures are used (determined by the
 * global header's flags), the public key comes right after the global header, and each
 * signature before the separator header. The partition size doesn't include signature's
 * size, but total size on global header includes everything. Each partition is padded
 * to 8bytes so that headers and signatures are always 8byte/header-size aligned, the
 * padding is also not included in partition's size.
 * 
 * The overall image container looks like this:
 *
 * <Sep. header 0 (omitted from image)>: [8 + pubkey_size (optional)][FFFFFFFF]
 * <Global header>
 * <Public key (optional)>
 * <Signature (optional)>
 *
 * <Sep. header 1>
 *
 * <Part. 1 header>
 * <Part. 1 payload>
 * <Part. 1 signature (optional)>
 *
 * <Sep. header 2>
 * .
 * .
 * .
 * <Sep. header N>: [0][CRC32 of the whole container]
 *
 */

#define IMG_MAGIC_NB	0x424E	/* "NB" for NetBoot */

typedef union {
	struct {
		uint16_t magic;
		uint8_t  hdr_version : 4;
		uint8_t  part_count  : 4;
		uint8_t  flags;
		uint32_t total_size;
	} __attribute__((packed));
	uint64_t raw;
} global_hdr_t;

enum global_flags {
	GBL_FLAG_NO_CRYPTO = 0,
	GBL_FLAG_ED25519 = 1,
	GBL_FLAG_ECDSA384 = 2,
	GBL_FLAG_MAX = 255
};

typedef union {
	struct {
		uint16_t version;
		uint8_t  type    : 4;
		uint8_t  unit_id : 4;
		uint8_t  flags;
		uint32_t image_size;
	} __attribute__((packed));
	uint64_t raw;
} part_hdr_t;

enum image_types {
	IMG_TYPE_BOOT_STEP = 0,	/* Image to execute before proceeding (only valid for self) */
	IMG_TYPE_FBSL = 1,	/* Image to execute when done */
	IMG_TYPE_DTB = 2,	/* Device Tree Blob (optional, comes after FSBL) */
	IMG_TYPE_MAX = 15
};

enum unit_id {
	UNIT_ID_SELF = 0,
	UNIT_ID_MAX = 15
};

enum part_flags {
	PART_FLAG_UNCOMPRESSED = 0,
	PART_FLAG_LZ4 = 1,
	PART_FLAG_MAX = 255
};

typedef union {
	struct {
		uint32_t next_part_size;
		uint32_t rolling_crc;
	} __attribute__((packed));
	uint64_t raw;
} sep_hdr_t;

/*
 * Unit declarations:
 * For each supported unit id, we have a mapping to a handler
 * function, acting as the unit's driver.
 */
typedef enum {
	UNIT_CMD_GET_REGION = 0,	/* Get region base/size to write to,
					 * use img_base to pass IMG_TYPE and in case of
					 * IMG_TYPE_DTB, pass FSBL size to max_img_size. */
	/* Only valid for unit id 0 */
	UNIT_CMD_EXEC_IMAGE = 1,	/* Execute image and return for more */
	UNIT_CMD_FSBL_JUMP = 2,		/* Jump to next boot stage */
	/* Only valid for unit id !0 */
	UNIT_CMD_RESET_BLOCK = 3,	/* Reset and wait for unit to become ready */
	UNIT_CMD_RESET_NONBLOCK = 4,	/* Reset and move on */
} unit_cmd_t;

typedef int (*unit_handler_fn)(unit_cmd_t cmd, uintptr_t *img_base, size_t *max_img_size);

struct uid_cb_map {
	uint32_t uid;
	uint32_t reserved;
	unit_handler_fn cb;
} __attribute__((packed));

#define UID_CBS_SECTION __attribute__((section("__uid_cbs"), used, aligned(16)))

#define REGISTER_UNIT_CB(unit_id, unit_handler) \
	static const struct uid_cb_map __unit_cb_##unit_id UID_CBS_SECTION = { \
		.uid = unit_id, \
		.cb = unit_handler \
	}

/* In units/self.c this should always exist, also called from main when done. */
int unit_handler_self(unit_cmd_t cmd, uintptr_t *img_base, size_t *max_img_size);

/**************\
* Image parser *
\**************/

enum imgp_state {
	IMGP_STATE_GLOBAL_HDR = 0,
	IMGP_STATE_PUBKEY,
	IMGP_STATE_SIG_GLOBAL,
	IMGP_STATE_SEP_HDR,
	IMGP_STATE_PART_HDR,
	IMGP_STATE_PAYLOAD,
	IMGP_STATE_SIG_PART,
	IMGP_STATE_DONE
};

struct img_parser_state {
	global_hdr_t global_hdr;
	sep_hdr_t last_sep_hdr;
	part_hdr_t cur_part_hdr;
	uint32_t crc32_nibbles[16];
	uint32_t crc32_val;
	size_t total_bytes_out;
	struct lz4_ctx lz4_ctx;
	enum imgp_state state;
	union {
		uint8_t chunk_bytes[8];
		uint64_t chunk;
	};
	size_t remaining_chunk_bytes;
	size_t remaining_part_chunks;
	size_t chunks_to_skip;
	uintptr_t out_ptr;
	unit_handler_fn cur_handler;
	uint8_t part_count;
};

typedef struct img_parser_state ImgpState;

ImgpState* imgp_init_state(void);
void imgp_clear_state(void);
int imgp_tftp_handler(void* out_ctx, const uint8_t *in_buff, uint32_t in_buff_len);
#endif /* _IMG_H */