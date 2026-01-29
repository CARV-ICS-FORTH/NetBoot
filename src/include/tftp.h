/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2023 Nick Kossifidis <mick@ics.forth.gr>
 * SPDX-FileCopyrightText: 2023 ICS/FORTH
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _TFTP_H
#define _TFTP_H
#include <stdint.h>	/* For typed ints */
#include <stddef.h>	/* For size_t */

/* Server's TID, RFC1350 section 4 */
#define TFTP_SERVER_PORT 69

/* TFTP header opcodes, RFC1350 section 5
 * and RFC2347 for OACK */
enum {
	TFTP_READ_REQ = 1,
	TFTP_WRITE_REQ = 2,
	TFTP_DATA = 3,
	TFTP_ACK = 4,
	TFTP_ERROR = 5,
	TFTP_OACK = 6
};

/* TFTP error codes, RFC1350, appendix */
enum {
	TFTP_ERROR_UNSEC = 0,
	TFTP_ERROR_NOT_FOUND = 1,
	TFTP_ERROR_ACCESS_VIOLATION = 2,
	TFTP_ERROR_DISK_FULL = 3,
	TFTP_ERROR_ILLEGAL_OP = 4,
	TFTP_ERROR_UNKNOWN_TID = 5,
	TFTP_ERROR_FILE_EXISTS = 6,
	TFTP_ERROR_UNKNOWN_USER = 7,
	TFTP_ERROR_OPTION_NEG_FAILED = 8,
};

/* Use those to define a fixed-length command buffer */
#define TFTP_MAX_FILENAME_LEN 64
#define TFTP_TRANSFER_MODE "octet" //6

/* Blocksize negotiation is defined in RFC2348 */
#define TFTP_BLOCKSIZE_OPTION "blksize" //8
/* Packet format for data packets is
 * ip_hdr(20) + udp_hdr(8) + op(2) + block_num(2)
 * so the maximum blocksize for a 1500MTU is:
 * 1500 - 20 - 8 - 2 -2 = 1500 - 32 = 1468
 * Because we want input to be 8byte aligned if possible (like
 * the default blocksize of 512), go for 1464 instead, and since
 * for some stupid reason TFTP wants this represented as a string
 * in the packet we need two macros...
 */
#define TFTP_MAX_BLOCKSIZE 1464
#define TFTP_MAX_BLOCKSIZE_STR "1464"

/* Transfer size option is defined in RFC2349 */
#define TFTP_TRANSFER_SIZE_OPTION "tsize"

/* Windowsize option is defined in RFC7440
 * Allows sending multiple blocks before requiring an ACK from the client */
#define TFTP_WINDOWSIZE_OPTION "windowsize"
#define TFTP_DEFAULT_WINDOWSIZE_STR "16"  // Conservative default

/* Packet format for RRQ/WRQ with blocksize and tsize options is
 * op(2) | filename_string|\0| mode_string|\0| "blksize"|\0| blksize_str|\0| "tsize"|\0| '0' |\0
 * all strings are null terminated. */
 #define TFTP_COMMAND_BUFFER_LEN (2 + TFTP_MAX_FILENAME_LEN +	 \
				 sizeof(TFTP_TRANSFER_MODE) +	 \
				 sizeof(TFTP_BLOCKSIZE_OPTION) + \
				 sizeof(TFTP_MAX_BLOCKSIZE_STR) +\
				 sizeof(TFTP_TRANSFER_SIZE_OPTION) + 2+ \
				 sizeof(TFTP_WINDOWSIZE_OPTION) + \
				 sizeof(TFTP_DEFAULT_WINDOWSIZE_STR))
/* Default block size in case blksize option is not implemented at
 * at the server side */
#define TFTP_DEFAULT_BLOCKSIZE	512

/* How many consecutive failed RX retries until we terminate.
 * Note that on each failure we'll retransmit our last command, and also increase the delay
 * from 1sec up to 4sec. In total with 5 retries we'll wait 10s, which is more than enough
 * to declare the server is out. */
#define TFTP_RX_RETRIES 4

/*
 * This will be called for every input block with in_buff pointing to the start of the block
 * and in_buff_len holding the block's size. If in_buff is NULL this can be used for checking
 * if in_buff_len will fit in output, if in_buff_len is less than the previous one (block size)
 * this indicates we reached the end of transmission.
 *
 * Returns:
 * - Bytes written to output, if everything went ok, signals TFTP client to move forward
 * - -ENOSPC if in_buff_len won't fit in output, in which case TFTP client will send back TFTP_ERROR_DISK_FULL
 * - -EINVAL if out_ctx is NULL or there is something wrong with it on init
 * - -EPROTO if handler got unexpected/invalid input
 * - -EBADMSG if handler detected corrupted input
 */
typedef int (*tftp_output_handler_fn)(void* out_ctx, const uint8_t *in_buff, uint32_t in_buff_len);

/*
 * This is the default output handler / out_ctx, it just copies incomming blocks
 * to output buffer.
 */
struct default_out_ctx {
	uint8_t *out_buff;
	size_t out_buff_len;
	size_t bytes_out;
};

int tftp_default_output_handler(void* out_ctx, const uint8_t *in_buff, uint32_t in_buff_len);

int tftp_request_file(const char* filename, tftp_output_handler_fn output_cb, void* out_ctx);

#endif /* _TFTP_H */
