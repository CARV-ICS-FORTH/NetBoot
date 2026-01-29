/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2023 Nick Kossifidis <mick@ics.forth.gr>
 * SPDX-FileCopyrightText: 2023 ICS/FORTH
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <tftp.h>
#include <net.h>	/* For ssize_t and net_* functions */
#include <utils.h>	/* For console output */
#include <string.h>	/* For memcpy()/memcmp() */
#include <stdlib.h>	/* For rand() */
#include <errno.h>	/* For errno and its values */
#include <limits.h>	/* For LONG_MAX */

/*********\
* HELPERS *
\*********/

/* Misc helpers */

static inline void
tftp_print_rx_progress(uint16_t num_blocks, size_t num_bytes)
{
	if (num_blocks)
		printf("\033[F");
	INF("[TFTP] received %li bytes\033[K\n", num_bytes);
}

static ssize_t
tftp_str_to_int(const char* value_str, size_t value_strlen)
{
	ssize_t result = 0;

	for (size_t i = 0; i < value_strlen; i++) {
		const char current_char = value_str[i];
		/* Not a digit, this is a protocol error */
		if (current_char < '0' || current_char > '9')
			return -EPROTO;

		int digit = current_char - '0';

		/* Check for overflow BEFORE it can happen:
		 * result * 10 + digit > LONG_MAX
		 * => result > (LONG_MAX - digit) / 10 */
		if (result > (LONG_MAX - digit) / 10)
			return -EOVERFLOW;

		result = (result * 10) + digit;
	}

	return result;
}

/* Protocol helpers */

/*
 * Helper functions to build TFTP command replies as uint64_t
 * Note: These assume little-endian byte order.
 */

static inline uint64_t
tftp_make_ack(uint16_t block_num, int *cmd_len)
{
	/* Format is: Opcode (2bytes) | Block number (2bytes)*/
	*cmd_len = 4;
	return (uint64_t)htons(TFTP_ACK) | ((uint64_t)htons(block_num) << 16);
}

static inline uint64_t
tftp_make_error(uint16_t error_code, int *cmd_len)
{
	/* Format is: Opcode (2bytes) | Error code (2bytes) | Error string (n bytes) | 0
	 * We won't send any string here and since the rest of uint64_t will be zero anyway
	 * we just increase command length by one byte so that we send Opcode|Error code|0. */
	*cmd_len = 5;
	return (uint64_t)htons(TFTP_ERROR) | ((uint64_t)htons(error_code) << 16);
}

/*
 * Write the Read Request (RRQ) to cmd_buffer
 * Format: opcode(2) | filename\0 | mode\0 | [option\0 | value\0]...
 */
static int
tftp_send_rrq(const char* filename, size_t filename_len, uint32_t server_ip, uint16_t client_tid)
{
	uint8_t cmd_buffer[TFTP_COMMAND_BUFFER_LEN] __attribute__ ((aligned (__SIZEOF_POINTER__)));
	memset(cmd_buffer, 0, TFTP_COMMAND_BUFFER_LEN);

	size_t cmd_len = 0;
	net_set_u16(htons(TFTP_READ_REQ), cmd_buffer);
	cmd_len += sizeof(uint16_t);

	memcpy(cmd_buffer + cmd_len, filename, filename_len);
	cmd_len += filename_len;
	cmd_buffer[cmd_len++] = (uint8_t) '\0';

	memcpy(cmd_buffer + cmd_len, TFTP_TRANSFER_MODE, sizeof(TFTP_TRANSFER_MODE));
	cmd_len += sizeof(TFTP_TRANSFER_MODE);

	/* Support for blksize option (RFC2348) - negotiate larger block sizes */
	memcpy(cmd_buffer + cmd_len, TFTP_BLOCKSIZE_OPTION, sizeof(TFTP_BLOCKSIZE_OPTION));
	cmd_len += sizeof(TFTP_BLOCKSIZE_OPTION);
	memcpy(cmd_buffer + cmd_len, TFTP_MAX_BLOCKSIZE_STR, sizeof(TFTP_MAX_BLOCKSIZE_STR));
	cmd_len += sizeof(TFTP_MAX_BLOCKSIZE_STR);

	/* Support for tsize option (RFC2349) - get file size from server */
	memcpy(cmd_buffer + cmd_len, TFTP_TRANSFER_SIZE_OPTION, sizeof(TFTP_TRANSFER_SIZE_OPTION));
	cmd_len += sizeof(TFTP_TRANSFER_SIZE_OPTION);
	cmd_buffer[cmd_len++] = (uint8_t) '0';	/* set tsize 0 to request it from the server */
	cmd_buffer[cmd_len++] = (uint8_t) '\0';

	/* Support for windowsize option (RFC7440) - ack groups of blocks to increase throughput */
	memcpy(cmd_buffer + cmd_len, TFTP_WINDOWSIZE_OPTION, sizeof(TFTP_WINDOWSIZE_OPTION));
	cmd_len += sizeof(TFTP_WINDOWSIZE_OPTION);
	memcpy(cmd_buffer + cmd_len, TFTP_DEFAULT_WINDOWSIZE_STR, sizeof(TFTP_DEFAULT_WINDOWSIZE_STR));
	cmd_len += sizeof(TFTP_DEFAULT_WINDOWSIZE_STR);

	return net_send_udp(server_ip, client_tid, TFTP_SERVER_PORT, cmd_buffer, cmd_len, 0);
}

/*
 * OACK format:
 * Format: opcode(2) | opt1\0 | value1\0 | [optN\0 | valueN\0]...
 */
static ssize_t
tftp_oack_get_optval(const uint8_t *inbuff, size_t inbuff_size,
		     const char *opt_name, size_t opt_name_len)
{
	/* Check if this OACK packet is even worth checking
	 * minimum oack: opc(2) + opt1(1) + 0 + value1(1) + 0 = 6*/
	if (inbuff_size <= 6)
		return -EBADMSG;

	const uint8_t *ptr = inbuff;
	const uint8_t *end = inbuff + inbuff_size;

	while (ptr < end) {
		/* Find the end of the current option name (optN) */
		const uint8_t *opt_end = memchr(ptr, '\0', end - ptr);
		if (!opt_end) {
			/* Missing the terminating null for the last option name */
			return -EBADMSG;
		}

		size_t current_opt_len = opt_end - ptr + 1;

		/* Check for option len/name match */
		if (current_opt_len == opt_name_len &&
		    memcmp(ptr, opt_name, opt_name_len) == 0) {

			/* Got a match, grab a pointer to the value string and
			 * make sure is within bounds before processing it. */
			const uint8_t *value_ptr = opt_end + 1;
			if (value_ptr >= end) {
				return -EBADMSG;
			}

			const uint8_t *value_end = memchr(value_ptr, '\0', end - value_ptr);
			if (!value_end )
				return -EBADMSG;

			size_t value_strlen = value_end - value_ptr;
			if (!value_strlen)
				return -EPROTO;

			/* Value is expected to be an integer string for the options we care about
			 * convert it to an integer representation. */
			ssize_t value = tftp_str_to_int((const char *)value_ptr, value_strlen);

			/* Make sure we didn't get a value of zero which is invalid */
			if (!value)
				return -EPROTO;

			return value;
		}

		/* Didn't get a match, move on to the next option, if we fail to find
		 * a null terminator it's an error since the whole buffer should end with
		 * a null terminated value. */
		const uint8_t *value_end = memchr(opt_end + 1, '\0', end - (opt_end + 1));
		if (!value_end)
			return -EBADMSG;

		/* Advance ptr past optN | 0 | valueN | 0 | */
		ptr = value_end + 1;
	}

	/* Finished search without a match */
	return -ENODATA;
}

/************************\
* Default output handler *
\************************/

int
tftp_default_output_handler(void* out_ctx, const uint8_t *in_buff, uint32_t in_buff_len)
{
	if(!out_ctx)
		return -EINVAL;
	struct default_out_ctx* out = (struct default_out_ctx*)out_ctx;

	size_t remaining_bytes = out->out_buff_len - out->bytes_out;
	if (in_buff_len > remaining_bytes)
		return -ENOSPC;

	/* If in_buff is NULL, this is just a space check, don't copy or advance. */
	if (!in_buff || !in_buff_len)
		return out->bytes_out;

	uint8_t *start_ptr = out->out_buff + out->bytes_out;
	memcpy(start_ptr, in_buff, in_buff_len);
	out->bytes_out += in_buff_len;
	return out->bytes_out;
}

/*************\
* Entry point *
\*************/

int
tftp_request_file(const char* req_filename, tftp_output_handler_fn output_cb, void* out_ctx)
{
	/* Get TFTP server info from net stack */
	uint32_t server_ip = 0;
	const char* filename = NULL;
	int ret = net_get_srvinfo(&server_ip, &filename);
	if (ret < 0) {
		ERR("[TFTP] couldn't get server info: %i\n", ret);
		return ret;
	}
	uint16_t server_tid = TFTP_SERVER_PORT;

	/* Override provided filename from DHCP with the requested one */
	if (req_filename)
		filename = req_filename;

	if (!filename) {
		ERR("[TFTP] couldn't resolve filename to requiest\n");
		return -EINVAL;
	}

	/* Validate filename before we can use/print it */
	const size_t filename_len = strnlen(filename, TFTP_MAX_FILENAME_LEN);
	if (filename_len == TFTP_MAX_FILENAME_LEN) {
		ERR("[TFTP] requested/provided filename too long: %li\n", filename_len);
		return -ENAMETOOLONG;
	}

	INF("[TFTP] server address: %s, bootfilename (%s): %s\n", inet_print_ipv4(server_ip),
	    (req_filename ? "requested" : "via DHCP"), filename);

	/* Make sure out_ctx is valid */
	if (output_cb(out_ctx, NULL, 0) == -EINVAL) {
		ERR("[TFTP] output handler returned EINVAL, invalid out_ctx!\n");
		return -EINVAL;
	}

	/* Pick a random client port above 1024, build Read Request (RRQ) packet, and send it. */
	const uint16_t client_tid = (uint16_t) ((rand() & 0x3FF) + 1024);
	ret = tftp_send_rrq(filename, filename_len, server_ip, client_tid);
	if (ret < 0) {
		ERR("[TFTP] unable to send initial request: %i\n", ret);
		return ret;
	}

	/* We are now ready to start processing input from the server, initialize client's state
	 * and proceed with the main loop. Note that from now on we'll only be sending small replies
	 * to the server (ACKs/Errors) that can easily fit within a uint64_t, so no command buffer is
	 * needed, we'll just play with cmd/cmd_len using the helpers above. */
	uint64_t cmd = 0;
	int cmd_len = 0;

	/* Default TFTP options that we may override
	 * after negotiation with the server. */
	uint16_t block_size = TFTP_DEFAULT_BLOCKSIZE;
	size_t file_size = 0;
	uint16_t window_size = 1;
	int blocks_in_window = 0;

	/* The main thing / state machine */
	int done = 0;
	int countdown = TFTP_RX_RETRIES;
	int delay_secs = 1;
	size_t num_blocks = 0;
	uint16_t last_block = 0;
	while (!done && countdown > 0) {
		ssize_t payload_size = 0;
		uint32_t remote_ip = 0;
		uint16_t remote_port = 0;
		/* Note: in case of error payload_size will hod an error value instead. */
		const uint8_t *in_buff = net_wait_for_udp(client_tid, &payload_size,
							  &remote_ip, &remote_port,
							  delay_secs * 1000);
		if (!in_buff) {
			DBG("[TFTP] failed while waiting for TFTP server: %li\n", payload_size);
			delay_secs++;
			countdown--;
			if (countdown == 1)
				done = (int) payload_size;
			/* Use server_tid for retransmit since remote_port is unset */
			remote_port = server_tid;
			goto retry;
		}

		/* Packet came from an unknown IP address, ignore it */
		if (remote_ip != server_ip)
			continue;

		/* Record server's tid, which unfortunately is the source UDP port,
		 * this is ugly for various reasons but anyway... Just to be on the
		 * safe side make sure server_tid is consistent among replies as expected. */
		if (server_tid == TFTP_SERVER_PORT) {
			/* First packet, set server_tid */
			server_tid = remote_port;
		} else if (remote_port != server_tid) {
			/* Server TID mismatch, send an error back to whoever sent
			 * us that packet. */
			WRN("[TFTP] got reply with a different server tid (%i vs %i) !\n",
			    remote_port, server_tid);
			cmd = tftp_make_error(TFTP_ERROR_UNKNOWN_TID, &cmd_len);
			goto retry;
		}

		/* Reset failure count/delay */
		countdown = TFTP_RX_RETRIES;
		delay_secs = 1;

		const uint16_t in_op = ntohs(net_get_u16(in_buff));
		switch (in_op) {
		case TFTP_OACK:
			/* Option Acknowledgment: server accepted (at least some of)
			 * our options. */

			/* Check if server provided us with an updated block size */
			const ssize_t new_block_size = tftp_oack_get_optval(in_buff + 2, payload_size - 2,
									    TFTP_BLOCKSIZE_OPTION,
									    sizeof(TFTP_BLOCKSIZE_OPTION));
			if (new_block_size < 0 && new_block_size != -ENODATA) {
				ERR("[TFTP] failure while parsing OACK: %li\n",new_block_size);
				cmd = tftp_make_error(TFTP_ERROR_OPTION_NEG_FAILED, &cmd_len);
				done = -EPROTO;
				break;
			}
			if (new_block_size > 0) {
				/* Make sure it's no larger than requested (mandated by the spec) */
				if (new_block_size > TFTP_MAX_BLOCKSIZE) {
					ERR("[TFTP] blocksize negotiation failed: %hu\n",
					    (uint16_t)new_block_size);
					cmd = tftp_make_error(TFTP_ERROR_OPTION_NEG_FAILED, &cmd_len);
					done = -EPROTO;
					break;
				}
				DBG("[TFTP] negotiated block size: %i\n", (uint16_t) new_block_size);
				block_size = (uint16_t) new_block_size;
			}

			/* Check if server provided us with the file's size */
			const ssize_t new_file_size = tftp_oack_get_optval(in_buff + 2, payload_size - 2,
									   TFTP_TRANSFER_SIZE_OPTION,
									   sizeof(TFTP_TRANSFER_SIZE_OPTION));
			if (new_file_size < 0 && new_file_size != -ENODATA) {
				ERR("[TFTP] failure while parsing OACK: %li\n", new_file_size);
				cmd = tftp_make_error(TFTP_ERROR_OPTION_NEG_FAILED, &cmd_len);
				done = -EPROTO;
				break;
			}
			if (new_file_size > 0) {
				DBG("[TFTP] got file size: %li\n", new_file_size);
				/* Check if the file would fit in output */
				if (output_cb(out_ctx, NULL, new_file_size) == -ENOSPC) {
					ERR("[TFTP] requested file won't fit in output (%li)\n",
					    new_file_size);
					/* Send an error packet back to the server to indicate "disk is full" */
					cmd = tftp_make_error(TFTP_ERROR_DISK_FULL, &cmd_len);
					done = -ENOSPC;
					break;
				}
				file_size = (size_t) new_file_size;
			}

			/* Check if server negotiated windowsize */
			const ssize_t new_window_size = tftp_oack_get_optval(in_buff + 2, payload_size - 2,
									     TFTP_WINDOWSIZE_OPTION,
									     sizeof(TFTP_WINDOWSIZE_OPTION));
			if (new_window_size < 0 && new_window_size != -ENODATA) {
				ERR("[TFTP] failure while parsing OACK: %li\n", new_window_size);
				cmd = tftp_make_error(TFTP_ERROR_OPTION_NEG_FAILED, &cmd_len);
				done = -EPROTO;
				break;
			}
			if (new_window_size > 0) {
				DBG("[TFTP] negotiated window size: %i\n", (uint16_t) new_window_size);
				window_size = (uint16_t) new_window_size;
			}

			/* Send back an ACK to continue */
			cmd = tftp_make_ack(0, &cmd_len);
			break;
		case TFTP_DATA:
			/* Data packet - contains file data
			 * Format: opcode(2) | block#(2) | data(0-blocksize bytes) */
			if (payload_size <= 4) {
				cmd = tftp_make_error(TFTP_ERROR_ILLEGAL_OP, &cmd_len);
				done = -EBADMSG;
				break;
			}

			const uint16_t cur_block = ntohs(net_get_u16(in_buff + 2));
			const uint16_t cur_block_size = payload_size - 4;

			/*
			 * Validate and handle block number
			 * So this part is messy: The TFTP protocol (RFC1350) defined block_num
			 * to be 2bytes, with its value starting from 1 and monotonically increasing.
			 * It doesn't say anything about what happens after 65k blocks. This issue
			 * hasn't been addressed officially since. The natural thing to do would be
			 * to just wrap to 0, but because there is this "value starting from 1" part
			 * some argued it should wrap to 1 and they couldn't agree. They tried to
			 * improve things with the blksize option that can go up to 65k, to support
			 * larger files, leaving it up to the network stack to handle the fragmentation
			 * of those 65k blocks via IP fragmentation, but that's seriously messed up and
			 * we won't support fragmentation here to avoid having to deal with such a
			 * large buffer and copies, and the "evil bit" etc. So with a normal blksize
			 * of 1464 we can get files up to 65k * 1464 = ~96MB. For modern systems that
			 * may not be enough, for example FSBL + firmware + kernel + initrramfs + fdt,
			 * could easily go above 100MB.
			 *
			 * Long story short: I want to strictly follow the spec but I can't, so I'll
			 * do what most other implementations do and just expect the block number to
			 * wrap to 0. This is the simplest approach that makes the most sense, and
			 * is the defacto standard.
			 */
			if (cur_block == 0) {
				if (!num_blocks || last_block != 65535) {
					ERR("[TFTP] invalid initial block number (0) !\n");
					cmd = tftp_make_error(TFTP_ERROR_ILLEGAL_OP, &cmd_len);
					done = -EPROTO;
					break;
				}
				DBG("[TFTP] block number wraparound detected\n");
			}
			last_block = cur_block;

			const uint16_t expected_block = (uint16_t) (num_blocks + 1);

			if (cur_block < expected_block) {
				/* Duplicate block (already received) - just re-ACK it
				 * This can happen if our ACK was lost */
				DBG("[TFTP] Duplicate block %u, re-ACKing\n", cur_block);
				cmd = tftp_make_ack((uint16_t)num_blocks, &cmd_len);
				break;
			} else if (cur_block == expected_block) {
				/* Expected block, call output handler and send an error if
				 * we are done with output. */
				int cb_ret = output_cb(out_ctx, in_buff + 4, cur_block_size);
				if (cb_ret < 0) {
					if (cb_ret == -ENOSPC) {
						ERR("[TFTP] received block won't fit in output (%i)\n", cur_block_size);
						cmd = tftp_make_error(TFTP_ERROR_DISK_FULL, &cmd_len);
					} else {
						ERR("[TFTP] output handler returned error %d\n", cb_ret);
						cmd = tftp_make_error(TFTP_ERROR_UNSEC, &cmd_len);
					}
					done = cb_ret;
					break;
				}
				size_t num_bytes = (num_blocks * block_size) + cur_block_size;

				/* Print progress (optional) */
				tftp_print_rx_progress(num_blocks, num_bytes);

				num_blocks++;
				blocks_in_window++;

				/* Check if this is the last block
				 * Last block is indicated by size < negotiated blocksize */
				if (cur_block_size < block_size) {
					DBG("[TFTP] Received last block\n");
					/* Check if the received tsize matches num_bytes,
					 * if not we probably got a truncated file, the server
					 * didn't implement tsize properly, or the file changed
					 * while we downloaded it. In any case it's too late to
					 * fail and this could be a false positive, just notify
					 * the user and let caller handle the mess. */
					if (file_size && num_bytes != file_size)
						WRN("[TFTP] received file mismatch: %li vs %li !\n",
						    num_bytes, file_size);
					done = 1;
				}
			} else {
				/* Gap in block sequence - protocol error
				 * This shouldn't happen in normal operation */
				ERR("[TFTP] Block sequence error: got %u, expected %li\n",
				    cur_block, num_blocks + 1);

				/* Send ERROR packet: "Illegal TFTP operation" (code 4) */
				cmd = tftp_make_error(TFTP_ERROR_ILLEGAL_OP, &cmd_len);
				done = -EPROTO;
				break;
			}

			/* Handle the case where we ACK a window (group of blocks) instead of individual
			 * blocks: If window_size is 1 (option not supported by the server) then
			 * blocks_in_window == num_blocks, so we'll always ACK, otherwise we'll ACK on
			 * every window_size blocks, or in case we are done. */
			if (blocks_in_window >= window_size || done) {
				cmd = tftp_make_ack((uint16_t)num_blocks, &cmd_len);
				blocks_in_window = 0;
			} else {
				/* Don't send an ACK yet, wait for the next window */
				cmd_len = 0;
			}
			break;
		case TFTP_ERROR:
			/* Error packet from server - transfer failed
			 * Format: opcode(2) | errcode(2) | errmsg\0
			 * (ignore errmsg, otherwise we'll need to make sure it's
			 * safe to print, errcode is enough). */
			ret = ntohs(net_get_u16(in_buff + 2));
			ERR("[TFTP] got error code from server: %i\n", ret);
			return -ECONNRESET;
		default:
			/* Unknown opcode - protocol violation */
			ERR("[TFTP] Unknown opcode: %u\n", in_op);
			/* Send ERROR packet: "Illegal TFTP operation" (code 4) */
			cmd = tftp_make_error(TFTP_ERROR_ILLEGAL_OP, &cmd_len);
			done = -EPROTO;
			break;
		}

  retry:
		if (cmd_len) {
			ret = net_send_udp(server_ip, client_tid,
					   remote_port, (uint8_t*)&cmd, cmd_len, 0);
			if (ret < 0)
				return ret;
		}
	}
	/* Everything went smoothly, return how many bytes the output handler wrote. */
	if (done == 1)
		return output_cb(out_ctx, NULL, 0);
	return done;
}