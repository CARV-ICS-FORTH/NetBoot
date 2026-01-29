/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2023 Nick Kossifidis <mick@ics.forth.gr>
 * SPDX-FileCopyrightText: 2023 ICS/FORTH
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <net.h>
#include <dhcp.h>
#include <utils.h>	/* For console output */
#include <stddef.h>	/* For offsetof() */
#include <string.h>	/* For memcpy() */
#include <errno.h>	/* For errno and its values */

/*
 * DHCP options handling error codes
 * These are returned as negative values by various functions here,
 * they are above 400 so that they don't overlap with standard errno codes,
 * or dhcp_validate_err codes from dhcp.c.
 */
enum dhcp_options_err {
	DHCP_ERR_OPTION_INVALID_LEN = 400,	/* Found option with invalid length */
	DHCP_ERR_OVERLOAD_INVALID_LEN,		/* Options overload option has invalid length */
	DHCP_ERR_OVERLOAD_DUPLICATE,		/* Options overload option present twice */
	DHCP_ERR_OVERLOAD_INVALID_TYPE,		/* Invalid options overload type value */
	DHCP_ERR_OPTION_SEARCH_FAILED,		/* Failed while searching for option */
	DHCP_ERR_STATIC_ROUTES_INVALID_SIZE,	/* Static routes list has invalid size */
	DHCP_ERR_OPTION_DUPLICATE,		/* Option added more than once */
	DHCP_ERR_OPTION_NO_SPACE,		/* Not enough space left for option */
};

/*********\
* Helpers *
\*********/

static inline uint8_t
hex_to_ascii(uint8_t hex)
{
	if (hex <= 9)
		return hex + 0x30;
	else
		return hex - 9 + 0x60;
}

/*********************************\
* Get options from server replies *
\*********************************/

int
dhcp_grab_option_offset(const uint8_t *msg_buff, uint8_t option_id)
{
	int options_offset = offsetof(DhcpMsg, options);
	const uint8_t *options_buff = msg_buff + options_offset;
	uint16_t options_field_size = DHCP_MIN_OPTIONS_LEN;
	uint8_t skipped_options = 0;
	uint8_t overload_type = 0;
	uint8_t option_len = 0;
	int i = 0;

	/* 
	 * Skip the magic cookie and start looking in the options field
	 *
	 * Note: All option ids are 1 octet (there were proposals for allowing 16bit
	 * options, but were rejected, check out RFC3942 section 3.1 for more infos),
	 * and except 0 (pad) and 0xFF (end) all of them have variable size (RFC2132
	 * section 2) which is encoded in the octet after their id. Also by default
	 * options are only present once unless noted otherwise. We won't do this
	 * check here (only for the options overload option), it will be done
	 * by our caller only for the options that we know about, doing it for
	 * all options (for a more strict validation) is too expensive. Here we'll
	 * just grab an option the first time we see it.
	 */
	for (i = 4; i < options_field_size; i++) {
		/* We are two octets before the end of our current options field,
		 * and haven't found the END marker yet. The only valid scenarios
		 * here is that we have END|PAD or PAD|END, any options other than
		 * END/PAD need two bytes (one for their id and one for their length),
		 * so it's not possible to get the END marker in that case.
		 *
		 * Note: according to RFC2131 section 4.1 the END marker is
		 * present in every possible options field when overloading
		 * options is enabled, so this check is always needed. */
		if (i == options_field_size - 2) {
			uint16_t end_check = net_get_u16(&options_buff[i]);
			if ((end_check != 0xFF00) && (end_check != 0x00FF))
				break;
			else
				return 0;
		}

		/* Found a PAD option, skip it / ignore it */
		if (options_buff[i] == 0)
			continue;

		/* Found requested option */
		if (options_buff[i] == option_id) {
			option_len = options_buff[i + 1];
			/* Make sure option fits the buffer and there is
			 * at least an octet left for the END marker */
			if ((i + option_len) > (options_field_size - 2)) {
				DBG("[DHCP] found option with invalid length: %i !\n", options_buff[i]);
				return -DHCP_ERR_OPTION_INVALID_LEN;
			}
			return options_offset + i;
		}

		/* Found the options overload option, set overload_type */
		if (options_buff[i] == DHCP_OPTION_OVERLOAD_OPTION) {
			if (options_buff[i + 1] != DHCP_OPTION_OVERLOAD_LEN) {
				DBG("[DHCP] got options overload option with invalid length !\n");
				return -DHCP_ERR_OVERLOAD_INVALID_LEN;
			}
			if (overload_type) {
				DBG("[DHCP] got overload options option more than once !\n");
				return -DHCP_ERR_OVERLOAD_DUPLICATE;
			}
			overload_type = options_buff[i + 2];
			i += 2;
			continue;
		}

		/* Found another option, grab its length field, count it, and skip it */
		if (options_buff[i] != DHCP_OPTION_END) {
			option_len = options_buff[i + 1];
			i += option_len + 1;
			skipped_options++;
			continue;
		} else {
			/* We got the end marker but we still need to search
			 * in other option fields as well, reset and restart.
			 * Note that each field is searched seperately so
			 * unfortunately we can't treat sname/file as one
			 * field even though they are next to each other. */
			if (overload_type) {
				switch (overload_type) {
				case DHCP_OPTIONS_OVERLOAD_BOTH:
				case DHCP_OPTIONS_OVERLOAD_FILE:
					options_offset = offsetof(DhcpMsg, boot_filename);
					options_buff = msg_buff + options_offset;
					options_field_size = DHCP_FILENAME_LEN;
					/* If both -> 2 (SNAME) is next, if file -> 0 (done) */
					overload_type--;
					break;
				case DHCP_OPTIONS_OVERLOAD_SNAME:
					options_offset = offsetof(DhcpMsg, server_hostname);
					options_buff = msg_buff + options_offset;
					options_field_size = DHCP_SERVER_HOSTNAME_LEN;
					overload_type = 0;
					break;
				default:
					DBG("[DHCP] got an invalid options overload type !\n");
					return -DHCP_ERR_OVERLOAD_INVALID_TYPE;
				}
				i = 0;
				continue;
			}
			/* We got the END marker and we are done searching, if the PAD (0)
			 * option was requested, return skipped_options instead of the
			 * offset, we use that for validating DHCPNACKs that MUST_NOT have
			 * any options set other than a few selected ones. If not we did the
			 * search but didn't find the requested options. */
			if (option_id == 0)
				return skipped_options;
			else
				return 0;
		}
	}

	DBG("[DHCP] failed while searching for option %i (offset was %i) !\n", option_id, options_offset + i);
	return -DHCP_ERR_OPTION_SEARCH_FAILED;
}


/***************************\
* Grab options fron replies *
\***************************/

int
dhcp_get_static_route_for_ip(const uint8_t* buff, uint32_t addr, uint32_t *gw_addr)
{
	int offset = dhcp_grab_option_offset(buff, DHCP_STATIC_ROUTE_OPTION);
	if (offset <= 0)
		return offset;
	uint8_t static_routes_len = buff[offset + 1];
	offset += 2;

	if ((static_routes_len < DHCP_STATIC_ROUTE_ELEMENT_LEN) ||
	    (static_routes_len % DHCP_STATIC_ROUTE_ELEMENT_LEN)) {
		DBG("[DHCP] list of static routes has invalid size !\n");
		return -DHCP_ERR_STATIC_ROUTES_INVALID_SIZE;
	}

	int max_offset = offset + static_routes_len - DHCP_STATIC_ROUTE_ELEMENT_LEN;

	for (; offset <= max_offset; offset += DHCP_STATIC_ROUTE_ELEMENT_LEN) {
		uint32_t daddr = net_get_u32(&buff[offset]);
		if (daddr != addr)
			continue;
		/* Gotcha ! */
		*gw_addr = net_get_u32(&buff[offset + 4]);
		break;
	}

	return  0;
}


/*****************************\
* Add options in our requests *
\*****************************/

/* Initialize an option set to track down the whole process */
void
dhcp_init_options_set(DhcpOpts *opts_set, uint8_t* msg_buff, uint8_t msg_type, int overload)
{ 
	int i = 0;

	opts_set->msg_buff = msg_buff;
	opts_set->options_buff = msg_buff + offsetof(DhcpMsg, options);
	opts_set->options_buff_len = DHCP_MIN_OPTIONS_LEN;
	opts_set->options_set = 0;
	opts_set->offset = 0;
	opts_set->overload_type = overload ? DHCP_OPTIONS_OVERLOAD_FILE : 0;
	opts_set->overload_type_offset = 0;

	/* Add the magic cookie in the options field */
	opts_set->options_buff[i++] = DHCP_MAGIC_COOKIE_0;
	opts_set->options_buff[i++] = DHCP_MAGIC_COOKIE_1;
	opts_set->options_buff[i++] = DHCP_MAGIC_COOKIE_2;
	opts_set->options_buff[i++] = DHCP_MAGIC_COOKIE_3;

	/* Add message type afterwards */
	opts_set->options_buff[i++] = DHCP_MESSAGE_TYPE_OPTION;
	opts_set->options_buff[i++] = DHCP_MESSAGE_TYPE_LEN;
	opts_set->options_buff[i++] = msg_type;

	/* If overload was requested add the overload option, put
	 * the END marker in the options field, and switch to using
	 * the boot_filename field. */
	if (overload) {
		int options_offset = offsetof(DhcpMsg, options);

		opts_set->options_buff[i++] = DHCP_OPTION_OVERLOAD_OPTION;
		opts_set->options_buff[i++] = DHCP_OPTION_OVERLOAD_LEN;
		opts_set->overload_type_offset = options_offset + i;
		opts_set->options_buff[i++] = DHCP_OPTIONS_OVERLOAD_FILE;

		opts_set->options_buff[i++] = DHCP_OPTION_END;

		/* PAD packet to align its size to 8bytes */
		while ((options_offset + i) % 8)
			opts_set->options_buff[i++] = DHCP_OPTION_PAD;

		opts_set->options_buff = msg_buff + offsetof(DhcpMsg, boot_filename);
		opts_set->options_buff_len = DHCP_FILENAME_LEN;

		/* We already know the length of the options field, it won't grow
		 * any further. */
		opts_set->msg_options_len = i;
	} else
		opts_set->offset += i;
}

/* Finish up with adding options and let the caller know how many
 * octets from the options field were used so that it can calculate
 * total packet size. */
int
dhcp_close_options_set(DhcpOpts *opts_set)
{
	/* Put an END marker in our current options field, dhcp_get_option_slot
	 * below makes sure that there is always at least an octet left. */
	opts_set->options_buff[opts_set->offset++] = DHCP_OPTION_END;

	/* In case of options overload we only used a few octets from
	 * the options field that we recorded in dhcp_init_options_set()
	 * abovre, return what we have, else return the final offset of
	 * our current options field, since it's dhcp_message->options. */
	switch (opts_set->overload_type) {
	case DHCP_OPTIONS_OVERLOAD_BOTH:
		/* Did we also end up using sname field ? If so update the type
		 * in the options ovverload option field. */
		opts_set->msg_buff[opts_set->overload_type_offset] = DHCP_OPTIONS_OVERLOAD_BOTH;
		__attribute__ ((fallthrough));
	case DHCP_OPTIONS_OVERLOAD_FILE:
		return opts_set->msg_options_len;
	default:
		break;
	}

	return opts_set->offset;
}

/* Get next slot for adding an option, making sure we only add it once.
 * This also makes sure we don't overflow any of the availalbe options fields
 * when adding options. */
static int
dhcp_get_option_slot(DhcpOpts *opts_set, uint8_t option_id,
		     uint32_t option_bit, uint8_t option_length)
{
	/* First let's see if the option is already there, the options we add
	 * (so far) can only be added once, make sure we don't screw up. */
	if (option_bit & opts_set->options_set) {
		DBG("[DHCP] option %i added more than once !\n", option_id);
		return -DHCP_ERR_OPTION_DUPLICATE;
	}

	/* Do we have enough space left in the current options field to
	 * hold the option, it's id/len fields, and an END marker afterwards
	 * if needed ? */
	if ((uint32_t)(opts_set->offset + option_length + 2  + 1) >= opts_set->options_buff_len) {
		/* If we use options overload and haven't used the sname field yet
		 * put an END marker here and move on. Note that we'll update the
		 * overload type in the overload option on dhcp_close_options_set(),
		 * no need to worry about it here. */
		 if (opts_set->overload_type == DHCP_OPTIONS_OVERLOAD_FILE) {
			opts_set->options_buff[opts_set->offset] = DHCP_OPTION_END;
			opts_set->options_buff = opts_set->msg_buff +
						 offsetof(DhcpMsg, server_hostname);
			opts_set->options_buff_len = DHCP_SERVER_HOSTNAME_LEN;
			opts_set->overload_type = DHCP_OPTIONS_OVERLOAD_BOTH;
			opts_set->offset = 0;
		 } else {
			 DBG("[DHCP] not enough space left for option %i !\n", option_id);
			 return -DHCP_ERR_OPTION_NO_SPACE;
		 }
	}

	/* Add option to the set so that we don't add it again */
	opts_set->options_set |= option_bit;

	return opts_set->offset;
}

/* Add client's hostname*/
void
dhcp_add_hostname(DhcpOpts *opts_set, const uint8_t* mac_addr)
{
	/* Note: 3:00am bug hunting...
	 * This is better not only because it'll just grab the string from .rodata
	 * instead of generating code to copy it on the stack at runtime. It also
	 * prevents GCC's optimization passes from fighting each other: At first
	 * -flto will figure out that memcpy is just a wrapper to memmove and swap
	 * them, then --gc-sections will see that nobody uses memcpy and remove it
	 * from the binary. If -Os is used instead of -O2, the backend will see
	 * a large code chunk/loop to initialize hostname in the stack and turn it
	 * to a call to memcpy to save space. Finaly linker will come here see the
	 * memcpy and try to resolve it, but it'll be nowhere. Long story short,
	 * keep static there ! */
	static const char hostname[] = DHCP_HOSTNAME;
	int hostname_len = sizeof(hostname) - 1; // No NULL terminator
	if (hostname_len <= 0)
		return;

	int offset = dhcp_get_option_slot(opts_set, DHCP_HOSTNAME_OPTION,
					  DHCP_HOSTNAME_OPTION_BIT, hostname_len + 4);
	if (offset < 0)
		return;

	opts_set->options_buff[offset++] = DHCP_HOSTNAME_OPTION;
	opts_set->options_buff[offset++] = hostname_len + 4;
	memcpy(opts_set->options_buff + offset, hostname, hostname_len);
	offset += hostname_len;
	opts_set->options_buff[offset++] = hex_to_ascii(((mac_addr[ETH_ADDR_LEN - 2] & 0xF0) >> 4));
	opts_set->options_buff[offset++] = hex_to_ascii((mac_addr[ETH_ADDR_LEN - 2] & 0x0F));
	opts_set->options_buff[offset++] = hex_to_ascii(((mac_addr[ETH_ADDR_LEN - 1] & 0xF0) >> 4));
	opts_set->options_buff[offset++] = hex_to_ascii((mac_addr[ETH_ADDR_LEN - 1] & 0x0F));

	opts_set->offset = offset;
}

/* Add client's requested IP */
void
dhcp_add_requested_ip_addr(DhcpOpts *opts_set, uint32_t ip_addr)
{
	union {
		uint8_t ip_bytes[4];
		uint32_t ip_addr;
	} ip;

	int offset = dhcp_get_option_slot(opts_set, DHCP_REQUESTED_IP_OPTION,
					  DHCP_REQUESTED_IP_OPTION_BIT,
					  DHCP_REQUESTED_IP_LEN);
	if (offset < 0)
		return;

	ip.ip_addr = ip_addr;
	opts_set->options_buff[offset++] = DHCP_REQUESTED_IP_OPTION;
	opts_set->options_buff[offset++] = DHCP_REQUESTED_IP_LEN;
	opts_set->options_buff[offset++] = ip.ip_bytes[0];
	opts_set->options_buff[offset++] = ip.ip_bytes[1];
	opts_set->options_buff[offset++] = ip.ip_bytes[2];
	opts_set->options_buff[offset++] = ip.ip_bytes[3];
	
	opts_set->offset = offset;
}

/* Add server's IP */
void
dhcp_add_server_id(DhcpOpts *opts_set, uint32_t ip_addr)
{
	union {
		uint8_t ip_bytes[4];
		uint32_t ip_addr;
	} ip;

	int offset = dhcp_get_option_slot(opts_set, DHCP_SERVER_ID_OPTION,
					  DHCP_SERVER_ID_OPTION_BIT,
					  DHCP_SERVER_ID_LEN);
	if (offset < 0)
		return;

	ip.ip_addr = ip_addr;
	opts_set->options_buff[offset++] = DHCP_SERVER_ID_OPTION;
	opts_set->options_buff[offset++] = DHCP_SERVER_ID_LEN;
	opts_set->options_buff[offset++] = ip.ip_bytes[0];
	opts_set->options_buff[offset++] = ip.ip_bytes[1];
	opts_set->options_buff[offset++] = ip.ip_bytes[2];
	opts_set->options_buff[offset++] = ip.ip_bytes[3];
	
	opts_set->offset = offset;
}

/* Add parameter request list */
void
dhcp_add_parameter_req_list(DhcpOpts *opts_set, int want_tftp)
{
	uint8_t len = want_tftp ? 5 : 3;
	int offset = dhcp_get_option_slot(opts_set, DHCP_PARAMETER_REQUEST_OPTION,
					  DHCP_PARAMETER_REQUEST_OPTION_BIT, len);
	if (offset < 0)
		return;

	opts_set->options_buff[offset++] = DHCP_PARAMETER_REQUEST_OPTION;
	opts_set->options_buff[offset++] = len;
	opts_set->options_buff[offset++] = DHCP_SUBNET_MASK_OPTION;
	opts_set->options_buff[offset++] = DHCP_ROUTER_OPTION;
	opts_set->options_buff[offset++] = DHCP_STATIC_ROUTE_OPTION;
	if (want_tftp) {
		opts_set->options_buff[offset++] = DHCP_TFTP_SERVER_IP_OPTION;
		opts_set->options_buff[offset++] = DHCP_BOOTFILE_NAME_OPTION;
	}
	opts_set->offset = offset;
}

/* Limit maximum message size to 576 octets
 * that's sizeof(dhcp_message) + udp header + ip header */
void
dhcp_add_max_msg_len(DhcpOpts *opts_set)
{
	union {
		uint8_t bytes[2];
		uint16_t val;
	} max_msg_len;

	int offset = dhcp_get_option_slot(opts_set, DHCP_MAXIMUM_MESSAGE_LENGTH_OPTION,
					  DHCP_MAXIMUM_MESSAGE_LENGTH_OPTION_BIT,
					  DHCP_MAXIMUM_MESSAGE_LENGTH_LEN);
	if (offset < 0)
		return;

	opts_set->options_buff[offset++] = DHCP_MAXIMUM_MESSAGE_LENGTH_OPTION;
	opts_set->options_buff[offset++] = DHCP_MAXIMUM_MESSAGE_LENGTH_LEN;
	max_msg_len.val = htons(576);
	opts_set->options_buff[offset++] = max_msg_len.bytes[0];
	opts_set->options_buff[offset++] = max_msg_len.bytes[1];

	opts_set->offset = offset;
}

/* Let the server know of our client's name/version */
void
dhcp_add_vendor_identifier(DhcpOpts *opts_set)
{
	static const char vendor_id_string[] = DHCP_VENDOR_CLASS_ID_STRING;
	int vendor_id_string_len = sizeof(vendor_id_string) - 1; // No NULL terminator
	if (vendor_id_string_len <= 0 || vendor_id_string_len >= DHCP_VENDOR_CLASS_ID_MAX_LEN)
		return;

	int offset = dhcp_get_option_slot(opts_set, DHCP_VENDOR_CLASS_ID_OPTION,
					  DHCP_VENDOR_CLASS_ID_OPTION_BIT, vendor_id_string_len);
	if (offset < 0)
		return;

	opts_set->options_buff[offset++] = DHCP_VENDOR_CLASS_ID_OPTION;
	opts_set->options_buff[offset++] = (uint8_t) vendor_id_string_len;
	memcpy(opts_set->options_buff + offset, vendor_id_string, vendor_id_string_len);
	offset += vendor_id_string_len;

	opts_set->offset = offset;
}

/* Add Client identifier option, use our MAC address and follow
 * the recommendations on RFC4361 section 6.1, creating a DUID
 * based on our MAC address only, as indicated by RFC3315 section 9.4.
 * This makes sense in our case also because when the next boot stage
 * loads and we reach the OS at some point, the OS will also do a
 * DHCP request, and it's a different entity (different IAID) with
 * the same MAC address (DUID). */
void
dhcp_add_client_identifier(DhcpOpts *opts_set, const uint8_t* mac_addr)
{
	int offset = dhcp_get_option_slot(opts_set, DHCP_CLIENT_ID_OPTION,
					  DHCP_CLIENT_ID_OPTION_BIT, 15);
	if (offset < 0)
		return;

	opts_set->options_buff[offset++] = DHCP_CLIENT_ID_OPTION;
	opts_set->options_buff[offset++] = 15;
	opts_set->options_buff[offset++] = 255;	 // Type
	opts_set->options_buff[offset++] = 0x2c; // IAID (first 4 bytes of SHA1 of "eth0-bootrom")
	opts_set->options_buff[offset++] = 0xaf;
	opts_set->options_buff[offset++] = 0x9d;
	opts_set->options_buff[offset++] = 0x9b;
	opts_set->options_buff[offset++] = 0;	 // DUID type (uint16_t in network order)
	opts_set->options_buff[offset++] = 3;
	opts_set->options_buff[offset++] = 0;	 // Hw addr type (uint16_t in network order)
	opts_set->options_buff[offset++] = ARP_HTYPE_ETHER;
	opts_set->options_buff[offset++] = mac_addr[0];
	opts_set->options_buff[offset++] = mac_addr[1];
	opts_set->options_buff[offset++] = mac_addr[2];
	opts_set->options_buff[offset++] = mac_addr[3];
	opts_set->options_buff[offset++] = mac_addr[4];
	opts_set->options_buff[offset++] = mac_addr[5];

	opts_set->offset = offset;
}

