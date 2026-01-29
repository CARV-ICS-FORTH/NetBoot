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
#include <stdlib.h>	/* For rand() */
#include <string.h> 	/* For memset()/memcpy() */
#include <stddef.h>	/* For offsetof() */
#include <errno.h>	/* For errno and its values */
#include <time.h>	/* For nanosleep() / clock() */

static DhcpState *dhcpc = NULL;

/*
 * DHCP reply validation error codes
 * These are returned as negative values from dhcp_reply_validate(), they are above 300 so that they
 * don't overlap with standard errno codes.
 */
enum dhcp_validate_err {
	DHCP_ERR_NO_CLIENT = 300,		/* DHCP Client state not initialized */
	DHCP_ERR_NOT_BOOTREPLY,			/* Message is not a BOOTREPLY */
	DHCP_ERR_INVALID_HWADDR,		/* Invalid hardware address type or length */
	DHCP_ERR_UNEXPECTED_SECS,		/* Unexpected value in secs_elapsed field */
	DHCP_ERR_FLAGS_XID_MISMATCH,		/* Flags or XID don't match our request */
	DHCP_ERR_NONZERO_HOPS,			/* Hops field is non-zero (buggy relay/server) */
	DHCP_ERR_RELAY_IP_SUBNET_MISMATCH,	/* Relay IP changed and it belongs to a different subnet */
	DHCP_ERR_HWADDR_MISMATCH,		/* Server replied with different client hwaddr */
	DHCP_ERR_INVALID_MAGIC_COOKIE,		/* Invalid magic cookie in options field */
	DHCP_ERR_NO_MSG_TYPE,			/* Reply missing DHCP message type option */
	DHCP_ERR_WRONG_MSG_TYPE,		/* Unexpected message type received */
	DHCP_ERR_NO_SERVER_ID,			/* Reply missing server identifier option */
	DHCP_ERR_DIFFERENT_SERVER,		/* Reply from a different server than expected */
	DHCP_ERR_HAS_REQUESTED_IP,		/* Server included requested IP option (forbidden) */
	DHCP_ERR_HAS_PARAM_REQUEST,		/* Server included parameter request option (forbidden) */
	DHCP_ERR_HAS_MAX_MSG_LEN,		/* Server included max message length option (forbidden) */
	DHCP_ERR_OFFER_CLIENT_IP_SET,		/* DHCPOFFER has client IP address set (should be zero) */
	DHCP_ERR_OFFER_NO_IP,			/* DHCPOFFER missing offered IP address */
	DHCP_ERR_OFFER_NO_LEASE,		/* DHCPOFFER missing lease time option */
	DHCP_ERR_OFFER_HAS_CLIENT_ID,		/* DHCPOFFER includes client identifier (forbidden) */
	DHCP_ERR_ACK_CLIENT_IP_MISMATCH,	/* DHCPACK client IP address mismatch */
	DHCP_ERR_ACK_CLIENT_IP_SET,		/* DHCPACK has client IP set (should be zero) */
	DHCP_ERR_ACK_NO_IP,			/* DHCPACK missing offered IP address */
	DHCP_ERR_ACK_INFORM_HAS_LEASE,		/* DHCPACK to DHCPINFORM includes lease time */
	DHCP_ERR_ACK_REQUEST_NO_LEASE,		/* DHCPACK to DHCPREQUEST missing lease time */
	DHCP_ERR_ACK_HAS_CLIENT_ID,		/* DHCPACK includes client identifier (forbidden) */
	DHCP_ERR_NAK_IPADDR_SET,		/* DHCPNAK has client/offered/server IP set */
	DHCP_ERR_NAK_SNAME_NOT_EMPTY,		/* DHCPNAK has non-empty sname field */
	DHCP_ERR_NAK_HOSTNAME_NOT_EMPTY,	/* DHCPNAK has non-empty hostname field */
	DHCP_ERR_NAK_UNEXPECTED_OPTIONS,	/* DHCPNAK has unexpected options */
	DHCP_ERR_UNKNOWN_MSG_TYPE,		/* Unknown or unhandled message type */
};

/*********\
* Helpers *
\*********/

static int
dhcp_check_empty_field(const char *buff, uint8_t size)
{
	int i = 0;
	for (i = 0; i < size; i++)
		if (buff[i] != 0)
			return 0;
	return 1;
}

static inline uint16_t
dhcp_get_elapsed_sec(void)
{
	clock_t now = clock();
	return (uint16_t)((now - dhcpc->session_start) /  CLOCKS_PER_SEC);
}

/******************\
* Input validation *
\******************/

static int
dhcp_reply_validate(const uint8_t *buff, uint8_t expected_msg_type)
{
	if (!dhcpc)
		return -DHCP_ERR_NO_CLIENT;

	if (!buff)
		return -ENODATA;

	DhcpMsg *in_msg = (DhcpMsg*) buff;
	const DhcpMsg *last_out_msg = &dhcpc->last_out_msg;

	/* Verify the message according to RFC2131 section 4.3.1 */

	/* Field restrictions common to all server messages */
	if (in_msg->op != DHCP_OP_BOOTREPLY) {
		DBG("[DHCP] got a reply message that's not BOOTREPLY !\n");
		return -DHCP_ERR_NOT_BOOTREPLY;
	}
	if ((in_msg->hw_addr_type != ARP_HTYPE_ETHER) || (in_msg->hw_addr_len != ETH_ADDR_LEN)) {
		DBG("[DHCP] got a reply message with invalid hwaddr/len info !\n");
		return -DHCP_ERR_INVALID_HWADDR;
	}
	if (net_get_u16_aligned(&in_msg->secs_elapsed)) {
		DBG("[DHCP] got non-zero secs in reply message !\n");
		return -DHCP_ERR_UNEXPECTED_SECS;
	}
	/*
	 * The transaction ID must be preserved across the whole process, regardless of whether a relay
	 * agent is present or not, the same applies to the flags field, which we always set to 0 to
	 * indicate that the client can receive unicast frames.
	 */
	if (net_get_u16_aligned(&in_msg->flags) || (net_get_u32(&in_msg->xid) != last_out_msg->xid)) {
		DBG("[DHCP] mismatch in flags/xid between our request and received reply !\n");
		return -DHCP_ERR_FLAGS_XID_MISMATCH;
	}
	/*
	 * So this is messy and it took me a while to sort it out:
	 * The table 3 in section 4.3.1 clearly states that the relay ip addr must be the same as
	 * the value in the client's request. However this field of the client's request may get
	 * modified in case there is a DHCP relay in place, in which case the (local) relay will add
	 * its own address there, instead of 0, to indicate to the server for which subnet the request
	 * was for. The relay must also increase the hops count, and make sure that any packets with
	 * more than 16 hops are silently dropped (at least according to RFC1542), however RFC2131 says
	 * that this field may "optionally" be used which contradicts the MUST on RFC1542. Anyway since
	 * we only care about the client here, the question is what should we expect for the hops field.
	 * Fortunately the situation is a bit simpler than the giaddr handling, since hops are only
	 * increased on the requests not the server's replies, and according to table 3 the server always
	 * sets them to 0. So the client should always observe hops == 0, even if giaddr is set.
	 */
	if (in_msg->hops != 0) {
		DBG("[DHCP] buggy relay/server detected, hops field is non zero !\n");
		return -DHCP_ERR_NONZERO_HOPS;
	}

	uint32_t in_relay_ipaddr = net_get_u32(&in_msg->relay_ipaddr);
	if (in_relay_ipaddr) {
		/* This is normal in load-balancing scenarios, as long as both IPs belong to
		 * the same subnet, if not this is dangerous...*/
		if (dhcpc->relay_ip && (in_relay_ipaddr != dhcpc->relay_ip)) {
			DBG("[DHCP] the relay's ip changed !\n");
			DBG("\tFrom: %s\n", inet_print_ipv4(dhcpc->relay_ip));
			DBG("\tTo: %s\n", inet_print_ipv4(in_relay_ipaddr));
			/* Since we are here let's be on the safe side */
			if (dhcpc->subnet_mask &&
			    (dhcpc->relay_ip & dhcpc->subnet_mask) != (in_relay_ipaddr & dhcpc->subnet_mask)) {
				ERR("[DHCP] relay's IP AND subnet changed !\n");
				return -DHCP_ERR_RELAY_IP_SUBNET_MISMATCH;
			    }
		}
	}

	if (memcmp(in_msg->client_hwaddr, last_out_msg->client_hwaddr, DHCP_CLIENT_HW_ALEN)) {
		DBG("[DHCP] server replied with another client hw address !\n");
		return -DHCP_ERR_HWADDR_MISMATCH;
	}

	/* Option restrictions common for all server messages */
	if ((in_msg->options[0] != DHCP_MAGIC_COOKIE_0) ||
	    (in_msg->options[1] != DHCP_MAGIC_COOKIE_1) ||
	    (in_msg->options[2] != DHCP_MAGIC_COOKIE_2) ||
	    (in_msg->options[3] != DHCP_MAGIC_COOKIE_3)) {
		DBG("[DHCP] got invalid magic cookie in options field !\n");
		return -DHCP_ERR_INVALID_MAGIC_COOKIE;
	}
	uint8_t options_count = 0;

	/* These should always be present, make sure they are valid as well. */
	int ret = dhcp_grab_option_offset(buff, DHCP_MESSAGE_TYPE_OPTION);
	if (!ret) {
		DBG("[DHCP] got reply without DHCP message type !\n");
		return -DHCP_ERR_NO_MSG_TYPE;
	} else if (ret < 0)
		return ret;
	uint8_t msg_type = buff[ret + 2];
	if (expected_msg_type && msg_type != expected_msg_type) {
		/* Expected an ACK and got a NAK */
		if (expected_msg_type == DHCPACK && msg_type == DHCPNAK)
			return -EAGAIN;
		DBG("[DHCP] expected message type %i and got %i instead !\n",
		    expected_msg_type, msg_type);
		return -DHCP_ERR_WRONG_MSG_TYPE;
	}
	options_count++;

	ret = dhcp_grab_option_offset(buff, DHCP_SERVER_ID_OPTION);
	if (!ret) {
		DBG("[DHCP] got reply without server identifier !\n");
		return -DHCP_ERR_NO_SERVER_ID;
	} else if (ret < 0)
		return ret;
	uint32_t server_ip = net_get_u32(buff + ret + 2);
	if (dhcpc->server_ip && dhcpc->server_ip != server_ip) {
		DBG("[DHCP] got reply from a different server !\n");
		return -DHCP_ERR_DIFFERENT_SERVER;
	}
	options_count++;


	/* These are all MUST_NOTs so they shouldn't be present in any case. */
	ret = dhcp_grab_option_offset(buff, DHCP_REQUESTED_IP_OPTION);
	if (ret > 0) {
		DBG("[DHCP] server replied with requested IP option !\n");
		return -DHCP_ERR_HAS_REQUESTED_IP;
	} else if (ret < 0)
		return ret;

	ret = dhcp_grab_option_offset(buff, DHCP_PARAMETER_REQUEST_OPTION);
	if (ret > 0) {
		DBG("[DHCP] server replied with paremeter list request !\n");
		return -DHCP_ERR_HAS_PARAM_REQUEST;
	} else if (ret < 0)
		return ret;

	ret = dhcp_grab_option_offset(buff, DHCP_MAXIMUM_MESSAGE_LENGTH_OPTION);
	if (ret > 0) {
		DBG("[DHCP] server replied with maximum message length !\n");
		return -DHCP_ERR_HAS_MAX_MSG_LEN;
	} else if (ret < 0)
		return ret;

	/* Field/Option restrictions per message type */
	uint32_t in_client_ipaddr = net_get_u32(&in_msg->client_ipaddr);
	uint32_t in_offered_ipaddr = net_get_u32(&in_msg->offered_ipaddr);
	uint32_t in_server_ipaddr = net_get_u32(&in_msg->server_ipaddr);
	switch (msg_type) {
		case DHCPOFFER:
			if (in_client_ipaddr) {
				DBG("[DHCP] got DHCPOFFER with client's ipaddr set !\n");
				return -DHCP_ERR_OFFER_CLIENT_IP_SET;
			}

			if (!in_offered_ipaddr) {
				DBG("[DHCP] got DHCPOFFER without an offered IP address !\n");
				return -DHCP_ERR_OFFER_NO_IP;
			}

			/* server_ip addr -> leave it to the caller */

			ret = dhcp_grab_option_offset(buff, DHCP_LEASE_TIME_SECS_OPTION);
			if(!ret) {
				DBG("[DHCP] got DHCPOFFER without lease time !\n");
				return -DHCP_ERR_OFFER_NO_LEASE;
			} else if (ret < 0)
				return ret;

			ret = dhcp_grab_option_offset(buff, DHCP_CLIENT_ID_OPTION);
			if (ret > 0) {
				DBG("[DHCP] got DHCPOFFER with client identifer !\n");
				return -DHCP_ERR_OFFER_HAS_CLIENT_ID;
			} else if (ret < 0)
				return ret;
			break;
		case DHCPACK:
			if (dhcpc->last_msg_type == DHCPREQUEST &&
			   (in_client_ipaddr)) {
				DBG("[DHCP] client ip address mismatch on DHCPACK: %04x !\n",
				    in_client_ipaddr);
				return -DHCP_ERR_ACK_CLIENT_IP_MISMATCH;
			} else if (in_client_ipaddr) {
				DBG("[DHCP] got DHCPACK with client ip address (should be zero) !\n");
				return -DHCP_ERR_ACK_CLIENT_IP_SET;
			}

			if (!in_offered_ipaddr) {
				DBG("[DHCP] got a DHCPACK without offered address !\n");
				return -DHCP_ERR_ACK_NO_IP;
			}

			/* server_ip addr -> leave it to the caller */

			ret = dhcp_grab_option_offset(buff, DHCP_LEASE_TIME_SECS_OPTION);
			if ((dhcpc->last_msg_type == DHCPINFORM) && ret > 0) {
				DBG("[DHCP] got a DHCPACK to DHCPINFORM with lease time set !\n");
				return -DHCP_ERR_ACK_INFORM_HAS_LEASE;
			} else if ((dhcpc->last_msg_type == DHCPREQUEST) && !ret) {
				DBG("[DHCP] got a DHCPACK to DHCPREQUEST without lease time set !\n");
				return -DHCP_ERR_ACK_REQUEST_NO_LEASE;
			} else if (ret < 0)
				return ret;

			ret = dhcp_grab_option_offset(buff, DHCP_CLIENT_ID_OPTION);
			if (ret > 0) {
				DBG("[DHCP] got DHCPACK with client identifer !\n");
				return -DHCP_ERR_ACK_HAS_CLIENT_ID;
			} else if (ret < 0)
				return ret;
			break;
		case DHCPNAK:
			if (in_client_ipaddr || in_offered_ipaddr || in_server_ipaddr) {
				DBG("[DHCP] got a DHCPNACK with client/offered/server ip addr set !\n");
				return -DHCP_ERR_NAK_IPADDR_SET;
			}

			/* Note: since the options overload option MUST_NOT be present in a DHCPNACK
			 * there won't be any options in sname/file fields, and since they are also
			 * unused, they should be empty. */
			if (dhcp_check_empty_field(in_msg->server_hostname, DHCP_SERVER_HOSTNAME_LEN)) {
				DBG("[DHCP] got a DHCPNACK with non-empty sname field !\n");
				return -DHCP_ERR_NAK_SNAME_NOT_EMPTY;
			}

			if (dhcp_check_empty_field(in_msg->server_hostname, DHCP_SERVER_HOSTNAME_LEN)) {
				DBG("[DHCP] got a DHCPNACK with non-empty hostname field !\n");
				return -DHCP_ERR_NAK_HOSTNAME_NOT_EMPTY;
			}

			/* Check for the remaining allowed options and count them */
			ret = dhcp_grab_option_offset(buff, DHCP_CLIENT_ID_OPTION);
			if (ret > 0) {
				options_count++;
			} else if (ret < 0)
				return ret;

			ret = dhcp_grab_option_offset(buff, DHCP_MESSAGE_OPTION);
			if (ret > 0) {
				options_count++;
			} else if (ret < 0)
				return ret;

			ret = dhcp_grab_option_offset(buff, DHCP_VENDOR_CLASS_ID_OPTION);
			if (ret > 0) {
				options_count++;
			} else if (ret < 0)
				return ret;

			/* Now make sure no other options are present by asking dhcp_grab_option_offset
			 * to give us all options it skipped while searching for nothing. */
			ret = dhcp_grab_option_offset(buff, 0);
			if (ret < 0)
				return ret;
			if (ret > options_count) {
				DBG("[DHCP] got DHCPNACK with unexpected number of options\n");
				return -DHCP_ERR_NAK_UNEXPECTED_OPTIONS;
			}
			break;
		default:
			DBG("[DHCP] got reply from server with unkown/unhandled message type: %0x !\n",
			    msg_type);
			return -DHCP_ERR_UNKNOWN_MSG_TYPE;
	}

	/* Done, return server_ip and let caller decide if this is the dhcp server we choose */
	return server_ip;
}

/***********************************\ 
* Request (re)transmission handling *
\***********************************/

typedef int (*dhcp_handler_fn)(const uint8_t *in_buff);

/*
 * Initiate a reliable exchange between the client and the server.
 * This takes care of retransmissions as mandated in RFC2131 sec. 4.1,
 * and tracking/maintenance of elapsed seconds etc. On reception it
 * verifies input and calls the provided handler function to take
 * care of it. 
 */
static int
dhcp_reliable_exchange(uint16_t out_msg_len, uint8_t expected_msg_type,
		       dhcp_handler_fn response_handler)
{
	if (!dhcpc)
		return -DHCP_ERR_NO_CLIENT;
	DhcpMsg *out_msg = &dhcpc->last_out_msg;
	int ret = 0;

	/* If we ended up waiting for 32secs during a retransmission without luck
	 * (the maximum backoff is 64) it means we've already waited for more than
	 * a minute (1+2+4+8+16+32=64) without luck. Just give up and let caller
	 * handle it. There is probably no DHCP server in the network or the
	 * server/network is down. */
	int delay_secs = 1;
	while (delay_secs <= 32) {
		/*
		 * Failure to send a messsage indicates a nic issue and is fatal,
		 * exit and let caller deal with it.
		 *
		 * Note: Although we know the server's ip address, we don't have an ip
		 * address assigned to us yet (we will after we reach the BOUND state),
		 * so the DHCP server won't be able to respond back using unicast. As
		 * RFC2131 section 3.1.3 mandates, we broadcast instead. This also acts
		 * as a notification to the other DHCP servers that we won't be accepting
		 * their offer.
		 */
		ret = net_send_udp(0, DHCP_BOOTP_CLIENT_PORT, DHCP_BOOTP_SERVER_PORT,
				   out_msg, out_msg_len, UDP_SEND_INETCONTROL | UDP_SEND_BCAST);
		if (ret < 0) {
			ERR("[DHCP] couldn't send message: %i\n", ret);
			return ret;
		} else if (ret < out_msg_len) {
			ERR("[DHCP] incomming message truncated: %i vs %i\n",
			    ret, out_msg_len);
			return -EIO;
		}

		/* We could just use net_wait_for_udp with a timeout, but we also need
		 * to handle stale packets from previous requests/sessions where the server
		 * took too long to send them, or we missed them and got one of the
		 * retransmissions later on. So this is a bit more complex than I'd like
		 * but whatever, here it goes...*/
		clock_t start = clock();
		uint32_t delay_msec = (rand() & 0x3E0UL) + (delay_secs * 1000);
		uint32_t elapsed_msec = 0;
		while (elapsed_msec < delay_msec) {
			/* net_wait_for_udp may return earlier than expected due to a
			 * stale packet, keep trying until we are out of time or we
			 * get what we expect. */
			uint32_t remaining_ms = delay_msec - elapsed_msec;
			ssize_t payload_size = 0;
			const uint8_t *in_buff = net_wait_for_udp(DHCP_BOOTP_CLIENT_PORT, &payload_size,
							 	  NULL, NULL, remaining_ms);
			clock_t now = clock();
			elapsed_msec = ((now - start) * 1000ULL) / CLOCKS_PER_SEC;

			if (!in_buff || payload_size <= 0)
				continue;

			if (response_handler)
				ret = response_handler(in_buff);
			else
				ret = dhcp_reply_validate(in_buff, expected_msg_type);

			if (ret == -DHCP_ERR_FLAGS_XID_MISMATCH || ret == -DHCP_ERR_WRONG_MSG_TYPE) {
				DBG("[DHCP] Ignoring stale or wrong packet (err: %i)...\n", ret);
				continue;
			}

			return ret;
		}

		/* Prepare for Retransmission */
		DBG("[DHCP] Timeout waiting for reply (waited %u ms), retransmitting...\n", delay_msec);
		delay_secs <<= 1;
		uint16_t secs_elapsed = dhcp_get_elapsed_sec();
		out_msg->secs_elapsed = htons(secs_elapsed);
	}
	return -ETIME;
}

/*******************\
* Protocol handling *
\*******************/

/* Send a DHCPRELEASE to let the server know we are done using
 * the IP it offered us. */
int
dhcp_send_release(void)
{
	if (!dhcpc)
		return -DHCP_ERR_NO_CLIENT;

	/* Never got an IP, nothing to release */
	if(!dhcpc->client_ip)
		return 0;

	/* Clean up last_out_msg */
	DhcpMsg *out_msg = &dhcpc->last_out_msg;
	out_msg->xid = rand();
	out_msg->secs_elapsed = 0;
	out_msg->client_ipaddr = dhcpc->client_ip;
	out_msg->offered_ipaddr = 0;
	out_msg->server_ipaddr = 0;
	out_msg->relay_ipaddr = 0;
	memset(out_msg->client_hwaddr + ETH_ADDR_LEN, 0,
	       DHCP_CLIENT_HW_ALEN - ETH_ADDR_LEN +
	       DHCP_SERVER_HOSTNAME_LEN + DHCP_FILENAME_LEN + DHCP_MIN_OPTIONS_LEN);

	/* Add options */
	DhcpOpts opts_set = {0};
	dhcpc->last_msg_type = DHCPRELEASE;
	dhcp_init_options_set(&opts_set, (uint8_t*) out_msg, DHCPRELEASE, 0);
	const uint8_t *mac_addr = mac_get_bytes(eth_get_mac_addr());
	dhcp_add_client_identifier(&opts_set, mac_addr);
	dhcp_add_server_id(&opts_set, dhcpc->server_ip);

	int ret = dhcp_close_options_set(&opts_set);
	uint16_t out_msg_len = sizeof(DhcpMsg) - (DHCP_MIN_OPTIONS_LEN) + ret;

	ret = net_send_udp(dhcpc->server_ip, DHCP_BOOTP_CLIENT_PORT,
			   DHCP_BOOTP_SERVER_PORT, out_msg, out_msg_len,
			   UDP_SEND_INETCONTROL);

	DBG("[DHCP] release sent: %i\n", ret);
	free(dhcpc);
	dhcpc = NULL;
	return ret;
}

/* Send a DHCPDECLINE to let the server know that the IP we got is
 * already taken. */
static int
dhcp_send_decline(void)
{
	if (!dhcpc)
		return -DHCP_ERR_NO_CLIENT;

	/* Clean up last_out_msg */
	DhcpMsg *out_msg = &dhcpc->last_out_msg;
	out_msg->xid = rand();
	out_msg->secs_elapsed = 0;
	out_msg->client_ipaddr = 0;
	out_msg->offered_ipaddr = 0;
	out_msg->server_ipaddr = 0;
	out_msg->relay_ipaddr = 0;
	memset(out_msg->client_hwaddr + ETH_ADDR_LEN, 0,
	       DHCP_CLIENT_HW_ALEN - ETH_ADDR_LEN +
	       DHCP_SERVER_HOSTNAME_LEN + DHCP_FILENAME_LEN + DHCP_MIN_OPTIONS_LEN);

	/* Add options */
	DhcpOpts opts_set = {0};
	dhcpc->last_msg_type = DHCPDECLINE;
	dhcp_init_options_set(&opts_set, (uint8_t*) out_msg, DHCPDECLINE, 0);
	const uint8_t *mac_addr = mac_get_bytes(eth_get_mac_addr());
	dhcp_add_client_identifier(&opts_set, mac_addr);
	dhcp_add_server_id(&opts_set, dhcpc->server_ip);
	dhcp_add_requested_ip_addr(&opts_set, dhcpc->client_ip);
	int ret = dhcp_close_options_set(&opts_set);
	uint16_t out_msg_len = sizeof(DhcpMsg) - (DHCP_MIN_OPTIONS_LEN) + ret;

	ret = net_send_udp(dhcpc->server_ip, DHCP_BOOTP_CLIENT_PORT,
			   DHCP_BOOTP_SERVER_PORT, out_msg, out_msg_len,
			   UDP_SEND_INETCONTROL);
	return ret;
}

/* Note: We'll only be at the SELECTING state when sending DHCPREQUEST messages,
 * we won't be renewing/rebinding our ip (we 'll release it much sooner than
 * our lease time, right before we move on to the next boot stage), and we won't
 * be asking for our previously assigned ip in init-reboot state, since we are
 * in the boot phase and we never got one. See RFC2131 section 4.3.2 for what
 * we should do. */
static int
dhcp_send_request(uint32_t offered_ip)
{
	if (!dhcpc)
		return -DHCP_ERR_NO_CLIENT;
	uint16_t secs_elapsed = dhcp_get_elapsed_sec();

	/* Just update the fields from our DHCPDISCOVER */
	DhcpMsg *out_msg = &dhcpc->last_out_msg;
	out_msg->secs_elapsed = htons(secs_elapsed);
	/* Make sure the fields that may contain options are empty. */
	memset(out_msg->server_hostname, 0,
	       DHCP_SERVER_HOSTNAME_LEN + DHCP_FILENAME_LEN + DHCP_MIN_OPTIONS_LEN);

	/* Add options */
	DhcpOpts opts_set = {0};
	dhcpc->last_msg_type = DHCPREQUEST;
	dhcp_init_options_set(&opts_set, (uint8_t*) out_msg, DHCPREQUEST,
			      dhcpc->use_option_overload);
	const uint8_t *mac_addr = mac_get_bytes(eth_get_mac_addr());
	dhcp_add_client_identifier(&opts_set, mac_addr);
	dhcp_add_vendor_identifier(&opts_set);
	dhcp_add_hostname(&opts_set, mac_addr);
	dhcp_add_parameter_req_list(&opts_set, dhcpc->want_tftp);
	dhcp_add_requested_ip_addr(&opts_set, offered_ip);
	dhcp_add_server_id(&opts_set, dhcpc->server_ip);
	dhcp_add_max_msg_len(&opts_set);

	int ret = dhcp_close_options_set(&opts_set);
	uint16_t out_msg_len = sizeof(DhcpMsg) - (DHCP_MIN_OPTIONS_LEN) + ret;

	return dhcp_reliable_exchange(out_msg_len, DHCPACK, NULL);
}

/* Enter SELECTING state, note that we may receive multiple offers from different
 * DHCP servers in the network. Typically the authoritative DHCP server will reply
 * first and others will follow. In our case we'll grab the first offer we get,
 * make sure it contains the TFTP server ip if that was requested (or else we
 * won't be able to boot), and move on. This behaviour is implementation
 * specific anyways, it's the default one in most cases, and included in the RFC
 * as an accepted approach. After all, all DHCP servers in the network should
 * be able to provide us with the same infos unless we have a rogue DHCP
 * server trying to take over, in which case it's the network administrator's
 * job to figure it out and fix it. We could wait for more replies and do
 * further checks but DHCP is not focused on security anyway, and we don't
 * want to stall the boot process waiting until a timeout occurs. */
static int
dhcp_process_offer(const uint8_t *in_buff)
{
	if (!dhcpc)
		return -DHCP_ERR_NO_CLIENT;

	if (!in_buff)
		return -ENODATA;
	const DhcpMsg *in_msg = (DhcpMsg*) in_buff;

	/* Make sure we got a valid DHCPOFFER */
	int ret = dhcp_reply_validate(in_buff, DHCPOFFER);
	if (ret < 0)
		return ret;
	uint32_t server_ip = ret;
	uint32_t offered_ip = net_get_u32(&in_msg->offered_ipaddr);

	/* Check if we got subnet mask from the server, we need this
	 * to make sure that we are on the same subnet as the TFTP
	 * server (or any other server we decide to talk to), or
	 * do we need to go through a router to reach it. */
	ret = dhcp_grab_option_offset(in_buff, DHCP_SUBNET_MASK_OPTION);
	if (ret < 0)
		return ret;
	else if (!ret) {
		ERR("[DHCP] server didn't provide us with a subnet mask !\n");
		return -EPROTO;
	}
	uint32_t subnet_mask = net_get_u32(in_buff + ret + 2);

	/* If we went through a relay agent, its address must be in the same subnet
	 * as the offered IP address. */
	uint32_t in_relay_ipaddr = net_get_u32(&in_msg->relay_ipaddr);
	if (in_relay_ipaddr) {
		if ((offered_ip & subnet_mask) != (in_relay_ipaddr & subnet_mask)) {
			ERR("[DHCP] relay belongs to a different subnet !\n");
			return -EINVAL;
		}

		DBG("[DHCP] relay's IP address: %s\n", inet_print_ipv4(in_relay_ipaddr));
		dhcpc->relay_ip = in_relay_ipaddr;
	}

	/* Grab the routers list and get the first one. The list is sorted
	 * by preference so the default gw is the first one. Note that this
	 * is not fatal, we can get away with it in case we only end up
	 * talking to servers inside our subnet. */
	uint32_t gw_ipaddr = 0;
	ret = dhcp_grab_option_offset(in_buff, DHCP_ROUTER_OPTION);
	if (ret < 0)
		return ret;
	else {
		gw_ipaddr = net_get_u32(in_buff + ret + 2);
		/* Just in case, make sure we'll be on the same subnet as the default gw */
		if ((offered_ip & subnet_mask) != (gw_ipaddr & subnet_mask)) {
			WRN("[DHCP] we don't belong in the same subnet as the default gw !\n");
			gw_ipaddr = 0;
		}
	}

	/* Grab the TFTP server infos if requested */
	uint32_t tftp_server_ip = 0;
	const char* boot_filename = NULL;
	if (dhcpc->want_tftp) {
		/* The TFTP option is more explicit and overrides the "next server"
		 * field if present. The "next server" field is not nesecarily a TFTP
		 * server, just the next server on the boot chain, it could e.g. be
		 * an NFS server. */
		uint32_t in_server_ipaddr = net_get_u32(&in_msg->server_ipaddr);
		ret = dhcp_grab_option_offset(in_buff, DHCP_TFTP_SERVER_IP_OPTION);
		if (ret < 0)
			return ret;
		else if (ret) {
			tftp_server_ip = net_get_u32(in_buff + ret + 2);
			DBG("[DHCP] TFTP server IP: %s\n", inet_print_ipv4(tftp_server_ip));
		} else if (in_server_ipaddr) {
			tftp_server_ip = in_server_ipaddr;
			DBG("[DHCP] next server IP: %s\n", inet_print_ipv4(tftp_server_ip));
		}

		if (tftp_server_ip) {
			/* Figure out how are we going to reach the TFTP server.
			 * First check if it's on the same subnet as our offered IP. */
			if ((offered_ip & subnet_mask) != (tftp_server_ip & subnet_mask)) {
				/* Is there a static route for reaching the server instead of the default gw ? */
				uint32_t tftp_gw_ipaddr = 0;
				ret = dhcp_get_static_route_for_ip(in_buff, tftp_server_ip, &tftp_gw_ipaddr);
				if (ret < 0)
					return ret;
				if (tftp_gw_ipaddr) {
					/* Make sure we'll be able to reach the provided gatewey, otherwise
					 * fallback to the default gw (and fail later on if we don't have one). */
					if ((offered_ip & subnet_mask) != (tftp_gw_ipaddr & subnet_mask)) {
						DBG("[DHCP] we don't belong in the same subnet as the static tftp gw, ignoring it\n");
					} else
						gw_ipaddr = tftp_gw_ipaddr;
				}
			}

			/* Check if we got a boot filename, first look for option 67, otherwise if options
			 * overloading is not there / doesn't extend to boot_filename field, use that instead. */
			ret = dhcp_grab_option_offset(in_buff, DHCP_BOOTFILE_NAME_OPTION);
			if (ret < 0)
				return ret;
			if (ret) {
				uint8_t filename_len = in_buff[ret + 1];
				if (filename_len >= DHCP_BOOTFILE_NAME_MAX_LEN) {
					ERR("[DHCP] received boot filename length too long\n");
					return -EINVAL;
				}
				memcpy(dhcpc->boot_filename, in_buff + ret + 2, filename_len);
				dhcpc->boot_filename[filename_len] = '\0';
				boot_filename = dhcpc->boot_filename;
			} else {
				uint8_t overload_type = 0;
				ret = dhcp_grab_option_offset(in_buff, DHCP_OPTION_OVERLOAD_OPTION);
				if (ret < 0)
					return ret;
				else if (ret > 0)
					overload_type = in_buff[ret + 2];

				if (!ret || overload_type == DHCP_OPTIONS_OVERLOAD_SNAME) {
					ret = strnlen(in_msg->boot_filename, DHCP_FILENAME_LEN);
					if (ret > 0 && ret < DHCP_FILENAME_LEN) {
						memcpy(dhcpc->boot_filename, in_msg->boot_filename, ret);
						dhcpc->boot_filename[ret] = '\0';
						boot_filename = dhcpc->boot_filename;
					}
				}
			}
		}
	}

	/* We got a valid offer so we should accept it to let the servers in the network
	 * know about it and stop waiting for us / free up resources. We can then decide
	 * if we want to keep that offer or decline it via a DHCPDECLINE message. That would
	 * help in identifying any issues on the server / administrator's side, and it's a
	 * better policy / behavior than just droping the offer and let everyone in the
	 * network wonder about it. */

	/* We are now in SELECTING state so select the server and its offer. */
	dhcpc->server_ip = server_ip;
	dhcpc->subnet_mask = subnet_mask;
	ret = dhcp_send_request(offered_ip);
	if (ret < 0)
		return ret;

	/* We are now in BOUND state */
	dhcpc->client_ip = offered_ip;

	/* See if we should keep that offer or decline it, first check if we
	 * got a tftp server address as expected. */
	if (dhcpc->want_tftp && !tftp_server_ip) {
		ERR("[DHCP] server didn't provide us with a TFTP server IP !\n");
		dhcp_send_decline();
		return -EDESTADDRREQ;
	}

	/* Next check if our IP address is already used by someone else by
	 * doing an ARP request for it and check that nobody answers. */
	mac_addr_t dmac = {0};
	ret = net_send_arp_req(offered_ip, &dmac);
	if (!ret) {
		ERR("[DHCP] the IP we got is already being used !\n");
		dhcp_send_decline();
		return -EADDRINUSE;
	}

	/* All good, we are keeping the offer. The caller is expected to call
	 * dhcp_send_release when done to let the server know so that it can
	 * release the offered IP. */
	INF("[DHCP] Accepted address: %s\n", inet_print_ipv4(offered_ip));
	/* Only unicast from now on */
	net_set_broadcast_filter(1);

	/* Update network config, and if that fails send a DHCPDECLINE and go back
	 * to the INIT state. */
	net_update_config(offered_ip, subnet_mask, gw_ipaddr,
			  tftp_server_ip, boot_filename);

	return 0;
}

/*************\
* Entry point *
\*************/

int
dhcp_send_discover(int use_option_overload, int want_tftp)
{
	/* Initialize client's state */

	/* This could be the start of a new session (first try)
	 * or a retry. We are expected to maintain a secs_elapsed
	 * counter across retries, so before cleaning up the client's
	 * state, save the session's start from the existing state and
	 * copy it over. */
	clock_t session_start = 0;
	uint16_t secs_elapsed = 0;
	if (!dhcpc) {
		dhcpc = malloc(sizeof(struct dhcp_state));
		if (!dhcpc)
			return -ENOMEM;
		session_start = clock();
	} else {
		session_start = dhcpc->session_start;
		secs_elapsed = dhcp_get_elapsed_sec();
	}
	memset(dhcpc, 0, sizeof(struct dhcp_state));
	dhcpc->use_option_overload = use_option_overload;
	dhcpc->want_tftp = want_tftp;
	dhcpc->session_start = session_start;


	/* We are at the INIT-REBOOT state, prepare our DHCPDISCOVER message.
	 * Note that we'll reuse this later on so that we don't re-add hwaddr etc. */
	DhcpMsg *out_msg = &dhcpc->last_out_msg;
	out_msg->op = DHCP_OP_BOOTREQUEST;
	out_msg->hw_addr_type = ARP_HTYPE_ETHER;
	out_msg->hw_addr_len = ETH_ADDR_LEN;
	out_msg->hops = 0;
	out_msg->xid = rand();
	out_msg->secs_elapsed = htons(secs_elapsed);
	out_msg->flags = 0;
	out_msg->client_ipaddr = 0;
	out_msg->offered_ipaddr = 0;
	out_msg->server_ipaddr = 0;
	out_msg->relay_ipaddr = 0;
	mac_addr_t *client_mac = eth_get_mac_addr();
	mac_copy_bytes(out_msg->client_hwaddr, client_mac);
	/* Zero pad the remaining hwaddr field, and clean up
	 * the rest of the message buffer. */
	memset(out_msg->client_hwaddr + ETH_ADDR_LEN, 0,
	       DHCP_CLIENT_HW_ALEN - ETH_ADDR_LEN +
	       DHCP_SERVER_HOSTNAME_LEN + DHCP_FILENAME_LEN + DHCP_MIN_OPTIONS_LEN);

	/* Add options */
	DhcpOpts opts_set = {0};
	dhcpc->last_msg_type = DHCPDISCOVER;
	dhcp_init_options_set(&opts_set, (uint8_t*) out_msg, DHCPDISCOVER, use_option_overload);
	dhcp_add_client_identifier(&opts_set, mac_get_bytes(client_mac));
	dhcp_add_vendor_identifier(&opts_set);
	dhcp_add_hostname(&opts_set, mac_get_bytes(client_mac));
	dhcp_add_parameter_req_list(&opts_set, want_tftp);
	dhcp_add_max_msg_len(&opts_set);

	/* Done, get total message length */
	int ret = dhcp_close_options_set(&opts_set);
	uint16_t out_msg_len = sizeof(DhcpMsg) - (DHCP_MIN_OPTIONS_LEN) + ret;

	INF("[DHCP] Sending discovery...\n");

	/* Even though the server/relay will see our MAC address, and we don't set
	 * the broadcast flag in out_msg->flags, it may still choose to broadcast
	 * its DHCPOFFER not only on layer 3 (using the bcast IP address) but also
	 * on layer 2. Disable the broadcast filter so that we can see the reply. */
	net_set_broadcast_filter(0);

	/* Wait a random number of secs/msecs to respect RFC2131 recommendation in
	 * section 4.4.1 for sending the first message to desynchronize the use of
	 * DHCP at startup. Note that in case we don't have any entropy sources or
	 * unique identifiers available during the init phase of rand(), we'll always
	 * get the same values here. */
	uint8_t delay_secs = 1;
	uint32_t delay_msecs = (rand() & 0x3E0UL);	// 0 - 992 (multiples of 32)
	struct timespec ts_delay = { .tv_sec = delay_secs,
				     .tv_nsec = delay_msecs * 1000ULL * 1000ULL};
	nanosleep(&ts_delay, NULL);

	ret = dhcp_reliable_exchange(out_msg_len, DHCPOFFER, &dhcp_process_offer);
	if (ret < 0)
		DBG("[DHCP] session failed: %i\n", ret);
	return ret;
}
