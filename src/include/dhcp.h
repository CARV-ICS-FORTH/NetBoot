/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2023 Nick Kossifidis <mick@ics.forth.gr>
 * SPDX-FileCopyrightText: 2023 ICS/FORTH
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _DHCP_H
#define _DHCP_H

#include <stdint.h>	/* For typed integers */
#include <assert.h>	/* For static_assert */
#include <time.h>	/* For clock_t */

#define DHCP_BOOTP_SERVER_PORT 67
#define DHCP_BOOTP_CLIENT_PORT 68

/* Note: Keep them below 32 octets so that we don't overflow
 * the file field in case we do options overloading. Also note
 * that the hostname is padded with the last two bytes of the
 * MAC address in order to be unique among instances, so 
 * it's 32 - 4 for hostname. The compiler will refuse to
 * compile this if the above limitations are not respected. */
#define VENDOR_IDENTIFIER "FORTH/CARV-BROM-01"
#define CLIENT_HOSTNAME "sdv3-bootrom-"


/*********************\
* DHCP Message format *
\*********************/

/* A DHCP Message as per RFC2131 */
#define DHCP_CLIENT_HW_ALEN 16
#define DHCP_SERVER_HOSTNAME_LEN 64
#define DHCP_FILENAME_LEN 128
/* According to the RFC2131 section 2, this is the minimum
 * length of the options field a client should be able to handle.
 * It can't go below that since RFC1122 defines 576 as the
 * minimum datagram size a host should be able to handle and
 * we already have 20bytes for the IP header and 8 for the UDP,
 * so that leaves us with with 548 for the DHCP message. All
 * fixed-lenght fields up to options are 264, so what's left for
 * options is 548 - 236 = 312. */
#define DHCP_MIN_OPTIONS_LEN 312
struct dhcp_message {
	uint8_t op;
	uint8_t hw_addr_type;
	uint8_t hw_addr_len;
	uint8_t hops;
	uint32_t xid;		// Unaligned
	uint16_t secs_elapsed;
	uint16_t flags;
	uint32_t client_ipaddr;	// Unaligned
	uint32_t offered_ipaddr;// Unaligned
	uint32_t server_ipaddr;	// Unaligned
	uint32_t relay_ipaddr;	// Unaligned
	uint8_t client_hwaddr[DHCP_CLIENT_HW_ALEN];	// [70:85]
	char server_hostname[DHCP_SERVER_HOSTNAME_LEN];	// [86:149]
	char boot_filename[DHCP_FILENAME_LEN];	// [150:277]
	uint8_t options[DHCP_MIN_OPTIONS_LEN];	// [278:]
}__attribute__ ((__packed__));
typedef struct dhcp_message DhcpMsg;

/* Possible values of the ops field */
enum {
	DHCP_OP_BOOTREQUEST = 1,
	DHCP_OP_BOOTREPLY = 2,
};

/* Only one flag defined for now */
enum {
	DHCP_FLAG_BROADCAST = 1 << 15
};

#define DHCP_MAGIC_COOKIE_0  0x63
#define DHCP_MAGIC_COOKIE_1  0x82
#define DHCP_MAGIC_COOKIE_2  0x53
#define DHCP_MAGIC_COOKIE_3  0x63

/**************\
* DHCP Options *
\**************/

/* Note: According to RFC2131 section 4.1 options may only appear
 * once unless noted otherwise. To track down the options we
 * add/receive, we define for each option that may only be
 * present once (most of them) a flag in a 32bit integer.
 * There are obviously way more than 32 options out there but
 * we only care for those we know (this is a simple client
 * after all, no vendor specific stuff, no dns/ntp/smtp etc
 * handling) and are able to handle. So keep in mind to keep
 * known/handled extensions up to 32 or else change the integer
 * for tracking them to 64bits.
 */

struct dhcp_options_set {
	uint8_t *msg_buff;
	uint8_t *options_buff;
	uint32_t options_buff_len;
	uint32_t options_set;
	uint16_t offset;
	uint8_t overload_type;
	uint8_t overload_type_offset;
	uint8_t msg_options_len;
};
typedef struct dhcp_options_set DhcpOpts;

void dhcp_init_options_set(DhcpOpts *opts_set, uint8_t* msg_buff,
			  uint8_t msg_type, int overload);
int dhcp_close_options_set(DhcpOpts *opts_set);
int dhcp_grab_option_offset(const uint8_t *msg_buff, uint8_t option_id);

/* PAD/END options, RFC2132 section 3.1/3.2
 * These are the only 1octet long options, all the rest are followed
 * by a length field. The PAD option may be used multiple times to
 * PAD option fields if needed, the END option is used once on each
 * field containig options. */
#define DHCP_OPTION_PAD 0
#define DHCP_OPTION_END	0xFF

/* Subnet mask, RFC2132 section 3.3
 * This is sent by the server in case we added subnet mask in the
 * parameter request list. */
#define DHCP_SUBNET_MASK_OPTION 1
#define DHCP_SUBNET_MASK_LEN 4
#define DHCP_SUBNET_MASK_OPTION_BIT	1

/* Router option, RFC2132 section 3.5
 * Note this is a list of routers so it's variable length,
 * the only restriction is that length is a multiple of 4
 * (the size of an IPv4 address). Since the list is ordered
 * by preference, the default gw is always the first one. */
#define DHCP_ROUTER_OPTION 3
#define DHCP_ROUTER_OPTION_ELEMENT_LEN 4
#define DHCP_ROUTER_OPTION_BIT		1 << 1

/* (client) Host Name option, RFC2132 section 3.14
 * We use this to notify DHCP server, and possibly the DNS server
 * too (which would be helpfull when cheking out server logs) of
 * our hostname. This is also a way to verify that the DHCP server
 * actually reads our options field and doesn't blindly respond,
 * since it'll probably send this back in case it reads it.*/
#define DHCP_HOSTNAME_OPTION 12
#define DHCP_HOSTNAME_MAX_LEN 32 - 4
#define DHCP_HOSTNAME_OPTION_BIT	1 << 2
#ifndef CLIENT_HOSTNAME
	#define DHCP_HOSTNAME ""
#else
	#define DHCP_HOSTNAME CLIENT_HOSTNAME
#endif
static_assert((sizeof(DHCP_HOSTNAME) <= DHCP_HOSTNAME_MAX_LEN),
	      "Hardcoded hostname is larger than expected");
void dhcp_add_hostname(DhcpOpts *opts_set, const uint8_t* mac_addr);

/* Boot file size (in multiples of 512octets), RFC2132 section 3.15 */
#define DHCP_BOOTFILE_SIZE_OPTION 13
#define DHCP_BOOTFILE_SIZE_LEN 2
#define DHCP_BOOTFILE_SIZE_OPTION_BIT	1 << 3

/* Static route option, RFC2132 section 5.8
 * This is a list of ip/router pairs (so its length must be a multiple of 8)
 * and we need to know about it in case the server is reached via a static
 * route. */
#define DHCP_STATIC_ROUTE_OPTION 33
#define DHCP_STATIC_ROUTE_ELEMENT_LEN 8
#define DHCP_STATIC_ROUTE_OPTION_BIT	1 << 4
int dhcp_get_static_route_for_ip(const uint8_t* buff, uint32_t addr, uint32_t *gw_addr);

/* Requested IP address, RFC2132 section 9.1
 * Client may send this to indicate a prefered IP address on DHCPDISCOVER
 * (we don't do that), but it also needs to send it after the server has
 * offered an IP, to indicate which ip the client accepted. */
#define DHCP_REQUESTED_IP_OPTION 50
#define DHCP_REQUESTED_IP_LEN 4
#define DHCP_REQUESTED_IP_OPTION_BIT	1 << 5
void dhcp_add_requested_ip_addr(DhcpOpts *opts_set, uint32_t ip_addr);

/* IP lease time in seconds, RFC2132 section 9.2 (UNSUPPORTED)
 * Usually we'll be done long before the lease is over but we keep
 * this arround so that we can parse/verify it. */
#define DHCP_LEASE_TIME_SECS_OPTION 51
#define DHCP_LEASE_TIME_SECS_LEN 4
#define DHCP_LEASE_TIME_SECS_OPTION_BIT	1 << 6

/* Option overload, RFC2132 section 9.3
 * This tells the client/server to look for options in the sname/file
 * fields as well in case they are unused.
 *
 * Note that the client is required by RFC2131 to support up to 312
 * octets in the options field which seem more than enough, especially
 * in our case where we'll be asking for just a few options from the
 * server.
 *
 * However this restriction doesn't mean that the client/server has
 * to transmit the whole options field, we are still allowed to send packets
 * smaller than that (there is a MAY there in the RFC regarding the padding
 * of the options field) and put options in the sname/file fields in case
 * they are unused which is a good thing.
 *
 * Note that the client may only ask for the server's name and
 * not the file (which may have a standard name hardcoded on the
 * client's side), so the search order mandated by RFC2131, that also
 * matches the values in the overload option field, is first to look
 * at the file field (which is also much larger than sname), and then
 * the sname field. This sucks a bit in case both fields are used,
 * since they are next to each other and they could be treated as one
 * field in case both of them are being used, but whatever, I can live
 * with that.
 */
#define DHCP_OPTION_OVERLOAD_OPTION 52
#define DHCP_OPTION_OVERLOAD_LEN 1
#define DHCP_OPTION_OVERLOAD_OPTION_BIT	1 << 7
enum {
	DHCP_OPTIONS_OVERLOAD_FILE = 1,
	DHCP_OPTIONS_OVERLOAD_SNAME = 2,
	DHCP_OPTIONS_OVERLOAD_BOTH = 3,
};

/* TFTP server name, RFC2132 section 9.4 (UNSUPPORTED)
 * It's better that we know about this (and maybe print it out) but
 * we won't do any DNS requests to get its address so ignore it for now.
 * We'll use the TFTP IP address option (see) below. */
#define DHCP_TFTP_SERVER_NAME_OPTION 66
#define DHCP_TFTP_SERVER_NAME_OPTION_BIT 1 << 8

/* Boot file name, RFC2132 section 9.5
 * Note that this is used when the normal file field is used for
 * options overloading. I guess it makes sense to define a max
 * length the same as the file field, although the RFC doesn't
 * specify this. */
#define DHCP_BOOTFILE_NAME_OPTION 67
#define DHCP_BOOTFILE_NAME_MAX_LEN DHCP_FILENAME_LEN
#define DHCP_BOOTFILE_NAME_OPTION_BIT	1 << 9

/* Message type, RFC2132 section 9.6
 * Message types explained in RFC2131 section 3.1 */
#define DHCP_MESSAGE_TYPE_OPTION 53
#define DHCP_MESSAGE_TYPE_LEN 1
#define DHCP_MESSAGE_TYPE_OPTION_BIT	1 << 10
enum {
	DHCPDISCOVER = 1,
	DHCPOFFER = 2,
	DHCPREQUEST = 3,
	DHCPDECLINE = 4,
	DHCPACK = 5,
	DHCPNAK = 6,
	DHCPRELEASE = 7,
	DHCPINFORM = 8
};
/* Added by dhcp_init_options_set() */

/* Server identifier option, RFC2132 section 9.7
 * That's the IP of the DHCP server so that we can use it for
 * unicast messages after DHCPOFFER. */
#define DHCP_SERVER_ID_OPTION 54
#define DHCP_SERVER_ID_LEN 4
#define DHCP_SERVER_ID_OPTION_BIT	1 << 11
void dhcp_add_server_id(DhcpOpts *opts_set, uint32_t ip_addr);

/* Parameter request option, RFC2132 section 9.8
 * Full list of parameters (matching option ids):
 * https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.txt
 */
#define DHCP_PARAMETER_REQUEST_OPTION 55
#define DHCP_PARAMETER_REQUEST_OPTION_BIT 1 << 12
void dhcp_add_parameter_req_list(DhcpOpts *opts_set, int want_tftp);

/* (error) Message option, RFC2132 section 9.9
 * This is an error message sent by the server on a DHCPNACK or
 * a client in DHCPDECLINE. Keep it in mind in case we want to
 * print it. */
#define DHCP_MESSAGE_OPTION 56
#define DHCP_MESSAGE_OPTION_BIT		1 << 13

/* DHCP Maximum message length, RFC2132, section 9.10
 * We need this to let server know that we won't be accepting packets
 * larger than 576 bytes (which is what our dhcp_message struct can hold). */
#define DHCP_MAXIMUM_MESSAGE_LENGTH_OPTION 57
#define DHCP_MAXIMUM_MESSAGE_LENGTH_LEN 2
#define DHCP_MAXIMUM_MESSAGE_LENGTH_OPTION_BIT	1 << 14
void dhcp_add_max_msg_len(DhcpOpts *opts_set);

/* Renewal time, RFC2132 section 9.11 (UNSUPPORTED)
 * The server will probably send this to indicate how long should it
 * take for the client to reach RENEW state and renew its lease.
 * We don't realy care about it since it won't take that long to
 * boot (hopefully) and even if it does we still need to reach
 * REBIND state, and our lease time could be longer than that.
 * Still we keep it around for sanity checks if needed. */
#define DHCP_RENEWAL_TIME_OPTION 58
#define DHCP_RENEWAL_TIME_LEN 4
#define DHCP_RENEWAL_TIME_OPTION_BIT	1 << 15


/* Rebind time, RFC2132 section 9.12 (UNSUPPORTED)
 * Same as above but for reaching the REBIND state */
#define DHCP_REBINDING_TIME_OPTION 59
#define DHCP_REBINDING_TIME_LEN 4
#define DHCP_REBINDING_TIME_OPTION_BIT	1 << 16

/* Vendor class identifier, RFC2132 section 9.13
 * We use this to provide the DHCP server infos regarding the
 * software being used on the client side, and also to
 * verify DHCPNACKs since it's one of the few options allowed
 * there. */
#define DHCP_VENDOR_CLASS_ID_OPTION 60
#define DHCP_VENDOR_CLASS_ID_MAX_LEN 32
#define DHCP_VENDOR_CLASS_ID_OPTION_BIT	1 << 17
#ifndef VENDOR_IDENTIFIER
	#define DHCP_VENDOR_CLASS_ID_STRING ""
#else
	#define DHCP_VENDOR_CLASS_ID_STRING VENDOR_IDENTIFIER
#endif
static_assert((sizeof(DHCP_VENDOR_CLASS_ID_STRING) <= DHCP_VENDOR_CLASS_ID_MAX_LEN),
	      "Hardcoded vendor class id string is larger than expected");
void dhcp_add_vendor_identifier(DhcpOpts *opts_set);

/* Client identifier option, RFC2132 section 9.14
 * In our case we use our MAC address and follow the recommendations
 * on RFC4361 section 6.1, creating a DUID based on our MAC address. */
#define DHCP_CLIENT_ID_OPTION 61
#define DHCP_CLIENT_ID_OPTION_BIT	1 << 18
void dhcp_add_client_identifier(DhcpOpts *opts_set, const uint8_t* mac_addr);


/* DHCP TFTP server address option, RFC5859
 * We use this since we don't want to rely on DNS for resolving
 * the server's name from the sname field of dhcp message, this
 * will instead provide us with the IP address of the TFTP server
 * directly. It may include multiple IPs for reduntancy so its
 * length is not fixed, but it should be a multiple of 4, like
 * in the router option. */
#define DHCP_TFTP_SERVER_IP_OPTION 150
#define DHCP_TFTP_SERVER_IP_ELEMENT_LEN 4

/* TODO: Rapid Config option, RFC4039 */

/************************************\
* DHCP CLIENT STATE AND ENTRY POINTS *
\************************************/

struct dhcp_state {
	DhcpMsg last_out_msg;
	uint32_t client_ip;
	DhcpMsg *last_in_msg;
	uint32_t server_ip;
	uint32_t relay_ip;
	clock_t session_start;
	char boot_filename[DHCP_BOOTFILE_NAME_MAX_LEN];
	uint32_t subnet_mask;
	uint8_t last_msg_type;
	uint8_t use_option_overload;
	uint8_t want_tftp;
};

typedef struct dhcp_state DhcpState;


int dhcp_send_discover(int use_option_overload, int want_tftp);
int dhcp_send_release(void);

#endif /* _DHCP_H */