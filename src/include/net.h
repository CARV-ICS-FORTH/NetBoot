/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2023 Nick Kossifidis <mick@ics.forth.gr>
 * SPDX-FileCopyrightText: 2023 ICS/FORTH
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _NET_H
#define _NET_H

#include <stdint.h>	/* For typed integers */
#include <stdlib.h>	/* For rand() */
#include <stddef.h>	/* For size_t */

/*
 * Note: we can't use any system headers, only standard C stuff
 * (there is no OS in bare metal), so we need to re-define a few
 * things here.
 */

/* Normaly part of sys/types.h */
typedef long int ssize_t;

/* We'll only be handling simple Ethernet II frames, no 802.1Q VLAN
 * tags or Q-in-Q (802.1ad), 802.3 frames (with length instead of
 * ethertype + 802.2LLC + SNAP header), MACSec, jumbo frames, or
 * anything fancy.
 *
 * For such a frame we need:
 * eth_hdr(14) + MTU(1500) + (in case NIC exposes it to sw) FCS(4)
 * so 1518 and to keep it 8byte aligned 1520.
 */
#define RX_BUFF_SIZE	1520
#define TX_BUFF_SIZE	1520


/****************\
* TIMEOUT POLICY *
\****************/

/* Timeout for receiveng an ethernet frame (note that this
 * may use mtimer/wfi and we may have low timer resolution) */
#define RX_ETH_TIMEOUT_MSEC	32
/* Timeout for sending out an ethernet frame. This is an overkill,
 * if nic can't send a frame within 1ms something is seriously wrong,
 * even in FPGA scenarios with slow clocks etc. */
#define TX_ETH_TIMEOUT_MSEC	1
/* How many times we'll poll the nic before giving up. Each poll
 * has its own timeout at the hardware layer. This creates a total
 * timeout of roughly RX_NET_POLLS * RX_ETH_TIMEOUT_MSEC on an idle
 * network. */
#define RX_NET_POLLS		8
#define RX_NET_TIMEOUT_IDLE_MSEC	(RX_NET_POLLS * RX_ETH_TIMEOUT_MSEC)
/* Keep that timeout less than 500ms */
_Static_assert(RX_NET_TIMEOUT_IDLE_MSEC < 500, "RX_NET_TIMEOUT_IDLE_MSEC must be < 500");

/* Ethernet polling intervals - tuned for Gigabit networks
 *
 * TX polling (50μs): We're waiting for our own frame to transmit, which is fast.
 * Even at worst case (minimum 64-byte frame on Gigabit), transmission takes ~0.5μs.
 * We poll every 50μs to quickly detect completion or errors without hammering hardware.
 *
 * RX polling (100μs): On Gigabit Ethernet, theoretical maximum is ~1.5M packets/sec
 * (minimum frames) or ~81K packets/sec (typical 1500-byte frames). In a 100μs window,
 * that's up to ~148 minimum frames or ~8 typical frames. On a switched network during
 * netboot, we'll see much less - primarily our TFTP DATA blocks plus occasional broadcasts.
 * Polling every 100μs can handle sustained line-rate traffic while being gentle on slow
 * hardware timers (works with 10kHz RTCs).
 *
 * Note: The timespec structs are initialized in net.c and declared as extern here so that
 * they are being reused from .rodata.
 */
extern const struct timespec eth_rx_poll_delay;		/* 100μs for RX */
extern const struct timespec eth_tx_poll_delay;		/* 50μs for TX */
#define RX_ETH_RETRIES	RX_ETH_TIMEOUT_MSEC * 10	// 10 * 100μs = 1ms
#define TX_ETH_RETRIES	TX_ETH_TIMEOUT_MSEC * 20	// 20 * 50μs = 1ms


/*********\
* Helpers *
\*********/
#define bswap16(x)	((((x) >> 8) & 0xff) | (((x) & 0xff) << 8))
#define ntohs(x)	bswap16(x)
#define htons(x)	bswap16(x)

/* Read uint16/32_t from potentially unaligned address */
static inline uint16_t net_get_u16(const void *buff)
{
	uint16_t val;
	uint8_t *v = (uint8_t *)&val;
	const uint8_t *p = (const uint8_t *)buff;
	v[0] = p[0];
	v[1] = p[1];
	return val;
}

static inline uint32_t net_get_u32(const void *buff)
{
	uint32_t val;
	uint8_t *v = (uint8_t *)&val;
	const uint8_t *p = (const uint8_t *)buff;
	v[0] = p[0];
	v[1] = p[1];
	v[2] = p[2];
	v[3] = p[3];
	return val;
}

/* Write uint16/32_t to potentially unaligned buffer */
static inline void net_set_u16(uint16_t val, void *buff)
{
	uint8_t *p = (uint8_t *)buff;
	const uint8_t *v = (const uint8_t *)&val;
	p[0] = v[0];
	p[1] = v[1];
}

static inline void net_set_u32(uint32_t val, void *buff)
{
	uint8_t *p = (uint8_t *)buff;
	const uint8_t *v = (const uint8_t *)&val;
	p[0] = v[0];
	p[1] = v[1];
	p[2] = v[2];
	p[3] = v[3];
}

/* Same for aligned accesses with a check during debug just in case */
static inline uint16_t net_get_u16_aligned(const void *buff)
{
	/* Assert alignment in debug builds */
	#ifdef NET_DEBUG
	if ((uintptr_t)buff & 0x1)
		ERR("[NET] Unaligned u16 access at %p!\n", buff);
		/* Could trap here in debug mode */
	#endif
	return *((const uint16_t *)buff);
}

static inline uint32_t net_get_u32_aligned(const void *buff)
{
	#ifdef NET_DEBUG
	if ((uintptr_t)buff & 0x3)
		ERR("[NET] Unaligned u32 access at %p!\n", buff);
	#endif
	return *((const uint32_t *)buff);
}

static inline void net_set_u16_aligned(uint16_t val, void *buff)
{
	#ifdef NET_DEBUG
	if ((uintptr_t)buff & 0x1)
		ERR("[NET] Unaligned u16 write at %p!\n", buff);
	#endif
	*((uint16_t *)buff) = val;
}

static inline void net_set_u32_aligned(uint32_t val, void *buff)
{
	#ifdef NET_DEBUG
	if ((uintptr_t)buff & 0x3)
		ERR("[NET] Unaligned u32 write at %p!\n", buff);
	#endif
	*((uint32_t *)buff) = val;
}

/**********\
* ETHERNET *
\**********/

/* Ethernet II header
 * Note: Ethernet packets will live in buffers allocated
 * with malloc, that'll always be aligned to pointer size.
 * Also note that we'll only RX/TX Ethernet II frames. */
#define ETH_ADDR_LEN	6
struct eth_hdr {
	uint8_t dst_mac[ETH_ADDR_LEN];
	uint8_t src_mac[ETH_ADDR_LEN];
	uint16_t ethertype;
} __attribute__ ((__packed__));

/* The ethertypes we'll use */
#define ETHERTYPE_IPV4	0x0800
#define ETHERTYPE_ARP	0x0806
#define ETH_MIN_FRM_LEN	64

/*****\
* ARP *
\*****/

/* IPv4 over Ethernet ARP packet
 * Note: This starts at offset 14 (eth_hdr is 0 -13)
 * so it's 2byte alligned. */
struct arp_ipv4oeth {
	uint16_t htype;
	uint16_t ptype;
	uint8_t hlen;
	uint8_t plen;
	uint16_t oper;
	uint8_t src_haddr[ETH_ADDR_LEN];
	uint8_t src_paddr[4];		// 4b aligned
	uint8_t dst_haddr[ETH_ADDR_LEN];// 4b aligned
	uint8_t dst_paddr[4];
} __attribute__ ((__packed__));

struct arp_frame {
	struct eth_hdr eth_hdr;
	struct arp_ipv4oeth arp_hdr;
	uint8_t padding[22];	// So that the ethernet frame is 64b
} __attribute__ ((__packed__));


/* ARP operations */
enum {
	ARP_REQUEST = 1,
	ARP_REPLY = 2,
};

/* The htype/ptype we'll use */
#define ARP_HTYPE_ETHER	1
#define ARP_PTYPE_IPV4	ETHERTYPE_IPV4


/******\
* IPv4 *
\******/

/* Standard IPv4 header
 * We don't expect any options from the DCHP/TFTP
 * server and we won't add any options either. In
 * general, IP options are a mess and usually filtered
 * or even droped (e.g. RFC6192). So in any case
 * the IPv4 header passed on to higher layers will
 * always have a fixed size (20bytes) and will start
 * at 14 after eth_hdr so it'll be 2-byte aligned.
 * That means all fields except src/dst addresses
 * are also aligned and can be accessed directly. */
struct ipv4_hdr {
	unsigned int ihl:4;
	unsigned int version:4;
	uint8_t tos;
	uint16_t tot_len;
	uint16_t id;
	uint16_t frag_off;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t hdr_csum;
	uint32_t src_addr;	// Unaligned
	uint32_t dst_addr;	// Unaligned
} __attribute__ ((__packed__));

#define IPV4_IHL	5	// In 32bit words
#define IPV4_VERSION	4
#define IPV4_MAX_LEN	65535
/* IP CS for Internetwork Control (ToS) */
#define IPV4_CLASS_SELECTOR_6	0xc0
#define IPV4_PROTO_UDP	17

/* Helper macro for constructing IPv4 addresses (big endian) */
#define IPV4_ADDR(a, b, c, d)	(((d & 0xff) << 24) | ((c & 0xff) << 16) | \
				 ((b & 0xff) << 8)  | (a & 0xff))

const char* inet_print_ipv4(uint32_t ip_addr);

/*****\
* UDP *
\*****/

/* UDP header
 * That's 2byte aligned (starting from 34) so all
 * uint16_t fields can be accessed directly, payload
 * remains 2byte aligned. */
struct udp_hdr {
	uint16_t sport;
	uint16_t dport;
	uint16_t dgram_len;
	uint16_t dgram_csum;
} __attribute__ ((__packed__));


struct udp_frame {
	struct eth_hdr eth_hdr;
	struct ipv4_hdr ip_hdr;
	struct udp_hdr udp_hdr;
} __attribute__ ((__packed__));

/* Flags when sending UDP packets */
enum {
	UDP_SEND_BCAST 		= 1,
	UDP_SEND_INETCONTROL	= 1 << 1,
};


/************************************\
* Helpers for mamaging MAC addresses *
\************************************/

/*
 * MAC address type - 6 bytes stored in uint64_t
 * The unused 2 bytes may be used by the driver inernally
 * and will be ignored / zeroed out when used from higher
 * layers.
 */
typedef union {
	uint64_t u64;
	uint8_t bytes[8];
} mac_addr_t;

static inline void mac_set_u64(mac_addr_t *mac, uint64_t val)
{
	mac->u64 = val & 0x0000FFFFFFFFFFFFULL;
}

static inline void mac_set_bytes(mac_addr_t *mac, const uint8_t *bytes)
{
	mac->u64 = 0;
	net_set_u32_aligned(net_get_u32(&bytes[0]), &mac->bytes[0]);
	net_set_u16_aligned(net_get_u16(&bytes[4]), &mac->bytes[4]);
}

static inline void mac_set_bytes_aligned(mac_addr_t *mac, const uint8_t *bytes)
{
	mac->u64 = 0;
	net_set_u32_aligned(net_get_u32_aligned(&bytes[0]), &mac->bytes[0]);
	net_set_u16_aligned(net_get_u16_aligned(&bytes[4]), &mac->bytes[4]);
}

static inline const uint8_t *mac_get_bytes(const mac_addr_t *mac)
{
	return &mac->bytes[0];
}

static inline void mac_copy(mac_addr_t *mac1, const mac_addr_t *mac2)
{
	mac1->u64 = mac2->u64;
}

static inline void mac_copy_bytes(uint8_t *outbuff, const mac_addr_t *mac)
{
	outbuff[0] = mac->bytes[0];
	outbuff[1] = mac->bytes[1];
	outbuff[2] = mac->bytes[2];
	outbuff[3] = mac->bytes[3];
	outbuff[4] = mac->bytes[4];
	outbuff[5] = mac->bytes[5];
}

static inline void mac_copy_bytes_aligned(uint8_t *outbuff, const mac_addr_t *mac)
{
	net_set_u32_aligned(net_get_u32_aligned(&mac->bytes[0]), &outbuff[0]);
	net_set_u16_aligned(net_get_u16_aligned(&mac->bytes[4]), &outbuff[4]);
}

static inline int mac_cmp(const mac_addr_t *mac1, const mac_addr_t *mac2)
{
	return (mac1->u64 != mac2->u64);
}

static inline int mac_is_broadcast(const mac_addr_t *mac)
{
	return (mac->u64 == 0x0000FFFFFFFFFFFFULL);
}

static inline void mac_set_broadcast(mac_addr_t *mac)
{
	mac->u64 = 0x0000FFFFFFFFFFFFULL;
}

static inline mac_addr_t mac_get_random(void)
{
	mac_addr_t mac;
	uint32_t rand1 = rand();  /* 32 bits for bytes 0-3 */
	uint32_t rand2 = rand();  /* 32 bits, we'll use 16 for bytes 4-5 */

	/* Fill octets with random bits, while folowing IEEE 802c */

	/* Clear I/G bit (this is a unicast address, not multicast)
	 * Set U/L bit (this is a localy administrated address,
	 * 		not a globally unique one)
	 * Leave bits 3,4 zeroed so that this becomes an AAI
	 * (Administratively Assigned Identifier)
	 */
	uint64_t mac_val = ((uint64_t)((rand1 & 0xF0) | 0x02)) |
			   (rand1 & 0xFFFFFF00ULL) |
			   ((uint64_t)(rand2 & 0xFFFF) << 32);

	mac_set_u64(&mac, mac_val);
	return mac;
}

/*************************************\
* ETHERNET NIC STATE AND ENTRY POINTS *
\*************************************/

/* These functions are implemented by the driver, note
 * that they are all blocking ops. */
int eth_open(void);
void eth_close(void);
uint8_t* eth_get_tx_buff(size_t size);
int eth_trigger_tx(size_t size);
uint8_t* eth_wait_for_rx_buff(ssize_t *size);
mac_addr_t* eth_get_mac_addr(void);

/********************************\
* NETWORK STATE AND ENTRY POINTS *
\********************************/

/* Global network state */
struct netstate {
	uint32_t ipaddr;
	uint32_t netmask;
	uint32_t gwaddr;
	uint32_t srvaddr;
	/* Consider this our one entry ARP cache
	 * plus one for the gateway. */
	uint32_t last_cached_ip;
	mac_addr_t last_cached_dmac;
	mac_addr_t gw_dmac;
	const char *bootfilename;
	int broadcast_filter;
};

typedef struct netstate NetState;

void net_set_broadcast_filter(int on);
int net_send_arp_req(uint32_t dest_ip, mac_addr_t *mac);
int net_send_udp(uint32_t daddr, uint16_t sport, uint16_t dport,
		 const void* buff, size_t size, int flags);
const uint8_t* net_wait_for_udp(uint16_t dport, ssize_t *payload_size,
				uint32_t *remote_ip,
				uint16_t *remote_port,
				uint32_t timeout_msec);
void net_update_config(uint32_t client_ip, uint32_t subnet_mask,
		       uint32_t gateway_ip, uint32_t srvaddr,
		       const char* bootfilename);
void net_set_srvinfo(uint32_t srvaddr, const char* bootfilename);
int net_get_srvinfo(uint32_t *srvaddr, const char** bootfilename);
int net_init(void);
void net_exit(void);

#endif /* NET_H */