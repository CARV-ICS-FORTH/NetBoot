/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2023 Nick Kossifidis <mick@ics.forth.gr>
 * SPDX-FileCopyrightText: 2023 ICS/FORTH
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <net.h>
#include <utils.h>	/* For console output */
#include <string.h>	/* For memcpy */
#include <stdlib.h>	/* For malloc */
#include <errno.h>	/* For errno and its values */
#include <time.h>	/* For clock() */

/* Single definitions - shared across all ethernet drivers - see net.h */
const struct timespec eth_tx_poll_delay = { .tv_nsec = 50 * 1000 };	/* 50μs */
const struct timespec eth_rx_poll_delay = { .tv_nsec = 100 * 1000 };	/* 100μs */

/*****************************\
* Helpers / utility functions *
\*****************************/

static inline uint64_t
net_get_elapsed_msec(clock_t start)
{
	clock_t now = clock();
	return ((now - start) * 1000ULL) / CLOCKS_PER_SEC;
}

/* Checksum used in IP/TCP/UDP headers, code taken from RFC1071
 * with additions to handle TCP/UDP pseudoheaders. The pseudoheader
 * for TCP/UDP is the normal header preceded by:
 * [source_ip | dest_ip | 0x00 | protocol | length (hdr + data)].
 * Since our ip header doesn't have any options, we can calculate
 * this simply by going back 8 octets to grab [source_ip | dest_ip]
 * from the end of the ip header, and add protocol and length to
 * the sum.
 *
 * Note: Our frame will be pointer-size aligned so this (see net.h)
 * will either operate on the IPv4 header (2byte aligned) or the
 * UDP header (also 2byte aligned), and since it reads 2bytes at
 * a time from a 2byte aligned buffer all reads can be done directly.
 * No need to do per-byte processing here, we can simply go per uint16_t.
 */
static uint16_t
inet_csum(const uint8_t* buff, uint16_t size, uint8_t protocol)
{
	uint32_t sum = 0;

	/* Add pseudoheader for TCP/UDP */
	if (protocol) {
		buff -= 8;
		sum += htons(protocol);
		sum += htons(size);
		size += 8;
	}

	/*  Inner loop */
	while (size > 1)  {
		sum += net_get_u16_aligned(buff);
		buff += 2;
		size -= 2;
	}

	/*  Add left-over byte, if any */
	if(size > 0)
		sum += *(buff);

	/*  Fold 32-bit sum to 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	/* Return 1's complement */
	return (uint16_t) ~sum;
}

/* Convert an ipv4 address to dotted decimal string format */
const char*
inet_print_ipv4(uint32_t ip_addr)
{
	union {
		uint8_t ip_bytes[4];
		uint32_t ip_addr;
	} ip;
	static char out[16] = {0};
	ip.ip_addr = ip_addr;
	snprintf(out, 16, "%i.%i.%i.%i", ip.ip_bytes[0], ip.ip_bytes[1],
					 ip.ip_bytes[2], ip.ip_bytes[3]);
	return (const char*) out;
}

#ifdef NET_DEBUG
static void net_frame_dump(const char *label, const uint8_t *data, size_t len)
{
	DBG_NET("[NET][%s] %zu bytes:\n", label, len);
	for (size_t i = 0; i < len; i++) {
		DBG_NET("%02X ", data[i]);
		if ((i + 1) % 16 == 0)
			putchar('\n');
	}
	if (len % 16 != 0)
		putchar('\n');
}
#else
static void net_frame_dump(const char *, const uint8_t *, size_t) {;;}
#endif

static NetState *net = NULL;

int
net_init(void)
{
	/* Check if we already initialized net_stack */
	if (net)
		return -EINVAL;

	int ret = eth_open();
	if (ret < 0) {
		ERR("[NET] Couldn't open ethernet NIC\n");
		return ret;
	}

	NetState *net_stack = malloc(sizeof(struct netstate));
	if (net_stack == NULL) {
		eth_close();
		return -ENOMEM;
	}
	memset(net_stack, 0, sizeof(struct netstate));

	net = net_stack;
	net->broadcast_filter = 1;
	return 0;
}

void
net_exit(void)
{
	if (!net)
		return;

	free(net);
	net = NULL;
	eth_close();
}

void
net_set_broadcast_filter(int on)
{
	if (!net)
		return;

	net->broadcast_filter = on;
}

/* Poll NIC for a frame with the expected ethertype provided. Timeout after
 * RX_NET_POLLS nic timeouts (e.g. on a silent network without frames), or
 * after RX_NET_TIMEOUT_IDLE_MSEC. */
static const uint8_t*
net_recv_raw(uint16_t expected_ethertype, ssize_t *frm_len)
{
	if (!net) {
		*frm_len = -ENOSYS;
		return NULL;
	}

	const uint64_t timeout_msec = RX_NET_TIMEOUT_IDLE_MSEC;
	clock_t start = clock();

	int countdown = RX_NET_POLLS;
	while (countdown > 0) {
		/* Are we out of time  ? */
		uint64_t msec_diff = net_get_elapsed_msec(start);
		if(msec_diff >= timeout_msec) {
			*frm_len = -ETIME;
			return NULL;
		}

		/* Note that inbuff will be pointer-size aligned */
		const uint8_t *inbuff = eth_wait_for_rx_buff(frm_len);
		if (inbuff == NULL || *frm_len < 0) {
			if (*frm_len != -ETIME && *frm_len != -ENOMSG) {
				/* Hard error from nic, fail fast */
				ERR("[NET] RX failed: %li\n", *frm_len);
				*frm_len = -EIO;
				return NULL;
			}
			countdown--;
			continue;
		}

		/* Drop any frames not directed to us in case hw doesn't
		 * filter stuff or is in promisc mode by default. */
		mac_addr_t in_dmac = {0};
		mac_set_bytes_aligned(&in_dmac, inbuff);
		mac_addr_t *our_smac = eth_get_mac_addr();
		if (mac_cmp(our_smac, &in_dmac)) {
			if (mac_is_broadcast(&in_dmac)) {
				/* Only accept broadcast frames if we are expecting them,
				 * but don't count filtered broadcast frames as retries. */
				if (net->broadcast_filter) {
					DBG_NET("[NET] broadcast frame filtered\n");
					*frm_len = -ENOMSG;
					continue;
				}
			} else {
				/* There is a possibility that eth nic doesn't filter out
				 * packages based on provided mac address (e.g. it has a
				 * very simple mac processing block), in which case we'll
				 * get any frame that reaches the nic (hopefully the switch
				 * will filter stuff out for us but anyway). Drop those frames
				 * but don't count them as retries or we'll get out or retries
				 * very fast if we end up in that scenario. */
				DBG_NET("[NET] Dropping packet not directed to us\n");
				*frm_len = -ENOMSG;
				continue;
			}
		}

		/* Check ethertype */
		uint16_t in_ethtype = ntohs(net_get_u16_aligned(&inbuff[12]));
		if (in_ethtype != expected_ethertype) {
			DBG_NET("[NET] Unexpected ethertype: %04x\n", in_ethtype);
			*frm_len = -ENOMSG;
			continue;
		}
		net_frame_dump("RX", inbuff, *frm_len);
		return inbuff;
	}
	DBG_NET("[NET] timeout while waiting for ethertype: %x\n", expected_ethertype);
	*frm_len = -ETIME;
	return NULL;
}


/*****\
* ARP *
\*****/

int
net_send_arp_req(uint32_t dest_ip, mac_addr_t *mac)
{
	if (!net)
		return -ENOSYS;

	/* Get a TX buffer and create an ARP request in there */

	uint8_t *outbuff = eth_get_tx_buff(sizeof(struct arp_frame));
	if (!outbuff)
		return -ENOBUFS;
	struct arp_frame *arp_req = (struct arp_frame*) outbuff;

	/* Set source MAC address to our own address for both the
	 * ethernet header and the ARP request */
	mac_addr_t *smac = eth_get_mac_addr();
	mac_copy_bytes(arp_req->eth_hdr.src_mac, smac);
	mac_copy_bytes(arp_req->arp_hdr.src_haddr, smac);

	/* Set destination MAC to broadcast/unknown */
	mac_addr_t dmac = {0};
	mac_copy_bytes_aligned(arp_req->arp_hdr.dst_haddr, &dmac);
	mac_set_broadcast(&dmac);
	mac_copy_bytes_aligned(arp_req->eth_hdr.dst_mac, &dmac);

	/* Set source IPv4 addr to our own (if zero it'll be a probe) */
	if (net->ipaddr)
		net_set_u32_aligned(net->ipaddr, arp_req->arp_hdr.src_paddr);
	else
		net_set_u32_aligned(0, arp_req->arp_hdr.src_paddr);

	/* Set requested IPv4 addr */
	net_set_u32(dest_ip, arp_req->arp_hdr.dst_paddr);

	/* Set ethertype to ARP */
	arp_req->eth_hdr.ethertype = htons(ETHERTYPE_ARP);

	/* Fill the rest of the ARP header */
	arp_req->arp_hdr.htype = htons(ARP_HTYPE_ETHER);
	arp_req->arp_hdr.ptype = htons(ARP_PTYPE_IPV4);
	arp_req->arp_hdr.hlen = ETH_ADDR_LEN;
	arp_req->arp_hdr.plen = sizeof(uint32_t);
	arp_req->arp_hdr.oper = htons(ARP_REQUEST);

	/* Done, send the tx buffer out */
	net_frame_dump("TX", outbuff, sizeof(struct arp_frame));
	int ret = eth_trigger_tx(sizeof(struct arp_frame));
	if (ret < 0) {
		ERR("[NET] couldn't send ARP request: %i\n", ret);
		return ret;
	}

	/* Receive and process the ARP reply (if we get one) */

	/* ARP replies are unicast, enable broadcast filter while waiting, and
	 * restore it's state right after we return. */
	int saved_bcast_filter = net->broadcast_filter;
	net_set_broadcast_filter(1);

	/* Note: it's ok to timeout here, since we also use this to verify
	 * if an IP is used or not. */
	ssize_t frm_len = 0;
	const uint8_t *inbuff = net_recv_raw(ETHERTYPE_ARP, &frm_len);
	net_set_broadcast_filter(saved_bcast_filter);
	if (inbuff == NULL) {
		mac->u64 = 0;
		return (int) frm_len;
	}
	struct arp_frame *arp_reply = (struct arp_frame*)inbuff;

	/* Verify the sender's ip address is the one we requested */
	uint32_t sender_ip = net_get_u32_aligned(arp_reply->arp_hdr.src_paddr);
	if (sender_ip != dest_ip) {
		DBG_NET("[NET] Got ARP reply for a differnt IP !\n");
		return -EPROTO;
	}

	/* Verify source MAC address on ARP reply matches the sender's MAC on eth header */
	mac_addr_t smac_eth = {0};
	mac_addr_t smac_arp = {0};
	mac_set_bytes(&smac_eth, arp_reply->eth_hdr.src_mac);
	mac_set_bytes(&smac_arp, arp_reply->arp_hdr.src_haddr);
	if (mac_cmp(&smac_eth, &smac_arp)) {
		DBG_NET("[NET] src MAC address mismatch (arp reply vs eth header) !\n");
		return -EPROTO;
	}

	/* Verify dest MAC address on ARP reply matches our own */
	mac_addr_t dmac_eth = {0};
	mac_addr_t dmac_arp = {0};
	mac_set_bytes_aligned(&dmac_eth, arp_reply->eth_hdr.dst_mac);
	mac_set_bytes_aligned(&dmac_arp, arp_reply->arp_hdr.dst_haddr);
	if (mac_cmp(&dmac_eth, &dmac_arp) || mac_cmp(&dmac_eth, smac)) {
		DBG_NET("[NET] dst MAC address mismatch (arp reply vs eth header vs our own) !\n");
		return -EPROTO;
	}

	/* Got a valid ARP reply, update ARP cache */
	mac_copy(mac, &smac_arp);
	mac_copy(&net->last_cached_dmac, &smac_arp);
	net->last_cached_ip = dest_ip;

	DBG_NET("[NET] got a valid ARP reply for: %s\n", inet_print_ipv4(dest_ip));
	return 0;
}


/*****\
* UDP *
\*****/

int
net_send_udp(uint32_t daddr, uint16_t sport, uint16_t dport,
	     const void *buff, size_t size, int flags)
{
	if (!net)
		return -ENOSYS;

	if (!buff || !size)
		return -ENODATA;

	/* Request a TX buffer large enough to hold the packet. Note
	 * that we won't support fragmentation and the assumption here
	 * is that our MTU is way smaller than the maximum IPv4 packet
	 * size (64K) so we don't need to also check for that. Note that
	 * we also need the frame to be at least 64b to be compliant with
	 * Ethernet, so if the packet is too small we may need to pad it. */
	uint8_t padding = 0;
	size_t frm_len = sizeof(struct udp_frame) + size;
	if (frm_len < ETH_MIN_FRM_LEN)
		padding = ETH_MIN_FRM_LEN - frm_len;
	uint8_t *outbuff = eth_get_tx_buff(frm_len + padding);
	if (!outbuff)
		return -ENOBUFS;
	struct udp_frame *out_frm = (struct udp_frame*) outbuff;

	/* Fill the ethernet header */

	mac_addr_t *smac = eth_get_mac_addr();
	mac_copy_bytes(out_frm->eth_hdr.src_mac, smac);
	out_frm->eth_hdr.ethertype = htons(ETHERTYPE_IPV4);

	mac_addr_t dmac = {0};
	/* This is a broadcast frame so use the broadcast
	 * MAC address as destination */
	if (flags & UDP_SEND_BCAST)
		mac_set_broadcast(&dmac);
	/* This is a unicast frame and the destination MAC address
	 * is in our ARP cache */
	else if (daddr == net->last_cached_ip)
		mac_copy(&dmac, &net->last_cached_dmac);
	/* This is a unicast packet but we need to figure out on
	 * which MAC addr to send it to */
	else {
		/* Do we need to go through the gw ? */
		if ((net->ipaddr && net->netmask) &&
		    ((daddr & net->netmask) != (net->ipaddr & net->netmask))) {
			if (net->gwaddr)
				mac_copy(&dmac, &net->gw_dmac);
			else {
				DBG_NET("[NET] can't reach ip without a gw: %s\n", inet_print_ipv4(daddr));
				return -EHOSTUNREACH;
			}
		} else {
			/* Do an ARP request to figure it out */
			int ret = net_send_arp_req(daddr, &dmac);
			if (ret < 0) {
				DBG_NET("[NET] could not resolve MAC addr for: %s\n", inet_print_ipv4(daddr));
				return -EHOSTDOWN;
			}
		}
	}
	mac_copy_bytes_aligned(out_frm->eth_hdr.dst_mac, &dmac);


	/* Fill the IP header */

	out_frm->ip_hdr.ihl	= 5;	/* 20 octets / 4 */
	out_frm->ip_hdr.version	= IPV4_VERSION;
	out_frm->ip_hdr.tos	= (flags & UDP_SEND_INETCONTROL) ? IPV4_CLASS_SELECTOR_6 : 0;
	out_frm->ip_hdr.tot_len	= htons(sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr) + size);
	out_frm->ip_hdr.id	= 0;
	out_frm->ip_hdr.frag_off = 0;
	/* If this is a broadcast message it doesn't make sense to live longer
	 * than a hop since the broadcast domain doesn't go past the subnet. With
	 * a TTL set to one, the router will decrease it to zero and the packet
	 * will die at the router as intended. Note that even if we put a higher
	 * TTL here the packet will still remain within the subnet so most
	 * implementations I've seen just blindly set TTL to 64 on the client
	 * side, well it doesn't make any sense, not my cup of tea, I know
	 * wireshark will give you warnings about "ttl being only one"
	 * get over it...
	 *
	 * Note: the DHCP may provide us with a TTL to use through option 23 and
	 * it would make sense to use it e.g. for reaching the boot server (assuming
	 * the DCHP knows how many hops away it is), but I haven't seen it being
	 * used out there, we don't have a way to explicitely request it through
	 * DHCP's parameter list, and I don't think many admins would care to
	 * maintain this config, so just stick to the default TTL for unicast. */
	out_frm->ip_hdr.ttl	 = (flags & UDP_SEND_BCAST) ? 1 : 64;
	out_frm->ip_hdr.protocol = IPV4_PROTO_UDP;
	out_frm->ip_hdr.hdr_csum = 0;
	net_set_u32(net->ipaddr, &out_frm->ip_hdr.src_addr);
	net_set_u32((flags & UDP_SEND_BCAST) ? 0xFFFFFFFF : daddr, &out_frm->ip_hdr.dst_addr);
	/* Update IP header checksum */
	out_frm->ip_hdr.hdr_csum = inet_csum(outbuff + sizeof(struct eth_hdr),
					     sizeof(struct ipv4_hdr), 0);


	/* Fill the UDP payload */

	out_frm->udp_hdr.sport	= htons(sport);
	out_frm->udp_hdr.dport	= htons(dport);
	out_frm->udp_hdr.dgram_len = htons(sizeof(struct udp_hdr) + size);
	out_frm->udp_hdr.dgram_csum = 0;
	/* Fill data */
	if (size)
		memcpy(outbuff + sizeof(struct udp_frame), buff, size);
	/* Update UDP checksum */
	out_frm->udp_hdr.dgram_csum = inet_csum(outbuff + sizeof(struct eth_hdr) + sizeof(struct ipv4_hdr),
						sizeof(struct udp_hdr) + size, IPV4_PROTO_UDP);

	net_frame_dump("TX", outbuff, frm_len + padding);
	return eth_trigger_tx(frm_len + padding);
}

const uint8_t*
net_wait_for_udp(uint16_t dport, ssize_t *payload_size, uint32_t *remote_ip,
		 uint16_t *remote_port, uint32_t timeout_msec)
{
	if (!net) {
		*payload_size = -ENOSYS;
		return NULL;
	}
	if (timeout_msec < RX_NET_TIMEOUT_IDLE_MSEC)
		timeout_msec = RX_NET_TIMEOUT_IDLE_MSEC;
	*payload_size = 0;

	/* Each call to net_recv_raw can take up to RX_NET_TIMEOUT_IDLE_MSEC, see how many
	 * times we can call net_recv_raw within our timeout_msec window. */
	int countdown = (timeout_msec / RX_NET_TIMEOUT_IDLE_MSEC);
	clock_t start = clock();
	while(countdown) {
		/* Are we out of time  ? */
		uint64_t msec_diff = net_get_elapsed_msec(start);
		if(msec_diff >= timeout_msec) {
			*payload_size = -ETIME;
			return NULL;
		}

		const uint8_t *inbuff = net_recv_raw(ETHERTYPE_IPV4, payload_size);
		if (!inbuff || *payload_size < 0) {
			/* Hard error */
			if (*payload_size == -EIO)
				return NULL;
			countdown--;
			continue;
		}
		struct udp_frame *in_frm = (struct udp_frame*)inbuff;

		/* Verify IP header checksum before we begin parsing it */
		uint16_t csum_saved = net_get_u16_aligned(&in_frm->ip_hdr.hdr_csum);
		net_set_u16_aligned(0, &in_frm->ip_hdr.hdr_csum);
		uint16_t csum_check = inet_csum(inbuff + sizeof(struct eth_hdr),
						sizeof(struct ipv4_hdr), 0);
		if (csum_saved != csum_check) {
			DBG_NET("[NET] got IP packet with invalid checksum\n");
			*payload_size = -EBADMSG;
			continue;
		}

		/* Verify IP header length is the expected one (no options) */
		if (in_frm->ip_hdr.ihl != IPV4_IHL) {
			DBG_NET("[NET] got IP packet with unexpected header length\n");
			*payload_size = -EBADMSG;
			continue;
		}

		/* Verify it's for our IP if we have one */
		if (net->ipaddr) {
			uint32_t daddr = net_get_u32(&in_frm->ip_hdr.dst_addr);
			if (net->ipaddr != daddr) {
				DBG_NET("[NET] got packet for another IP: %s\n", inet_print_ipv4(daddr));
				*payload_size = -ENOMSG;
				continue;
			}
		}

		/* Verify it's a UDP packet */
		if (in_frm->ip_hdr.protocol != IPV4_PROTO_UDP) {
			DBG_NET("[NET] got an IP packet but it's not UDP, protocol: %d\n",
			    in_frm->ip_hdr.protocol);
			*payload_size = -ENOMSG;
			continue;
		}

		/* Before we attempt to read it for verifying its checksum make sure the size
		 * field is correct so that we don't go past our receive buffer. Use uint32_t for
		 * tot_len to avoid int overflow. */
		uint32_t tot_len = (uint32_t) ntohs(net_get_u16_aligned(&in_frm->ip_hdr.tot_len)) +
						    sizeof(struct eth_hdr);
		if (tot_len > *payload_size) {
			DBG_NET("[NET] received UDP packet larger than received buffer (%i > %li)\n",
			    tot_len, *payload_size);
			*payload_size = -EMSGSIZE;
			continue;
		}

		/* Verify UDP checksum if present (since it's optional for UDP over IPv4) */
		csum_saved = net_get_u16_aligned(&in_frm->udp_hdr.dgram_csum);
		if (csum_saved) {
			net_set_u16_aligned(0, &in_frm->udp_hdr.dgram_csum);
			csum_check = inet_csum(inbuff + sizeof(struct eth_hdr) + sizeof(struct ipv4_hdr),
					       ntohs(net_get_u16_aligned(&in_frm->udp_hdr.dgram_len)),
					       IPV4_PROTO_UDP);
			if (csum_saved != csum_check) {
				WRN("[NET] got UDP packet with invalid checksum\n");
				*payload_size = -EBADMSG;
				countdown--;
				continue;
			}
		}

		/* Verify dport is the expected one */
		uint16_t in_dport = ntohs(net_get_u16_aligned(&in_frm->udp_hdr.dport));
		if (dport != in_dport) {
			DBG_NET("[Net] got UDP packet for another port: %i\n", in_dport);
			*payload_size = -ENOMSG;
			countdown--;
			continue;
		}

		*payload_size = ntohs(net_get_u16_aligned(&in_frm->udp_hdr.dgram_len)) - sizeof(struct udp_hdr);
		if (remote_ip)
			*remote_ip = net_get_u32(&in_frm->ip_hdr.src_addr);
		if (remote_port)
			*remote_port = ntohs(net_get_u16_aligned(&in_frm->udp_hdr.sport));
		return inbuff + sizeof(struct eth_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr);
	}

	DBG_NET("[Net] timeout on net_wait_for_udp()\n");
	*payload_size = -ETIME;
	return NULL;
}

void
net_update_config(uint32_t client_ip, uint32_t subnet_mask, uint32_t gateway_ip,
		  uint32_t srvaddr, const char* bootfilename)
{
	if (!net)
		return;

	net->ipaddr = client_ip;
	net->netmask = subnet_mask;

	/* Do an ARP request to get the gateway's mac address */
	if (gateway_ip) {
		mac_addr_t gw_mac = {0};
		int ret = net_send_arp_req(gateway_ip, &gw_mac);
		if (ret < 0) {
			WRN("[NET] could not resolve gateway's mac address: %i\n", ret);
			net->gwaddr = 0;
		} else {
			mac_copy(&net->gw_dmac, &gw_mac);
			net->gwaddr = gateway_ip;
		}
	}

	net->srvaddr = srvaddr;
	net->bootfilename = bootfilename;

	INF("[NET] Got IP: %s\n", inet_print_ipv4(client_ip));
	DBG_NET("[NET] Subnet mask: %s\n", inet_print_ipv4(subnet_mask));
	DBG_NET("[NET] Gateway: %s\n", inet_print_ipv4(gateway_ip));
}

int
net_get_srvinfo(uint32_t *srvaddr, const char** bootfilename)
{
	if (!net)
		return -ENOSYS;

	if (!net->srvaddr)
		return -EADDRNOTAVAIL;

	*srvaddr = net->srvaddr;

	if (bootfilename)
		*bootfilename = net->bootfilename;

	return 0;
}

void
net_set_srvinfo(uint32_t srvaddr, const char* bootfilename)
{
	if (!net)
		return;
	net->srvaddr = srvaddr;
	net->bootfilename = bootfilename;
}