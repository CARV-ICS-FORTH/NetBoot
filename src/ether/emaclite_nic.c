/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2023 Nick Kossifidis <mick@ics.forth.gr>
 * SPDX-FileCopyrightText: 2023 ICS/FORTH
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <target_config.h>	/* For PLAT_EMACLITE_BASE_ADDR */
#if defined(PLAT_EMACLITE_BASE_ADDR) && (PLAT_EMACLITE_BASE_ADDR > 0)
#include <platform/riscv/mmio.h>	/* For read32/write32 */

#include <net.h>
#include <utils.h>	/* For console output */
#include <stddef.h>	/* For NULL */
#include <string.h>	/* For memcpy */
#include <stdlib.h>	/* For rand, malloc */
#include <errno.h>	/* For errno's values */
#include <time.h>	/* For nanosleep() */

/*********************\
* EmacLite Memory Map *
\*********************/

#define EMACLITE_TX_PING_BUFF		0x0
#define EMACLITE_TX_PING_BUFF_PKTLEN	0x07F4
#define EMACLITE_GIE			0x07F8
enum {
	EMACLITE_GIE_BIT = (1 << 31)
};
#define EMACLITE_TX_PING_CTL		0x07FC
enum {
	EMACLITE_TX_CTL_STATUS	= 1,
	EMACLITE_TX_CTL_PROGRAM	= (1 << 1),
	EMACLITE_TX_CTL_IE	= (1 << 3),
	EMACLITE_TX_CTL_LOOPBACK = (1 << 4)
};
#define EMACLITE_TX_PONG_BUFF		0x0800
#define EMACLITE_TX_PONG_BUFF_PKTLEN	0x0FF4
#define EMACLITE_TX_PONG_CTL		0x0FFC
#define EMACLITE_RX_PING_BUFF		0x1000
#define EMACLITE_RX_PING_CTL		0x17FC
enum {
	EMACLITE_RX_CTL_STATUS	= 1,
	EMACLITE_RX_CTL_IE	= (1 << 3)
};
#define EMACLITE_RX_PONG_BUFF		0x1800
#define EMACLITE_RX_PONG_CTL		0x1FFC

#define EMACLITE_PKT_LEN_MASK		0x0000FFFF

struct emaclite_nic {
	uint8_t rx_buff[RX_BUFF_SIZE] __attribute__((aligned(4)));
	uint8_t tx_buff[TX_BUFF_SIZE] __attribute__((aligned(4)));
	mac_addr_t smac_addr;
};
typedef struct emaclite_nic EmacLiteNic;
static EmacLiteNic *emlnic = NULL;

/*********\
* Helpers *
\*********/

static uint32_t
emaclite_reg_read(uint16_t reg)
{
	uintptr_t addr = (uintptr_t)(PLAT_EMACLITE_BASE_ADDR + reg);
	return read32((const uint32_t*)addr);
}

static void
emaclite_reg_write(uint16_t reg, uint32_t val)
{
	uintptr_t addr = (uintptr_t)(PLAT_EMACLITE_BASE_ADDR + reg);
	return write32((uint32_t*)addr, val);
}

static void
emaclite_copy_to_tx_buff(const uint8_t *inbuff, size_t inbuff_len)
{
	uint32_t aligned_word = 0;
	int remaining_words = inbuff_len / 4;
	int remaining_bytes = inbuff_len % 4;
	int word_bytes = remaining_words * 4;
	int i = 0;
	int j = 0;

	/* Check if input buffer is 4-byte aligned */
	if ((uintptr_t)inbuff % 4 == 0) {
		/* Fast path: aligned access */
		while (remaining_words-- > 0) {
			aligned_word = net_get_u32_aligned(&inbuff[i]);
			emaclite_reg_write(EMACLITE_TX_PING_BUFF + i, aligned_word);
			i += 4;
		}
	} else {
		/* Slow path: unaligned access - copy byte-by-byte */
		while (remaining_words-- > 0) {
			aligned_word = net_get_u32(&inbuff[i]);
			emaclite_reg_write(EMACLITE_TX_PING_BUFF + i, aligned_word);
			i += 4;
		}
	}

	/* Handle remaining bytes (0-3 bytes) */
	aligned_word = 0;
	while (remaining_bytes-- > 0) {
		aligned_word |= inbuff[i++] << j;
		j += 8;
	}

	if (j)
		emaclite_reg_write(EMACLITE_TX_PING_BUFF + word_bytes, aligned_word);
}

static int
emaclite_copy_from_rx_buff(uint8_t *outbuff, int use_alt_buffer)
{
	/* Hw doesn't report rx packet size so we need to find out on our own.
	 * Read 5 words, enough to include ipv4's total length field (and part of
	 * an ARP packet). */
	uint32_t aligned_word = 0;
	uint16_t buff_offset = use_alt_buffer ? EMACLITE_RX_PONG_BUFF : EMACLITE_RX_PING_BUFF;
	uint16_t buff_ctl_offset = use_alt_buffer ? EMACLITE_RX_PONG_CTL : EMACLITE_RX_PING_CTL;
	int remaining_words = 5;
	int remaining_bytes = 0;
	int i = 0;

	while (remaining_words-- > 0) {
		aligned_word = emaclite_reg_read(buff_offset + i);
		/* Note that the address of outbuff itself is 4byte aligned (check the
		 * struct emaclite_nic declaration above) and since we increase 4 bytes
		 * at a time we'll only do aligned writes here. */
		net_set_u32_aligned(aligned_word, &outbuff[i]);
		i += 4;
	}

	struct eth_hdr *eth_hdr = (struct eth_hdr*) outbuff;
	struct ipv4_hdr *ip_hdr = NULL;
	uint16_t outlen = 0;
	switch (ntohs(eth_hdr->ethertype)) {
		case ETHERTYPE_ARP:
			/* ARP packets have fixed size of 42 [eth_hdr(14) + arp_ipv4oeth(28)]
			 * so we need 42 - 20 bytes to go. */
			outlen = 22;
			remaining_words = 22 / 4;
			remaining_bytes = 22 % 4;
			break;
		case ETHERTYPE_IPV4:
			ip_hdr = (struct ipv4_hdr*) (outbuff + sizeof(struct eth_hdr));
			outlen = ntohs(net_get_u16_aligned(&ip_hdr->tot_len));
			/* We already got 20 - eth_hdr(14) bytes from the ipv4 header */
			outlen -= 6;
			remaining_words = outlen / 4;
			remaining_bytes = outlen % 4;
			/* Sanity check, IP header may be corrupt in which case we may get an
			 * invalid length field, make sure we won't go past our RX buffer */
			if ((outlen + 20) > RX_BUFF_SIZE) {
				DBG_NET("[EmacLite] Got IP packet larger than our RX buffer !\n");
				return -EMSGSIZE;
			}
			break;
		default:
			/* Unhandled ethertype, ignore the frame */
			i = -ENOMSG;
			goto done;
	}

	while (remaining_words-- > 0) {
		aligned_word = emaclite_reg_read(buff_offset + i);
		net_set_u32_aligned(aligned_word, &outbuff[i]);
		i += 4;
	}

	if (remaining_bytes) {
		int j = 0;
		aligned_word = emaclite_reg_read(buff_offset + i);
		while (remaining_bytes-- > 0) {
			outbuff[i++] = (aligned_word >> j) & 0xFF;
			j += 8;
		}
	}

 done:
	/* Allow hw to receive next frame, set status to 0 */
	emaclite_reg_write(buff_ctl_offset, 0);
	return i;
}

void
emaclite_set_mac_addr(mac_addr_t smac_addr)
{
	if (!emlnic)
		return;

	int countdown = TX_ETH_RETRIES;
	/* Fill hw tx bufer with MAC address and set the program bit */
	emaclite_copy_to_tx_buff(mac_get_bytes(&smac_addr), ETH_ADDR_LEN);
	emaclite_reg_write(EMACLITE_TX_PING_CTL, EMACLITE_TX_CTL_PROGRAM |
						 EMACLITE_TX_CTL_STATUS);

	/* Wait until hw becomes ready */
	while (--countdown) {
		uint32_t check = emaclite_reg_read(EMACLITE_TX_PING_CTL);
		if (!(check & EMACLITE_TX_CTL_STATUS)) {
			DBG_NET("[EmacLite] MAC set\n");
			mac_copy(&emlnic->smac_addr, &smac_addr);
			return;
		}
		nanosleep(&eth_tx_poll_delay, NULL);
	}
	WRN("[EmacLite] timeout while programing MAC address !\n");
}

/**************\
* Entry points *
\**************/

mac_addr_t*
eth_get_mac_addr(void)
{
	if (!emlnic)
		return NULL;

	return &emlnic->smac_addr;
}

uint8_t*
eth_get_tx_buff(size_t size)
{
	if (!emlnic)
		return NULL;

	if (size > TX_BUFF_SIZE) {
		ERR("[EmacLite] requested buffer size exceeds TX buffer len\n");
		return NULL;
	}
	memset(emlnic->tx_buff, 0, size);
	return emlnic->tx_buff;
}

int
eth_trigger_tx(size_t size)
{
	if (!emlnic)
		return -ENODEV;

	if (size > TX_BUFF_SIZE) {
		ERR("[EmacLite] requested frame size won't fit TX buffer\n");
		return -EMSGSIZE;
	}

	/* Check if on-chip buffer is ready, we only send one frame at a time
	 * so only use the ping buffer. */
	int countdown = TX_ETH_RETRIES;
	while (--countdown) {
		uint32_t check = emaclite_reg_read(EMACLITE_TX_PING_CTL);
		if (!(check & EMACLITE_TX_CTL_STATUS))
			break;
		nanosleep(&eth_tx_poll_delay, NULL);
	}

	if (!countdown) {
		WRN("[EmacLite] timeout while waiting for TX buffer availability\n");
		return -ETIME;
	}

	/* Fill hw tx buffer and set frame length */
	emaclite_copy_to_tx_buff(emlnic->tx_buff, size);
	emaclite_reg_write(EMACLITE_TX_PING_BUFF_PKTLEN, size & EMACLITE_PKT_LEN_MASK);

	/* Trigger transmission of tx buff and wait for completion */
	emaclite_reg_write(EMACLITE_TX_PING_CTL, EMACLITE_TX_CTL_STATUS);
	while (--countdown) {
		uint32_t check = emaclite_reg_read(EMACLITE_TX_PING_CTL);
		if (!(check & EMACLITE_TX_CTL_STATUS))
			return size;
		nanosleep(&eth_tx_poll_delay, NULL);
	}
	WRN("[EmacLite] timeout while sending frame !\n");
	return -ETIME;
}

uint8_t*
eth_wait_for_rx_buff(ssize_t *size)
{
	if (!emlnic) {
		*size = -ENODEV;
		return NULL;
	}

	/* Check if one of ping/pong buffers is ready */
	int countdown = RX_ETH_RETRIES;
	int use_alt_buffer = 0;
	while (--countdown) {
		uint32_t check = emaclite_reg_read(EMACLITE_RX_PING_CTL);
		if (check & EMACLITE_RX_CTL_STATUS)
			break;
		check = emaclite_reg_read(EMACLITE_RX_PONG_CTL);
		if (check & EMACLITE_RX_CTL_STATUS) {
			use_alt_buffer = 1;
			break;
		}
		nanosleep(&eth_rx_poll_delay, NULL);
	}

	if (!countdown) {
		DBG_NET("[EmacLite] timeout while receving frame !\n");
		*size = -ETIME;
		return NULL;
	}
	*size = emaclite_copy_from_rx_buff(emlnic->rx_buff, use_alt_buffer);
	return emlnic->rx_buff;
}

int
eth_open(void)
{
	/* Already initialized */
	if (emlnic)
		return -EINVAL;

	/* Note: malloc will return a pointer-size-aligned address */
	emlnic = malloc(sizeof(struct emaclite_nic));
	if (emlnic != NULL)
		memset(emlnic, 0, sizeof(struct emaclite_nic));
	else
		return -ENOMEM;

	mac_addr_t smac_addr = mac_get_random();
	DBG_NET("[EmacLite] using MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
	    smac_addr.bytes[0], smac_addr.bytes[1],
	    smac_addr.bytes[2], smac_addr.bytes[3],
	    smac_addr.bytes[4], smac_addr.bytes[5]);
	emaclite_set_mac_addr(smac_addr);
	return 0;
}

void
eth_close(void)
{
	if (!emlnic)
		return;

	free(emlnic);
	emlnic = NULL;
}

#endif /* defined(PLAT_EMACLITE_BASE_ADDR) && (PLAT_EMACLITE_BASE_ADDR > 0) */