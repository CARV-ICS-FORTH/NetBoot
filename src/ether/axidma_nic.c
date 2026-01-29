/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2025 Nick Kossifidis <mick@ics.forth.gr>
 * SPDX-FileCopyrightText: 2025 ICS/FORTH
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* Bare metal driver for Xilinx AXI DMA based NIC
 * 
 * This is a simplified driver for CARV's custom NIC which uses Xilinx's
 * AXI DMA engine with a dummy MAC. The driver uses a single descriptor
 * per TX/RX queue (no descriptor rings) and polling instead of interrupts,
 * making it suitable for bare metal environments like netboot.
 */
#include <target_config.h>	/* For PLAT_AXIDMA_BASE_ADDR */
#if defined(PLAT_AXIDMA_BASE_ADDR) && (PLAT_AXIDMA_BASE_ADDR > 0)
#include <platform/riscv/mmio.h>	/* For read32/write32 */

#include <net.h>
#include <utils.h>	/* For console output */
#include <stddef.h>	/* For NULL */
#include <string.h>	/* For memcpy, memset */
#include <stdlib.h>	/* For malloc */
#include <stdatomic.h>	/* For atomic_thread_fence */
#include <errno.h>	/* For errno values */
#include <time.h>	/* For nanosleep() */

/******************************\
* AXI DMA Channel Register Map *
\******************************/

#define AXIDMA_CR_OFFSET		0x00	/* Control */
#define AXIDMA_SR_OFFSET		0x04	/* Status */
#define AXIDMA_CDESC_OFFSET		0x08	/* Current Descriptor */
#define AXIDMA_TDESC_OFFSET		0x10	/* Tail Descriptor */

#define AXIDMA_MM2S_CHAN_BASE		0	/* TX channel base addr */
#define AXIDMA_S2MM_CHAN_BASE		0x30	/* RX channel base addr */

#define TX_REG(_n)	(AXIDMA_MM2S_CHAN_BASE + _n)
#define RX_REG(_n)	(AXIDMA_S2MM_CHAN_BASE + _n)

/* Control Register Bits */
enum {
	AXIDMA_CR_RUNSTOP	= (1 << 0),	/* Start/Stop DMA */
	AXIDMA_CR_RESET		= (1 << 2),	/* Reset DMA engine */
};

/* Status Register Bits */
enum {
	AXIDMA_SR_HALTED	= (1 << 0),	/* DMA channel halted */
	AXIDMA_SR_IDLE		= (1 << 1),	/* DMA channel idle */
	AXIDMA_SR_DMA_ERR_INT	= (1 << 4),	/* Internal error (Buffers) */
	AXIDMA_SR_DMA_ERR_SLV	= (1 << 5),	/* Slave error (Buffers) */
	AXIDMA_SR_DMA_ERR_DEC	= (1 << 6),	/* Decode error (Buffers) */
	AXIDMA_SR_DMA_ERR_ALL	= (AXIDMA_SR_DMA_ERR_INT | 
				   AXIDMA_SR_DMA_ERR_SLV | 
				   AXIDMA_SR_DMA_ERR_DEC),
	AXIDMA_SR_SG_ERR_INT	= (1 << 8),	/* Internal error (Descriptors) */
	AXIDMA_SR_SG_ERR_SLV	= (1 << 9),	/* Slave error (Descriptors) */
	AXIDMA_SR_SG_ERR_DEC	= (1 << 10),	/* Decode error (Descriptors) */
	AXIDMA_SR_SG_ERR_ALL	= (AXIDMA_SR_SG_ERR_INT |
				   AXIDMA_SR_SG_ERR_SLV |
				   AXIDMA_SR_SG_ERR_DEC),
	AXIDMA_SR_ERR_ALL	= (AXIDMA_SR_DMA_ERR_ALL | AXIDMA_SR_SG_ERR_ALL),
	AXIDMA_SR_ERR_INT	= (AXIDMA_SR_DMA_ERR_INT | AXIDMA_SR_SG_ERR_INT),
};

/*****************************\
* Buffer Descriptor Structure *
\*****************************/

/* AXI DMA Buffer Descriptor
 * 
 * The DMA engine uses these descriptors to know where to read/write data.
 * Each descriptor points to a data buffer and contains control/status info.
 * In our simplified driver, we use just one descriptor per TX/RX queue.
 * 
 * Note: Must be 64-byte aligned when instantiated (AXIDMA_BD_MINIMUM_ALIGNMENT)
 */
#define AXIDMA_BD_MINIMUM_ALIGNMENT	64

struct axidma_bd {
	uint32_t next;		/* Physical address of next descriptor (low 32 bits) */
	uint32_t next_msb;	/* Physical address of next descriptor (high 32 bits) */
	uint32_t phys;		/* Physical address of data buffer (low 32 bits) */
	uint32_t phys_msb;	/* Physical address of data buffer (high 32 bits) */
	uint32_t reserved3;
	uint32_t reserved4;
	uint32_t cntrl;		/* Control and buffer length */
	uint32_t status;	/* Status and actual transferred length */
	uint32_t app0;		/* Application word 0 (unused) */
	uint32_t app1;		/* Application word 1 (unused) */
	uint32_t app2;		/* Application word 2 (unused) */
	uint32_t app3;		/* Application word 3 (unused) */
	uint32_t app4;		/* Application word 4 (unused) - last field used by hw */
	uint32_t pad[3];	/* Padding until we reach 64-byte size */
};

/* BD Control Register Bits */
enum {
	AXIDMA_BD_CTRL_LENGTH_MASK	= 0x007FFFFF,	/* Buffer length (23 bits) */
	AXIDMA_BD_CTRL_TXEOF		= (1 << 26),	/* End of frame (TX) */
	AXIDMA_BD_CTRL_TXSOF		= (1 << 27),	/* Start of frame (TX) */
};

/* BD Status Register Bits */
enum {
	AXIDMA_BD_STS_ACTUAL_LEN_MASK	= 0x007FFFFF,	/* Actual transferred length */
	AXIDMA_BD_STS_RXEOF		= (1 << 26),	/* End of frame (RX) */
	AXIDMA_BD_STS_RXSOF		= (1 << 27),	/* Start of frame (RX) */
	AXIDMA_BD_STS_ERR_INT		= (1 << 28),	/* Internal error */
	AXIDMA_BD_STS_ERR_SLV		= (1 << 29),	/* Slave error */
	AXIDMA_BD_STS_ERR_DEC		= (1 << 30),	/* Decode error */
	AXIDMA_BD_STS_COMPLETE		= (1U << 31),	/* Transfer complete */
	AXIDMA_BD_STS_ERR_ALL		= (AXIDMA_BD_STS_ERR_INT | 
					   AXIDMA_BD_STS_ERR_SLV | 
					   AXIDMA_BD_STS_ERR_DEC),
};

/****************\
* Driver State  *
\****************/

struct axidma_nic {
	/* TX / RX buffers - 8-byte aligned due to size (1520 bytes each) */
	uint8_t tx_buff[TX_BUFF_SIZE] __attribute__((aligned(8)));
	uint8_t rx_buff[RX_BUFF_SIZE] __attribute__((aligned(8)));

	/* MAC address */
	mac_addr_t smac_addr;

	/* TX / RX descriptors - 64-byte aligned */
	struct axidma_bd tx_bd __attribute__((aligned(AXIDMA_BD_MINIMUM_ALIGNMENT)));
	struct axidma_bd rx_bd __attribute__((aligned(AXIDMA_BD_MINIMUM_ALIGNMENT)));
};
typedef struct axidma_nic AxiDmaNic;

/* Global driver state - only one NIC instance in bare metal */
static AxiDmaNic *nic_state = NULL;

/*********\
* Helpers *
\*********/

static uint32_t
axidma_reg_read(uint16_t reg)
{
	uintptr_t addr = (uintptr_t)(PLAT_AXIDMA_BASE_ADDR + reg);
	return read32((const uint32_t*)addr);
}

static void
axidma_reg_write(uint16_t reg, uint32_t val)
{
	uintptr_t addr = (uintptr_t)(PLAT_AXIDMA_BASE_ADDR + reg);
	write32((uint32_t*)addr, val);
}

static inline uint32_t
addr_lo32(const void *ptr)
{
	return (uint32_t)((uintptr_t)ptr & 0xFFFFFFFFUL);
}

static inline uint32_t
addr_hi32(const void *ptr)
{
	return (uint32_t)(((uintptr_t)ptr >> 32) & 0xFFFFFFFFUL);
}

static void
axidma_set_desc(uint16_t reg, const void *ptr)
{
	uint32_t lo = addr_lo32(ptr);
	uint32_t hi = addr_hi32(ptr);
	axidma_reg_write(reg, lo);
	axidma_reg_write(reg + 4, hi);
}

static inline void
axidma_update_desc(struct axidma_bd* bd, uint32_t cntrl)
{
	bd->cntrl = cntrl;
	bd->status = 0;
	atomic_thread_fence(memory_order_release);
}

static __attribute((unused)) struct axidma_bd*
axidma_get_desc(uint16_t reg)
{
	uint32_t lo = axidma_reg_read(reg);
	uint32_t hi = axidma_reg_read(reg + 4);
	uintptr_t addr = (uintptr_t)hi << 32 | (uintptr_t)lo;
	return (struct axidma_bd*)addr;
}

static int
axidma_reset(void)
{
	const struct timespec ts_delay = { .tv_nsec = 1 * 1000 * 1000 }; /* 1ms */
	int countdown = 100; /* 100ms timeout */

	DBG_NET("[AxiDMA] Resetting DMA engine...\n");

	/* Reset DMA core (affects both channels) */
	axidma_reg_write(AXIDMA_CR_OFFSET, AXIDMA_CR_RESET);

	/* Wait for reset to complete - both channels should show halted */
	while (--countdown) {
		uint32_t tx_sr = axidma_reg_read(TX_REG(AXIDMA_SR_OFFSET));
		uint32_t rx_sr = axidma_reg_read(RX_REG(AXIDMA_SR_OFFSET));

		if ((tx_sr & AXIDMA_SR_HALTED) && (rx_sr & AXIDMA_SR_HALTED)) {
			DBG_NET("[AxiDMA] Reset complete\n");
			return 0;
		}

		nanosleep(&ts_delay, NULL);
	}

	ERR("[AxiDMA] Reset timeout!\n");
	return -ETIME;
}

static int
axidma_init(void)
{
	if (!nic_state)
		return -EINVAL;

	struct axidma_bd* tx_bd = &nic_state->tx_bd;
	tx_bd->next = addr_lo32(tx_bd);
	tx_bd->next_msb = addr_hi32(tx_bd);
	tx_bd->phys = addr_lo32(nic_state->tx_buff);
	tx_bd->phys_msb = addr_hi32(nic_state->tx_buff);

	struct axidma_bd* rx_bd = &nic_state->rx_bd;
	rx_bd->next = addr_lo32(rx_bd);
	rx_bd->next_msb = addr_hi32(rx_bd);
	rx_bd->phys = addr_lo32(nic_state->rx_buff);
	rx_bd->phys_msb = addr_hi32(nic_state->rx_buff);
	rx_bd->cntrl = (uint32_t)(RX_BUFF_SIZE & AXIDMA_BD_CTRL_LENGTH_MASK);

	/* Reset DMA core*/
	int ret = axidma_reset();
	if (ret < 0)
		return -ENODEV;

	return 0;
}

static int
axidma_trigger_channel(int chan_base, size_t *buff_size)
{
	if (!nic_state)
		return -ENODEV;

	struct axidma_bd* bd;
	const char *chan_name;
	const struct timespec *ts_delay;
	int countdown = 0;
	switch(chan_base) {
		case AXIDMA_MM2S_CHAN_BASE:
			if (!buff_size || *buff_size > TX_BUFF_SIZE || *buff_size == 0)
				return -EMSGSIZE;
			bd = &nic_state->tx_bd;
			/* Mark as start-of-frame and end-of-frame (single packet) */
			bd->cntrl = (uint32_t)(*buff_size & AXIDMA_BD_CTRL_LENGTH_MASK) | 
						AXIDMA_BD_CTRL_TXSOF | 
						AXIDMA_BD_CTRL_TXEOF;
			bd->status = 0;
			chan_name = "TX";
			ts_delay = &eth_tx_poll_delay;
			countdown = TX_ETH_RETRIES;
			break;
		case AXIDMA_S2MM_CHAN_BASE:
			bd = &nic_state->rx_bd;
			bd->status = 0;
			chan_name = "RX";
			ts_delay = &eth_tx_poll_delay;
			countdown = RX_ETH_RETRIES;
			break;
		default:
			return -EINVAL;
	}
	atomic_thread_fence(memory_order_release);

	uint16_t sr_reg = chan_base + AXIDMA_SR_OFFSET;
	uint16_t cr_reg = chan_base + AXIDMA_CR_OFFSET;
	uint16_t cdesc_reg = chan_base +  AXIDMA_CDESC_OFFSET;
	uint16_t tdesc_reg = chan_base +  AXIDMA_TDESC_OFFSET;

	uint32_t sr = axidma_reg_read(sr_reg);
	/* Channel is halted, set it up to process bd and pause */
	if (sr & AXIDMA_SR_HALTED) {
		DBG_NET("[AxiDMA] %s is halted (sr: 0x%x), restarting...\n", chan_name, sr);
		axidma_set_desc(cdesc_reg, bd);
		axidma_reg_write(cr_reg, AXIDMA_CR_RUNSTOP);
		axidma_set_desc(tdesc_reg, bd);
	} else if (sr & AXIDMA_SR_IDLE) {
		axidma_set_desc(tdesc_reg, bd);
	}

	while (--countdown) {
		atomic_thread_fence(memory_order_acquire);

		if (bd->status & AXIDMA_BD_STS_COMPLETE) {
			uint32_t requested_size = (bd->cntrl & AXIDMA_BD_CTRL_LENGTH_MASK);
			uint32_t transfered_size = (bd->status & AXIDMA_BD_STS_ACTUAL_LEN_MASK);
			if (chan_base == AXIDMA_MM2S_CHAN_BASE &&
			    transfered_size != requested_size) {
				WRN("[AxiDMA] TX packet truncated (%i vs %i) !\n",
				    requested_size, transfered_size);
				return -EMSGSIZE;
			} else if (chan_base == AXIDMA_S2MM_CHAN_BASE &&
				   (transfered_size > RX_BUFF_SIZE)) {
				WRN("[AxiDMA] invalid RX packet size: %i\n", transfered_size);
				return -EMSGSIZE;
			}
			*buff_size = transfered_size;
			return transfered_size;
		}

		nanosleep(ts_delay, NULL);
	}

	DBG_NET("[AxiDMA] %s timeout\n", chan_name);
	axidma_reset();
	return -ETIME;
}

/**************\
* Entry Points *
\**************/

mac_addr_t*
eth_get_mac_addr(void)
{
	if (!nic_state)
		return NULL;

	return &nic_state->smac_addr;
}

uint8_t*
eth_get_tx_buff(size_t size)
{
	if (!nic_state)
		return NULL;

	if (size > TX_BUFF_SIZE) {
		ERR("[AxiDMA] Requested buffer size exceeds TX buffer length\n");
		return NULL;
	}

	memset(nic_state->tx_buff, 0, size);
	return nic_state->tx_buff;
}

int
eth_trigger_tx(size_t size)
{
	size_t tx_size = size;
	return axidma_trigger_channel(AXIDMA_MM2S_CHAN_BASE, &tx_size);
}

uint8_t*
eth_wait_for_rx_buff(ssize_t *size)
{
	if (!nic_state) {
		*size = -ENODEV;
		return NULL;
	}

	size_t buff_size = 0;
	int ret = axidma_trigger_channel(AXIDMA_S2MM_CHAN_BASE, &buff_size);
	if (ret < 0) {
		*size = (ssize_t)ret;
		return NULL;
	}
	*size = (ssize_t)buff_size;
	return nic_state->rx_buff;
}

int
eth_open(void)
{
	int ret = 0;

	/* Check if already initialized */
	if (nic_state != NULL) {
		WRN("[AxiDMA] Driver already initialized\n");
		return -EBUSY;
	}

	/* Allocate driver state
	 * malloc returns pointer-size-aligned address. Our structure has
	 * alignment attributes on the BDs to ensure 64-byte alignment. */
	nic_state = malloc(sizeof(struct axidma_nic));
	if (!nic_state)
		return -ENOMEM;
	memset(nic_state, 0, sizeof(struct axidma_nic));

	/* Generate a random MAC address */
	mac_addr_t smac_addr = mac_get_random();
	DBG_NET("[AxiDMA] Using MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
	    smac_addr.bytes[0], smac_addr.bytes[1],
	    smac_addr.bytes[2], smac_addr.bytes[3],
	    smac_addr.bytes[4], smac_addr.bytes[5]);
	mac_copy(&nic_state->smac_addr, &smac_addr);

	/* Reset the DMA engine */
	ret = axidma_init();
	if (ret < 0)
		goto cleanup;

	DBG_NET("[AxiDMA] Initialization complete\n");
	return 0;

cleanup:
	if (nic_state) {
		free(nic_state);
		nic_state = NULL;
	}
	return ret;
}

void
eth_close(void)
{
	if (nic_state) {
		/* Flush/complete any pending commands/transfers
		 * before freeing buffers */
		axidma_reset();		
		free(nic_state);
		nic_state = NULL;
	}
}

#endif /* defined(PLAT_AXIDMA_BASE_ADDR) && (PLAT_AXIDMA_BASE_ADDR > 0) */
