/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2026 Nick Kossifidis <mick@ics.forth.gr>
 * SPDX-FileCopyrightText: 2026 ICS/FORTH
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* Bare metal driver for the Synopsys DesignWare GMAC, dwmac-1000 generation
 * (a.k.a. "GMAC"/v3.x, version register 0x3x). This is the classic stmmac IP
 * found on many SoCs; the driver is deliberately platform-agnostic so it can
 * be reused for any dwmac-1000 - anything SoC-specific (clocks, resets, PHY
 * power-on) belongs in the platform's platform_init(), and DMA cache
 * coherency is handled through the SDK's dma_cache_* API (a no-op on coherent
 * platforms).
 *
 * Like the other netboot NIC drivers it handles exactly one frame at a time
 * with polling (no interrupts): a single TX and a single RX descriptor, each
 * chained to itself, so the DMA engine reuses it after every frame. Register
 * map, descriptor layout and the init/send/recv flow follow the reference
 * u-boot designware driver.
 */
#include <target_config.h>	/* For PLAT_DWMAC3_BASE_ADDR */
#if defined(PLAT_DWMAC3_BASE_ADDR) && (PLAT_DWMAC3_BASE_ADDR > 0)
#include <platform/riscv/mmio.h>	/* For read32/write32 */
#include <platform/riscv/cache.h>	/* For dma_cache_flush/inval */

#include <net.h>
#include <utils.h>	/* For console output */
#include <stddef.h>	/* For NULL */
#include <string.h>	/* For memcpy, memset */
#include <stdlib.h>	/* For malloc/free */
#include <stdint.h>	/* For typed integers */
#include <errno.h>	/* For errno values */
#include <time.h>	/* For nanosleep() */

#ifndef PLAT_DWMAC3_CSR_CLOCK_HZ
#error "dwmac3 needs PLAT_DWMAC3_CSR_CLOCK_HZ (the MAC CSR clock) for the MDC divider"
#endif

/* Normal (non-enhanced) descriptors carry a single 32-bit buffer address and
 * a 32-bit next pointer - this IP cannot DMA above 4GB. DMA buffers live in
 * our RAM, which must therefore sit in the DRAM window and below 4GB. */
_Static_assert((uint64_t)PLAT_RAM_BASE + PLAT_RAM_SIZE <= 0x100000000ULL,
	       "dwmac3 is 32-bit DMA only: RAM region sits above 4GB");
#if (PLAT_RAM_BASE < PLAT_SYSRAM_BASE) || \
    (PLAT_RAM_BASE + PLAT_RAM_SIZE > PLAT_SYSRAM_BASE + PLAT_SYSRAM_SIZE)
#error "DMA buffers (in RAM) must lie within the DRAM/SYSRAM region"
#endif

/********************\
* DWMAC Register Map *
\********************/

/* MAC block at base + 0x0000 */
#define MAC_CONF		0x0000
#define MAC_MIIADDR		0x0010
#define MAC_MIIDATA		0x0014
#define MAC_VERSION		0x0020
#define MAC_ADDR0_HI		0x0040
#define MAC_ADDR0_LO		0x0044

/* MAC configuration bits */
enum {
	MAC_CONF_RXENABLE	= (1 << 2),
	MAC_CONF_TXENABLE	= (1 << 3),
	MAC_CONF_FULLDPLX	= (1 << 11),
	MAC_CONF_DISABLERXOWN	= (1 << 13),
	MAC_CONF_FES_100	= (1 << 14),
	MAC_CONF_MII_PORTSEL	= (1 << 15),	/* MII (10/100) vs GMII (1000) */
	MAC_CONF_FRAMEBURST	= (1 << 21),
};

/* MII (MDIO) address register bits */
enum {
	MII_BUSY		= (1 << 0),
	MII_WRITE		= (1 << 1),
	MIIREGSHIFT		= 6,
	MIIADDRSHIFT		= 11,
	MII_REGMSK		= (0x1F << 6),
	MII_ADDRMSK		= (0x1F << 11),
};

/* MDIO CSR-clock-range field (MDC divider select), bits [4:2] */
enum {
	MII_CLKRANGE_60_100M	= 0x00,
	MII_CLKRANGE_100_150M	= 0x04,
	MII_CLKRANGE_20_35M	= 0x08,
	MII_CLKRANGE_35_60M	= 0x0C,
	MII_CLKRANGE_150_250M	= 0x10,
	MII_CLKRANGE_250_300M	= 0x14,
};

/* Version register: SNPSVER is the low byte (0x3x for dwmac-1000) */
#define MAC_VER_SNPS_MASK	0xFF

/* DMA block at base + 0x1000 */
#define DMA_BASE		0x1000
#define DMA_BUSMODE		(DMA_BASE + 0x00)
#define DMA_TXPOLL		(DMA_BASE + 0x04)
#define DMA_RXPOLL		(DMA_BASE + 0x08)
#define DMA_RXDESC		(DMA_BASE + 0x0c)
#define DMA_TXDESC		(DMA_BASE + 0x10)
#define DMA_STATUS		(DMA_BASE + 0x14)
#define DMA_OPMODE		(DMA_BASE + 0x18)
#define DMA_INTEN		(DMA_BASE + 0x1c)

/* Bus mode bits */
enum {
	DMA_BUSMODE_SWR		= (1 << 0),
	DMA_BUSMODE_PBL8	= (8 << 8),	/* burst length 8 */
	DMA_BUSMODE_PRIORXTX_41	= (3 << 14),
	DMA_BUSMODE_FIXEDBURST	= (1 << 16),
};

/* Operation mode bits */
enum {
	DMA_OPMODE_RXSTART	= (1 << 1),
	DMA_OPMODE_TXSTART	= (1 << 13),
	DMA_OPMODE_FLUSHTXFIFO	= (1 << 20),
	DMA_OPMODE_STOREFORWARD	= (1 << 21),
};

#define DMA_POLL_DEMAND		0xFFFFFFFF

/*****************\
* DMA Descriptors *
\*****************/

/* Normal (non-enhanced) 16-byte descriptor */
struct dwmac3_desc {
	uint32_t status;	/* ownership + status */
	uint32_t cntl;		/* control + buffer length */
	uint32_t addr;		/* buffer address (32-bit) */
	uint32_t next;		/* next descriptor address (32-bit) */
};

/* TX status / control bits */
enum {
	DESC_TXSTS_OWN		= (1U << 31),
	DESC_TXCTRL_TXCHAIN	= (1 << 24),
	DESC_TXCTRL_TXFIRST	= (1 << 29),
	DESC_TXCTRL_TXLAST	= (1 << 30),
	DESC_TXCTRL_SIZE1MASK	= 0x7FF,
};

/* RX status / control bits */
enum {
	DESC_RXSTS_OWN		= (1U << 31),
	DESC_RXSTS_FRMLEN_SHIFT	= 16,
	DESC_RXSTS_FRMLEN_MASK	= (0x3FFF << 16),
	DESC_RXCTRL_RXCHAIN	= (1 << 24),
	DESC_RXCTRL_SIZE1MASK	= 0x7FF,
};

/***************\
* Driver State  *
\***************/

/* Everything the DMA engine reads or writes must be cache-line isolated so
 * our flush/invalidate on one object never clips another. 64 bytes is the
 * RISC-V RVA cache-block size and is also >= any dwmac descriptor alignment
 * requirement. The aligned attributes put each DMA object on its own 64-byte
 * boundary within the struct; the struct itself is 64-byte aligned because it
 * is the first malloc (the yalibc heap starts cache-line aligned), as the
 * other DMA NIC drivers rely on too. */
#define DWMAC3_DMA_ALIGN	64

struct dwmac3_nic {
	struct dwmac3_desc tx_desc __attribute__((aligned(DWMAC3_DMA_ALIGN)));
	struct dwmac3_desc rx_desc __attribute__((aligned(DWMAC3_DMA_ALIGN)));
	uint8_t tx_buff[TX_BUFF_SIZE] __attribute__((aligned(DWMAC3_DMA_ALIGN)));
	uint8_t rx_buff[RX_BUFF_SIZE] __attribute__((aligned(DWMAC3_DMA_ALIGN)));

	mac_addr_t smac_addr;
	int phy_addr;
	int rx_armed;	/* RX descriptor currently owned by the DMA engine */
};
typedef struct dwmac3_nic DwMac3Nic;

static DwMac3Nic *nic = NULL;

/*********\
* Helpers *
\*********/

static inline uint32_t
mac_read(uint16_t reg)
{
	return read32((const uint32_t *)(uintptr_t)(PLAT_DWMAC3_BASE_ADDR + reg));
}

static inline void
mac_write(uint16_t reg, uint32_t val)
{
	write32((uint32_t *)(uintptr_t)(PLAT_DWMAC3_BASE_ADDR + reg), val);
}

static inline uint32_t
desc_addr32(const void *ptr)
{
	/* Safe: _Static_assert above keeps all DMA memory below 4GB. */
	return (uint32_t)(uintptr_t)ptr;
}

/* Map the CSR (application) clock to the MDC divider select field. */
static uint32_t
mdc_clkrange(void)
{
	uint32_t hz = PLAT_DWMAC3_CSR_CLOCK_HZ;

	if (hz <= 35000000)
		return MII_CLKRANGE_20_35M;
	else if (hz <= 60000000)
		return MII_CLKRANGE_35_60M;
	else if (hz <= 100000000)
		return MII_CLKRANGE_60_100M;
	else if (hz <= 150000000)
		return MII_CLKRANGE_100_150M;
	else if (hz <= 250000000)
		return MII_CLKRANGE_150_250M;
	else
		return MII_CLKRANGE_250_300M;
}

/*******\
* MDIO  *
\*******/

static int
mdio_read(int phy, int reg)
{
	uint32_t addr = ((phy << MIIADDRSHIFT) & MII_ADDRMSK) |
			((reg << MIIREGSHIFT) & MII_REGMSK) |
			mdc_clkrange() | MII_BUSY;
	mac_write(MAC_MIIADDR, addr);

	int countdown = TX_ETH_RETRIES;	/* ~1ms, plenty for an MDC cycle */
	while (--countdown) {
		if (!(mac_read(MAC_MIIADDR) & MII_BUSY))
			return (int)(mac_read(MAC_MIIDATA) & 0xFFFF);
		nanosleep(&eth_tx_poll_delay, NULL);
	}
	return -ETIME;
}

static __attribute__((unused)) int
mdio_write(int phy, int reg, uint16_t val)
{
	mac_write(MAC_MIIDATA, val);
	uint32_t addr = ((phy << MIIADDRSHIFT) & MII_ADDRMSK) |
			((reg << MIIREGSHIFT) & MII_REGMSK) |
			mdc_clkrange() | MII_WRITE | MII_BUSY;
	mac_write(MAC_MIIADDR, addr);

	int countdown = TX_ETH_RETRIES;
	while (--countdown) {
		if (!(mac_read(MAC_MIIADDR) & MII_BUSY))
			return 0;
		nanosleep(&eth_tx_poll_delay, NULL);
	}
	return -ETIME;
}

/********\
* PHY    *
\********/

/* Generic MII register numbers (IEEE 802.3 clause 22) */
enum {
	MII_BMSR		= 1,	/* basic status */
	MII_PHYSID1		= 2,
	MII_ADVERTISE		= 4,	/* our 10/100 abilities */
	MII_LPA			= 5,	/* link partner 10/100 abilities */
	MII_CTRL1000		= 9,	/* our 1000 abilities */
	MII_STAT1000		= 10,	/* link partner 1000 abilities */
	MII_ESTATUS		= 15,	/* extended (1000) status */
};

/* BMSR bits */
enum {
	BMSR_LSTATUS		= 0x0004,
	BMSR_ANEGCOMPLETE	= 0x0020,
	BMSR_ESTATEN		= 0x0100,	/* MII_ESTATUS is valid */
};

/* ADVERTISE / LPA bits (10/100, same layout in both registers) */
enum {
	ADV_10HALF		= 0x0020,
	ADV_10FULL		= 0x0040,
	ADV_100HALF		= 0x0080,
	ADV_100FULL		= 0x0100,
};

/* CTRL1000 (our) / STAT1000 (partner) and ESTATUS gigabit bits */
enum {
	CTRL1000_HALF		= 0x0100,
	CTRL1000_FULL		= 0x0200,
	STAT1000_HALF		= 0x0400,
	STAT1000_FULL		= 0x0800,
	ESTATUS_1000_THALF	= 0x1000,
	ESTATUS_1000_TFULL	= 0x2000,
};

/* Find the ePHY on the MDIO bus (the board DTS gives no fixed address, and it
 * sits at 0 or 1 depending on the SoC) by scanning for a valid PHY id. */
static int
phy_scan(void)
{
	for (int addr = 0; addr < 32; addr++) {
		int id1 = mdio_read(addr, MII_PHYSID1);
		if (id1 < 0)
			continue;
		if (id1 == 0x0000 || id1 == 0xFFFF)
			continue;
		DBG_NET("[dwmac3] PHY at addr %i (id1 0x%04x)\n", addr, id1);
		return addr;
	}
	return -ENODEV;
}

/*
 * Wait for auto-negotiation / link up, resolve the negotiated speed and duplex
 * (generic genphy-style: 1000 from CTRL1000/STAT1000, 10/100 from ADVERTISE &
 * LPA), and hand back the matching MAC_CONF bits.
 */
static int
phy_wait_link(uint32_t *conf_bits)
{
	const struct timespec ts_10ms = { .tv_nsec = 10 * 1000 * 1000 };
	int countdown = 500;	/* 500 * 10ms = 5s */
	int phy = nic->phy_addr;
	int bmsr = 0;

	while (--countdown) {
		bmsr = mdio_read(phy, MII_BMSR);
		if (bmsr >= 0 && (bmsr & BMSR_LSTATUS) && (bmsr & BMSR_ANEGCOMPLETE))
			break;
		nanosleep(&ts_10ms, NULL);
	}
	if (bmsr < 0 || !(bmsr & BMSR_LSTATUS)) {
		WRN("[dwmac3] no link\n");
		return -ENETDOWN;
	}

	int speed = 10, duplex = 0;

	/* Gigabit resolution, only if the PHY advertises extended status. */
	int est = (bmsr & BMSR_ESTATEN) ? mdio_read(phy, MII_ESTATUS) : 0;
	if (est > 0 && (est & (ESTATUS_1000_TFULL | ESTATUS_1000_THALF))) {
		int ours = mdio_read(phy, MII_CTRL1000);
		int lp = mdio_read(phy, MII_STAT1000);
		if (ours >= 0 && lp >= 0) {
			if ((ours & CTRL1000_FULL) && (lp & STAT1000_FULL)) {
				speed = 1000;
				duplex = 1;
			} else if ((ours & CTRL1000_HALF) && (lp & STAT1000_HALF)) {
				speed = 1000;
				duplex = 0;
			}
		}
	}

	/* Fall back to the common 10/100 abilities. */
	if (speed != 1000) {
		int adv = mdio_read(phy, MII_ADVERTISE);
		int lpa = mdio_read(phy, MII_LPA);
		if (adv < 0 || lpa < 0)
			return -EIO;
		int common = adv & lpa;
		if (common & ADV_100FULL) {
			speed = 100;
			duplex = 1;
		} else if (common & ADV_100HALF) {
			speed = 100;
			duplex = 0;
		} else if (common & ADV_10FULL) {
			speed = 10;
			duplex = 1;
		} else {
			speed = 10;
			duplex = 0;
		}
	}

	/* dwmac-1000: GMII for gigabit (port-select clear), MII for 10/100
	 * (port-select set); FES only for 100M. */
	*conf_bits = 0;
	if (speed != 1000)
		*conf_bits |= MAC_CONF_MII_PORTSEL;
	if (speed == 100)
		*conf_bits |= MAC_CONF_FES_100;
	if (duplex)
		*conf_bits |= MAC_CONF_FULLDPLX;

	INF("[dwmac3] link up: %i Mbps, %s-duplex\n",
	    speed, duplex ? "full" : "half");
	return 0;
}

/****************\
* DMA / MAC init *
\****************/

static void
dwmac3_set_mac_addr(void)
{
	const uint8_t *m = mac_get_bytes(&nic->smac_addr);
	uint32_t lo = m[0] | (m[1] << 8) | (m[2] << 16) | ((uint32_t)m[3] << 24);
	uint32_t hi = m[4] | (m[5] << 8);
	mac_write(MAC_ADDR0_HI, hi);
	mac_write(MAC_ADDR0_LO, lo);
}

/* Arm the single RX descriptor: hand it to the DMA engine and nudge it. */
static void
dwmac3_arm_rx(void)
{
	nic->rx_desc.status = DESC_RXSTS_OWN;
	dma_cache_flush(&nic->rx_desc, sizeof(nic->rx_desc));
	mac_write(DMA_RXPOLL, DMA_POLL_DEMAND);
	nic->rx_armed = 1;
}

static int
dwmac3_dma_reset(void)
{
	const struct timespec ts_1ms = { .tv_nsec = 1000 * 1000 };
	int countdown = 1000;	/* 1s */

	mac_write(DMA_BUSMODE, mac_read(DMA_BUSMODE) | DMA_BUSMODE_SWR);
	while (--countdown) {
		if (!(mac_read(DMA_BUSMODE) & DMA_BUSMODE_SWR))
			return 0;
		nanosleep(&ts_1ms, NULL);
	}
	ERR("[dwmac3] DMA reset timeout\n");
	return -ETIME;
}

static int
dwmac3_hw_init(void)
{
	uint32_t conf_bits;
	int ret;

	/* Confirm we're talking to a dwmac-1000 (v3.x) before poking it. */
	uint32_t ver = mac_read(MAC_VERSION) & MAC_VER_SNPS_MASK;
	if (ver < 0x30 || ver >= 0x40) {
		ERR("[dwmac3] unexpected MAC version 0x%02x (need 0x3x)\n", ver);
		return -ENODEV;
	}
	DBG_NET("[dwmac3] DesignWare GMAC version 0x%02x\n", ver);

	/* Clear GMII port-select before the reset; it gets set per negotiated
	 * speed afterwards. */
	mac_write(MAC_CONF, mac_read(MAC_CONF) & ~MAC_CONF_MII_PORTSEL);

	ret = dwmac3_dma_reset();
	if (ret < 0)
		return ret;

	/* The soft reset cleared the MAC address registers. */
	dwmac3_set_mac_addr();

	/* Single self-chained TX descriptor, owned by the CPU. */
	nic->tx_desc.addr = desc_addr32(nic->tx_buff);
	nic->tx_desc.next = desc_addr32(&nic->tx_desc);
	nic->tx_desc.cntl = DESC_TXCTRL_TXCHAIN;
	nic->tx_desc.status = 0;
	dma_cache_flush(&nic->tx_desc, sizeof(nic->tx_desc));
	mac_write(DMA_TXDESC, desc_addr32(&nic->tx_desc));

	/* Single self-chained RX descriptor. Flush the buffer first so no stale
	 * dirty line is later evicted over DMA-written data. */
	dma_cache_flush(nic->rx_buff, sizeof(nic->rx_buff));
	nic->rx_desc.addr = desc_addr32(nic->rx_buff);
	nic->rx_desc.next = desc_addr32(&nic->rx_desc);
	nic->rx_desc.cntl = DESC_RXCTRL_RXCHAIN |
			    (sizeof(nic->rx_buff) & DESC_RXCTRL_SIZE1MASK);
	nic->rx_desc.status = DESC_RXSTS_OWN;
	dma_cache_flush(&nic->rx_desc, sizeof(nic->rx_desc));
	mac_write(DMA_RXDESC, desc_addr32(&nic->rx_desc));
	nic->rx_armed = 1;

	/* Program the DMA bus mode and start both engines. */
	mac_write(DMA_BUSMODE, DMA_BUSMODE_FIXEDBURST | DMA_BUSMODE_PRIORXTX_41 |
				DMA_BUSMODE_PBL8);
	mac_write(DMA_OPMODE, mac_read(DMA_OPMODE) | DMA_OPMODE_FLUSHTXFIFO |
				DMA_OPMODE_STOREFORWARD);
	mac_write(DMA_OPMODE, mac_read(DMA_OPMODE) | DMA_OPMODE_RXSTART |
				DMA_OPMODE_TXSTART);

	/* Bring up the PHY link and apply the negotiated speed/duplex. */
	ret = phy_wait_link(&conf_bits);
	if (ret < 0)
		return ret;

	mac_write(MAC_CONF, mac_read(MAC_CONF) | conf_bits |
			    MAC_CONF_FRAMEBURST | MAC_CONF_DISABLERXOWN |
			    MAC_CONF_RXENABLE | MAC_CONF_TXENABLE);
	return 0;
}

/**************\
* Entry Points *
\**************/

mac_addr_t*
eth_get_mac_addr(void)
{
	if (!nic)
		return NULL;
	return &nic->smac_addr;
}

uint8_t*
eth_get_tx_buff(size_t size)
{
	if (!nic)
		return NULL;
	if (size > TX_BUFF_SIZE) {
		ERR("[dwmac3] requested buffer size exceeds TX buffer length\n");
		return NULL;
	}
	memset(nic->tx_buff, 0, size);
	return nic->tx_buff;
}

int
eth_trigger_tx(size_t size)
{
	if (!nic)
		return -ENODEV;
	if (size == 0 || size > TX_BUFF_SIZE)
		return -EMSGSIZE;

	/* Push the frame out of the cache for the DMA engine. */
	dma_cache_flush(nic->tx_buff, size);

	/* Single-frame descriptor: first + last, CPU hands it to the DMA. */
	nic->tx_desc.cntl = DESC_TXCTRL_TXCHAIN | DESC_TXCTRL_TXFIRST |
			    DESC_TXCTRL_TXLAST |
			    ((uint32_t)size & DESC_TXCTRL_SIZE1MASK);
	nic->tx_desc.status = DESC_TXSTS_OWN;
	dma_cache_flush(&nic->tx_desc, sizeof(nic->tx_desc));

	mac_write(DMA_TXPOLL, DMA_POLL_DEMAND);

	int countdown = TX_ETH_RETRIES;
	while (--countdown) {
		dma_cache_inval(&nic->tx_desc, sizeof(nic->tx_desc));
		if (!(nic->tx_desc.status & DESC_TXSTS_OWN))
			return (int)size;
		nanosleep(&eth_tx_poll_delay, NULL);
	}
	WRN("[dwmac3] TX timeout\n");
	return -ETIME;
}

uint8_t*
eth_wait_for_rx_buff(ssize_t *size)
{
	if (!nic) {
		*size = -ENODEV;
		return NULL;
	}

	/* Re-arm the RX descriptor if we consumed a frame last time. */
	if (!nic->rx_armed)
		dwmac3_arm_rx();

	int countdown = RX_ETH_RETRIES;
	while (--countdown) {
		dma_cache_inval(&nic->rx_desc, sizeof(nic->rx_desc));
		uint32_t status = nic->rx_desc.status;
		if (!(status & DESC_RXSTS_OWN)) {
			/* Frame received; the descriptor is ours again. */
			nic->rx_armed = 0;
			uint32_t len = (status & DESC_RXSTS_FRMLEN_MASK) >>
				       DESC_RXSTS_FRMLEN_SHIFT;
			if (len == 0 || len > RX_BUFF_SIZE) {
				DBG_NET("[dwmac3] bad RX length %u\n", len);
				*size = -EMSGSIZE;
				return NULL;
			}
			dma_cache_inval(nic->rx_buff, len);
			*size = (ssize_t)len;
			return nic->rx_buff;
		}
		nanosleep(&eth_rx_poll_delay, NULL);
	}
	DBG_NET("[dwmac3] RX timeout\n");
	*size = -ETIME;
	return NULL;
}

int
eth_open(void)
{
	if (nic != NULL) {
		WRN("[dwmac3] driver already initialized\n");
		return -EBUSY;
	}

	/* First malloc in the netboot flow: the yalibc heap starts cache-line
	 * aligned, so the aligned(64) DMA members land on real 64-byte
	 * boundaries (same assumption as the other DMA NIC drivers). */
	nic = malloc(sizeof(DwMac3Nic));
	if (!nic)
		return -ENOMEM;
	memset(nic, 0, sizeof(DwMac3Nic));

	/* No eFuse MAC on this part; use a random locally-administered one. */
	nic->smac_addr = mac_get_random();
	DBG_NET("[dwmac3] using MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
	    nic->smac_addr.bytes[0], nic->smac_addr.bytes[1],
	    nic->smac_addr.bytes[2], nic->smac_addr.bytes[3],
	    nic->smac_addr.bytes[4], nic->smac_addr.bytes[5]);

	/* The ePHY is powered up and calibrated by platform_init(); find it. */
	int addr = phy_scan();
	if (addr < 0) {
		ERR("[dwmac3] no PHY found on MDIO bus\n");
		goto fail;
	}
	nic->phy_addr = addr;

	if (dwmac3_hw_init() < 0)
		goto fail;

	DBG_NET("[dwmac3] initialization complete\n");
	return 0;

 fail:
	free(nic);
	nic = NULL;
	return -ENODEV;
}

void
eth_close(void)
{
	if (!nic)
		return;

	/* Stop RX/TX and halt the DMA engines. */
	mac_write(MAC_CONF, mac_read(MAC_CONF) &
			    ~(MAC_CONF_RXENABLE | MAC_CONF_TXENABLE));
	mac_write(DMA_OPMODE, mac_read(DMA_OPMODE) &
			    ~(DMA_OPMODE_RXSTART | DMA_OPMODE_TXSTART));
	free(nic);
	nic = NULL;
}

#endif /* defined(PLAT_DWMAC3_BASE_ADDR) && (PLAT_DWMAC3_BASE_ADDR > 0) */
