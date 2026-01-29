/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2025 Nick Kossifidis <mick@ics.forth.gr>
 * SPDX-FileCopyrightText: 2025 ICS/FORTH
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <target_config.h>	/* For PLAT_VIRTIO_NET_BASE_ADDR */
#include <platform/riscv/mmio.h>	/* For read32/write32 */
#include <platform/utils/bitfield.h>	/* For BIT macro */
#include <platform/utils/utils.h>	/* For console output */

#include <net.h>
#include <errno.h>	/* For errno values */
#include <stdlib.h>	/* For malloc/free */
#include <string.h>	/* For memset */
#include <time.h>	/* For nanosleep */
#include <stdatomic.h>	/* For atomic_thread_fence */

/* Note all section references are based on virtio spec v1.2:
 * https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html
 */

#if defined(PLAT_VIRTIO_NET_BASE_ADDR) && (PLAT_VIRTIO_NET_BASE_ADDR > 0)


/***************************\
* GENERIC VIRTIO MMIO LAYER *
\***************************/

/*
 * VirtIO Device status bits (section 2.1)
 */
enum virtio_status {
	VIRTIO_STATUS_ACKNOWLEDGE = BIT(0),
	VIRTIO_STATUS_DRIVER = BIT(1),
	VIRTIO_STATUS_DRIVER_OK = BIT(2),
	VIRTIO_STATUS_FEATURES_OK = BIT(3),
	VIRTIO_STATUS_DEVICE_NEEDS_RESET = BIT(4),
	VIRTIO_STATUS_FAILED = BIT(5),
};

/* Generic feature bits we care about (chapter 6) */
#define VIRTIO_F_VERSION_1		32

/*
 * Generic VirtIO MMIO Device register layout (section 4.2.2)
 */
#define VIRTIO_MMIO_MAGIC_VALUE		0x000
#define VIRTIO_MMIO_VERSION		0x004
#define VIRTIO_MMIO_DEVICE_ID		0x008
#define VIRTIO_MMIO_VENDOR_ID		0x00c
#define VIRTIO_MMIO_DEVICE_FEATURES	0x010
#define VIRTIO_MMIO_DEVICE_FEATURES_SEL	0x014
#define VIRTIO_MMIO_DRIVER_FEATURES	0x020
#define VIRTIO_MMIO_DRIVER_FEATURES_SEL	0x024
#define VIRTIO_MMIO_QUEUE_SEL		0x030
#define VIRTIO_MMIO_QUEUE_NUM_MAX	0x034
#define VIRTIO_MMIO_QUEUE_NUM		0x038
#define VIRTIO_MMIO_QUEUE_READY		0x044
#define VIRTIO_MMIO_QUEUE_NOTIFY	0x050
#define VIRTIO_MMIO_INTERRUPT_STATUS	0x060
#define VIRTIO_MMIO_INTERRUPT_ACK	0x064
#define VIRTIO_MMIO_STATUS		0x070
#define VIRTIO_MMIO_QUEUE_DESC_LOW	0x080
#define VIRTIO_MMIO_QUEUE_DESC_HIGH	0x084
#define VIRTIO_MMIO_QUEUE_AVAIL_LOW	0x090
#define VIRTIO_MMIO_QUEUE_AVAIL_HIGH	0x094
#define VIRTIO_MMIO_QUEUE_USED_LOW	0x0a0
#define VIRTIO_MMIO_QUEUE_USED_HIGH	0x0a4
#define VIRTIO_MMIO_CONFIG_GENERATION	0x0fc
#define VIRTIO_MMIO_CONFIG		0x100

/* Expected magic value */
#define VIRTIO_MMIO_MAGIC		0x74726976

/*********\
* Helpers *
\*********/

/* MMIO register access helpers */
static inline uint32_t
virtio_mmio_reg_read32(uint32_t reg)
{
	uintptr_t addr = (uintptr_t)(PLAT_VIRTIO_NET_BASE_ADDR + reg);
	return read32((const uint32_t *)addr);
}

static inline void
virtio_mmio_reg_write32(uint32_t reg, uint32_t val)
{
	uintptr_t addr = (uintptr_t)(PLAT_VIRTIO_NET_BASE_ADDR + reg);
	write32((uint32_t *)addr, val);
}

/********************\
* Virtqueue handling *
\********************/

/* Note: We'll use 2 descriptors/buffers per queue, one for
 * the virtio_net_hdr (see below), and one for the buffer.
 * This way we can return a pointer-size-aligned buffer to
 * the caller, as expected (as if the buffer was malloced),
 * otherwise we'd have to return a pointer at the end of
 * the header, that would be 4b aligned instead of 8b aligned. */

/* Virtqueue descriptor format (section 2.7.5) */
struct virtq_desc {
	uint64_t addr;
	uint32_t len;
	uint16_t flags;
	uint16_t next;
};

/* Virtqueue descriptor flags we care about */
#define VIRTQ_DESC_F_NEXT		1
#define VIRTQ_DESC_F_WRITE		2

/* Virtqueue available ring (section 2.7.6) */
struct virtq_avail {
	uint16_t flags;
	uint16_t idx;
	uint16_t ring[2];
	uint16_t used_event;
};

/* Suppress notifications from device to driver */
#define VIRTQ_AVAIL_F_NO_INTERRUPT	1

/* Virtqueue used element (section 2.7.8) */
struct virtq_used_elem {
	uint32_t id;
	uint32_t len;
};

/* Virtqueue used ring (section 2.7.8) */
struct virtq_used {
	uint16_t flags;
	uint16_t idx;
	struct virtq_used_elem ring[2];
	uint16_t avail_event;
};

/* Split virtqueue (chapter 2.7) */
struct virtq {
	struct virtq_desc desc[2] __attribute__((aligned(16)));
	struct virtq_avail avail __attribute__((aligned(2)));
	struct virtq_used used __attribute__((aligned(4)));
};

/* Setup a virtqueue (simplified for single descriptor) */
static int
virtio_mmio_setup_queue(uint32_t queue_idx, struct virtq *vq)
{
	virtio_mmio_reg_write32(VIRTIO_MMIO_QUEUE_SEL, queue_idx);

	/* Check queue exists */
	uint32_t max_size = virtio_mmio_reg_read32(VIRTIO_MMIO_QUEUE_NUM_MAX);
	if (max_size == 0) {
		ERR("[VirtioNet] Queue %u doesn't exist\n", queue_idx);
		return -ENODEV;
	}

	/* We only need 2 descriptors */
	virtio_mmio_reg_write32(VIRTIO_MMIO_QUEUE_NUM, 2);

	/* Set queue descriptor table address (64-bit physical address) */
	uint64_t desc_addr = (uint64_t)(uintptr_t)&vq->desc;
	virtio_mmio_reg_write32(VIRTIO_MMIO_QUEUE_DESC_LOW, (uint32_t)desc_addr);
	virtio_mmio_reg_write32(VIRTIO_MMIO_QUEUE_DESC_HIGH, (uint32_t)(desc_addr >> 32));

	/* Set queue available ring address (64-bit physical address) */
	uint64_t avail_addr = (uint64_t)(uintptr_t)&vq->avail;
	virtio_mmio_reg_write32(VIRTIO_MMIO_QUEUE_AVAIL_LOW, (uint32_t)avail_addr);
	virtio_mmio_reg_write32(VIRTIO_MMIO_QUEUE_AVAIL_HIGH, (uint32_t)(avail_addr >> 32));

	/* Set queue used ring address (64-bit physical address) */
	uint64_t used_addr = (uint64_t)(uintptr_t)&vq->used;
	virtio_mmio_reg_write32(VIRTIO_MMIO_QUEUE_USED_LOW, (uint32_t)used_addr);
	virtio_mmio_reg_write32(VIRTIO_MMIO_QUEUE_USED_HIGH, (uint32_t)(used_addr >> 32));

	/* Mark queue ready */
	virtio_mmio_reg_write32(VIRTIO_MMIO_QUEUE_READY, 1);

	return 0;
}

/*************************************\
* Generic VirtIO MMIO device handling *
\*************************************/

/* Get/set status bits */
static inline uint32_t
virtio_mmio_get_status(void)
{
	return virtio_mmio_reg_read32(VIRTIO_MMIO_STATUS);
}

static inline void
virtio_mmio_update_status(uint32_t bits)
{
	uint32_t curr_status = virtio_mmio_reg_read32(VIRTIO_MMIO_STATUS);
	virtio_mmio_reg_write32(VIRTIO_MMIO_STATUS, curr_status | bits);
}

/* Reset the virtio device */
static void
virtio_mmio_reset_device(void)
{
	virtio_mmio_reg_write32(VIRTIO_MMIO_STATUS, 0);
	/* According to 2.4.2 "The driver SHOULD consider a
	 * driver-initiated reset complete when it reads device
	 * status as 0.", so let's poll status register as required. */
	int countdown = 10;
	const struct timespec ts = { .tv_nsec = 10 * 1000 }; /* 10μs */
	while(countdown-- > 0) {
		uint32_t status = virtio_mmio_reg_read32(VIRTIO_MMIO_STATUS);
		if (status == 0)
			return;
		nanosleep(&ts, NULL);
	}
	WRN("[VirtioNet] Device failed to complete reset on time\n");
}

/* Check if a feature bit is offered by device */
static int
virtio_mmio_device_has_feature(uint32_t feature)
{
	uint32_t sel = feature / 32;
	uint32_t bit = feature % 32;
	
	virtio_mmio_reg_write32(VIRTIO_MMIO_DEVICE_FEATURES_SEL, sel);
	uint32_t features = virtio_mmio_reg_read32(VIRTIO_MMIO_DEVICE_FEATURES);
	
	return (features & (1U << bit)) != 0;
}

/* Enable/disable a feature bit */
static void
virtio_mmio_set_feature(uint32_t feature, int enabled)
{
	uint32_t sel = feature / 32;
	uint32_t bit = feature % 32;
	
	virtio_mmio_reg_write32(VIRTIO_MMIO_DRIVER_FEATURES_SEL, sel);
	uint32_t features = virtio_mmio_reg_read32(VIRTIO_MMIO_DRIVER_FEATURES);
	if (enabled)
		features |= (1U << bit);
	else
		features &= ~(1U << bit);
	virtio_mmio_reg_write32(VIRTIO_MMIO_DRIVER_FEATURES, features);
}

static int
virtio_mmio_commit_features(void)
{
	/* Set FEATURES_OK and check if they were accepted */
	virtio_mmio_update_status(VIRTIO_STATUS_FEATURES_OK);
	uint32_t status = virtio_mmio_reg_read32(VIRTIO_MMIO_STATUS);
	if (!(status & VIRTIO_STATUS_FEATURES_OK)) {
		ERR("[VirtioNet] Device rejected features\n");
		return -ENOSYS;
	}
	
	DBG_NET("[VirtioNet] Feature negotiation complete\n");
	return 0;
}

/* VirtIO Network device specific, chapter 5.1 */
#define VIRTIO_DEVICE_ID_NET		1

/* Feature bits we care about */
#define VIRTIO_NET_F_MAC		5
#define VIRTIO_NET_F_STATUS		16

static int
virtio_mmio_net_device_init(void)
{
	/* Note: Driver Initialization requirements,
	 * section 4.2.3.1.1 */

	/* Verify this is a virtio device */
	uint32_t magic = virtio_mmio_reg_read32(VIRTIO_MMIO_MAGIC_VALUE);
	if (magic != VIRTIO_MMIO_MAGIC) {
		ERR("[VirtioNet] Invalid magic value: 0x%x (expected 0x%x)\n",
		    magic, VIRTIO_MMIO_MAGIC);
		return -ENODEV;
	}
	
	/* Check version (we support version 2 = modern virtio) */
	uint32_t version = virtio_mmio_reg_read32(VIRTIO_MMIO_VERSION);
	if (version != 2) {
		ERR("[VirtioNet] Unsupported virtio version: %u (need 2)\n", version);
		return -ENODEV;
	}
	
	/* Verify this is a network device */
	uint32_t device_id = virtio_mmio_reg_read32(VIRTIO_MMIO_DEVICE_ID);
	if (device_id != VIRTIO_DEVICE_ID_NET) {
		ERR("[VirtioNet] Wrong device ID: %u (expected %u)\n",
		    device_id, VIRTIO_DEVICE_ID_NET);
		return -ENODEV;
	}
	
	DBG_NET("[VirtioNet] Found virtio-net device (version %u)\n", version);
	virtio_mmio_reset_device();

	/* Let device know that we discovered it and that we
	 * know how to drive it.*/
	virtio_mmio_update_status(VIRTIO_STATUS_ACKNOWLEDGE);
	virtio_mmio_update_status(VIRTIO_STATUS_DRIVER);

	/* Feature negotiation, handle the bare minimum. We won't need fragmentation
	 * so TSO/USO/GSO is out of the picture, we'll only have a single RX queue
	 * so RSS is also out of the picture, no jumbo frames, no excess reporting etc.
	 */

	/* We need VIRTIO_F_VERSION_1 for modern virtio */
	if (!virtio_mmio_device_has_feature(VIRTIO_F_VERSION_1)) {
		ERR("[VirtioNet] Device doesn't support VERSION_1\n");
		goto fail;
	}
	virtio_mmio_set_feature(VIRTIO_F_VERSION_1, 1);
	
	/* Try to get MAC address from device if available */
	if (virtio_mmio_device_has_feature(VIRTIO_NET_F_MAC)) {
		virtio_mmio_set_feature(VIRTIO_NET_F_MAC, 1);
		DBG_NET("[VirtioNet] Device provides MAC address\n");
	}

	int ret = virtio_mmio_commit_features();
	if (!ret)
		return 0;

 fail:
	virtio_mmio_reg_write32(VIRTIO_MMIO_STATUS, VIRTIO_STATUS_FAILED);
	return -ENODEV;
}

/* Read MAC address from device config space (see struct virtio_net_config, chapter 5.1.4 )*/
static void
virtio_mmio_net_read_mac(mac_addr_t *mac)
{
	uint32_t mac_lo = virtio_mmio_reg_read32(VIRTIO_MMIO_CONFIG);
	uint32_t mac_hi = virtio_mmio_reg_read32(VIRTIO_MMIO_CONFIG + 4);

	uint64_t mac_val = (uint64_t)mac_lo | ((uint64_t)mac_hi << 32);
	mac_set_u64(mac, mac_val);
}


/******************\
* VIRTIO NET LAYER *
\******************/

/* Virtio net header (prepended to each ethernet frame), section 5.1.6 */
struct virtio_net_hdr {
	uint8_t flags;
	uint8_t gso_type;
	uint16_t hdr_len;
	uint16_t gso_size;
	uint16_t csum_start;
	uint16_t csum_offset;
	uint16_t num_buffers;
};

/* Complete NIC state with embedded structures, this will be malloced */
struct virtio_net_nic {
	/* MAC address first (8 bytes on pointer-aligned base) */
	mac_addr_t mac_addr;

	/* Flag to track if RX descriptor is posted */
	int rx_posted;

	/* Index tracking for completion detection */
	uint16_t tx_last_used_idx;
	uint16_t rx_last_used_idx;

	/* Virtqueues (first desc needs 16-byte alignment) */
	struct virtq txq __attribute__((aligned(16)));
	struct virtq rxq __attribute__((aligned(16)));

	/* Separate headers and frames for proper alignment */
	struct virtio_net_hdr tx_hdr __attribute__((aligned(8)));
	struct virtio_net_hdr rx_hdr __attribute__((aligned(8)));
	uint8_t tx_frame[TX_BUFF_SIZE] __attribute__((aligned(8)));
	uint8_t rx_frame[RX_BUFF_SIZE] __attribute__((aligned(8)));
};

typedef struct virtio_net_nic VirtioNetNic;

/* Global NIC instance */
static VirtioNetNic *vnic = NULL;

/* Queue indices */
#define VIRTIO_NET_RXQ			0
#define VIRTIO_NET_TXQ			1

static int
virtio_net_init(void)
{
	/* Already initialized */
	if (vnic)
		return -EINVAL;

	int ret;

	/* Single malloc for entire NIC state */
	vnic = malloc(sizeof(VirtioNetNic));
	if (!vnic) {
		ERR("[VirtioNet] Failed to allocate NIC state\n");
		return -ENOMEM;
	}
	memset(vnic, 0, sizeof(VirtioNetNic));

	/* Initialize device */
	ret = virtio_mmio_net_device_init();
	if (ret < 0) {
		ERR("[VirtioNet] Device init failed: %d\n", ret);
		goto err_free;
	}

	/* Setup TX queue */
	ret = virtio_mmio_setup_queue(VIRTIO_NET_TXQ, &vnic->txq);
	if (ret < 0) {
		ERR("[VirtioNet] TX queue setup failed: %d\n", ret);
		goto err_reset;
	}

	/* Setup RX queue */
	ret = virtio_mmio_setup_queue(VIRTIO_NET_RXQ, &vnic->rxq);
	if (ret < 0) {
		ERR("[VirtioNet] RX queue setup failed: %d\n", ret);
		goto err_reset;
	}

	/* Get or generate MAC address */
	ret = virtio_mmio_device_has_feature(VIRTIO_NET_F_MAC);
	if (ret) {
		virtio_mmio_net_read_mac(&vnic->mac_addr);
	} else {
		vnic->mac_addr = mac_get_random();
	}
	DBG_NET("[VirtioNet] Got MAC (%s): %02X:%02X:%02X:%02X:%02X:%02X\n",
	    ret ? "provided" : "random",
	    vnic->mac_addr.bytes[0], vnic->mac_addr.bytes[1],
	    vnic->mac_addr.bytes[2], vnic->mac_addr.bytes[3],
	    vnic->mac_addr.bytes[4], vnic->mac_addr.bytes[5]);

	/* Device ready */
	virtio_mmio_update_status(VIRTIO_STATUS_DRIVER_OK);
	
	DBG_NET("[VirtioNet] Initialization complete\n");
	return 0;
	
err_reset:
	virtio_mmio_reset_device();
err_free:
	free(vnic);
	vnic = NULL;
	return ret;
}

/**************\
* Entry points *
\**************/

int
eth_open(void)
{
	return virtio_net_init();
}

void
eth_close(void)
{
	if (!vnic)
		return;

	virtio_mmio_reset_device();
	free(vnic);
	vnic = NULL;
	DBG_NET("[VirtioNet] Device closed\n");
}

uint8_t*
eth_get_tx_buff(size_t size)
{
	if (!vnic)
		return NULL;

	if (size > TX_BUFF_SIZE) {
		ERR("[VirtioNet] TX size %zu exceeds max %u\n", size, TX_BUFF_SIZE);
		return NULL;
	}

	/* Clear header and frame separately */
	memset(&vnic->tx_hdr, 0, sizeof(struct virtio_net_hdr));
	memset(vnic->tx_frame, 0, size);
	return vnic->tx_frame;
}

int
eth_trigger_tx(size_t size)
{
	if (!vnic)
		return -ENODEV;

	if (size > TX_BUFF_SIZE) {
		ERR("[VirtioNet] TX size %zu exceeds max %u\n", size, TX_BUFF_SIZE);
		return -EMSGSIZE;
	}

	/* Setup descriptor 0: virtio_net_hdr (read-only for device) */
	vnic->txq.desc[0].addr = (uint64_t)(uintptr_t)&vnic->tx_hdr;
	vnic->txq.desc[0].len = sizeof(struct virtio_net_hdr);
	vnic->txq.desc[0].flags = VIRTQ_DESC_F_NEXT;  // ← Chain to next
	vnic->txq.desc[0].next = 1;  // ← Points to descriptor 1

	/* Setup descriptor 1: ethernet frame (read-only for device) */
	vnic->txq.desc[1].addr = (uint64_t)(uintptr_t)vnic->tx_frame;
	vnic->txq.desc[1].len = (uint32_t)size;
	vnic->txq.desc[1].flags = 0;  // ← No chaining, end of chain
	vnic->txq.desc[1].next = 0;

	/* Post descriptor chain to available ring (head = descriptor 0) */
	vnic->txq.avail.ring[0] = 0;  // ← Start with descriptor 0
	vnic->txq.avail.flags = VIRTQ_AVAIL_F_NO_INTERRUPT;
	/* Ensure descriptor writes complete before updating idx */
	atomic_thread_fence(memory_order_release);
	vnic->txq.avail.idx++;

	/* Notify device */
	virtio_mmio_reg_write32(VIRTIO_MMIO_QUEUE_NOTIFY, VIRTIO_NET_TXQ);

	/* Poll for completion */
	int countdown = TX_ETH_RETRIES;
	while (countdown-- > 0) {
		if (vnic->txq.used.idx != vnic->tx_last_used_idx) {
			vnic->tx_last_used_idx = vnic->txq.used.idx;
			return size;
		}
		nanosleep(&eth_tx_poll_delay, NULL);
	}

	WRN("[VirtioNet] TX timeout\n");
	return -ETIME;
}

uint8_t*
eth_wait_for_rx_buff(ssize_t *size)
{
	if (!vnic) {
		*size = -ENODEV;
		return NULL;
	}

	/* Setup RX descriptor chain if not already posted */
	if (!vnic->rx_posted) {
		/* Setup descriptor 0: virtio_net_hdr (writable for device) */
		vnic->rxq.desc[0].addr = (uint64_t)(uintptr_t)&vnic->rx_hdr;
		vnic->rxq.desc[0].len = sizeof(struct virtio_net_hdr);
		vnic->rxq.desc[0].flags = VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE;
		vnic->rxq.desc[0].next = 1;

		/* Setup descriptor 1: ethernet frame (writable for device) */
		vnic->rxq.desc[1].addr = (uint64_t)(uintptr_t)vnic->rx_frame;
		vnic->rxq.desc[1].len = RX_BUFF_SIZE;
		vnic->rxq.desc[1].flags = VIRTQ_DESC_F_WRITE;
		vnic->rxq.desc[1].next = 0;

		vnic->rxq.avail.ring[0] = 0;  // ← Start with descriptor 0
		vnic->rxq.avail.flags = VIRTQ_AVAIL_F_NO_INTERRUPT;
		atomic_thread_fence(memory_order_release);
		vnic->rxq.avail.idx++;

		virtio_mmio_reg_write32(VIRTIO_MMIO_QUEUE_NOTIFY, VIRTIO_NET_RXQ);
		vnic->rx_posted = 1;
	}

	/* Poll for received packet */
	int countdown = RX_ETH_RETRIES;
	while (countdown-- > 0) {
		atomic_thread_fence(memory_order_acquire);
		if (vnic->rxq.used.idx != vnic->rx_last_used_idx) {
			/* Got a packet! Device writes total bytes across entire chain */
			uint16_t slot = vnic->rx_last_used_idx % 2;
			uint32_t total_len = vnic->rxq.used.ring[slot].len;
			vnic->rx_last_used_idx = vnic->rxq.used.idx;

			/* Make sure received length is ok */
			if (total_len < sizeof(struct virtio_net_hdr)) {
				DBG_NET("[VirtioNet] RX packet too small: %u\n", total_len);
				vnic->rx_posted = 0; /* Will re-post on next call */
				*size = -EMSGSIZE;
				return NULL;
			}

			uint32_t frame_len = total_len - sizeof(struct virtio_net_hdr);
			if (frame_len > RX_BUFF_SIZE) {
				DBG_NET("[VirtioNet] RX frame too large: %u\n", frame_len);
				vnic->rx_posted = 0;
				*size = -EMSGSIZE;
				return NULL;
			}

			/* Valid packet, let device know the descriptors are
			 * available again. */
			atomic_thread_fence(memory_order_release);
			vnic->rxq.avail.idx++;
			*size = frame_len;
			return vnic->rx_frame;
		}
		nanosleep(&eth_rx_poll_delay, NULL);
	}

	DBG_NET("[VirtioNet] RX timeout\n");
	vnic->rx_posted = 0;
	*size = -ETIME;
	return NULL;
}

mac_addr_t* eth_get_mac_addr(void)
{
	return vnic ? &vnic->mac_addr : NULL;
}

#endif /* defined(PLAT_VIRTIO_NET_BASE_ADDR) && (PLAT_VIRTIO_NET_BASE_ADDR > 0) */