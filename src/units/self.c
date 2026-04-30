/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2026 Nick Kossifidis <mick@ics.forth.gr>
 * SPDX-FileCopyrightText: 2026 ICS/FORTH
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* Driver for Unit 0 (self) */
#include <img.h>
#include <utils.h>	/* For console output */
#include <errno.h>	/* For error codes */

#if !defined(HOST_TEST)
#include <target_config.h>		/* For PLAT_SYSRAM_BASE/PLAT_NO_MTIMER */
#include <platform/interfaces/timer.h>	/* For timer_nsecs_to_cycles */
#include <platform/riscv/csr.h>		/* For csr_read/CSR_MHARTID */
#include <platform/riscv/hart.h>	/* For hart_wakeup_all_with_addr() */

/* Payload should be at a 4byte alligned address so
 * that the first instruction can be fetched correctly
 * however in order to be able to map it using hugepages
 * we allign it to the size of the 2nd page table level
 * which for Sv39 is 2MB. */
#define PAYLOAD_ALIGN	(2 * MB)
#define FDT_ALIGN (16)

#if !defined(PLAT_SYSRAM_BASE) || (PLAT_SYSRAM_BASE == 0)
	#error "No PLAT_SYSRAM_BASE defined, don't know where to place boot images !"
#endif

#define PAYLOAD_BASE	(((PLAT_SYSRAM_BASE) + (PAYLOAD_ALIGN) - 1) & ~((PAYLOAD_ALIGN) - 1))
#define FDT_BASE(x)	(((x) + (FDT_ALIGN) - 1) & ~((FDT_ALIGN) - 1))
static uintptr_t fdt_base = 0;

int
unit_handler_self(unit_cmd_t cmd, uintptr_t *img_base, size_t *max_img_size)
{
	switch(cmd) {
		case UNIT_CMD_GET_REGION:
			unsigned int type = (*img_base & 0xF);
			switch (type) {
				case IMG_TYPE_BOOT_STEP:
				case IMG_TYPE_FBSL:
					*img_base = (uintptr_t)(PAYLOAD_BASE);
					/* XXX: For now stick with 256MB, should be more than enough */
					*max_img_size = (size_t)(256 * MB);
					return 0;
				case IMG_TYPE_DTB:
					if (*max_img_size == 0)
						return -EPROTO;
					*img_base = (uintptr_t)FDT_BASE(PAYLOAD_BASE + *max_img_size);
					*max_img_size = (size_t)(256 * MB) - *max_img_size;
					fdt_base = *img_base;
					return 0;
				default:
					return -EPROTO;
			}
			break;
		case UNIT_CMD_EXEC_IMAGE:
			/* TODO */
			break;
		case UNIT_CMD_FSBL_JUMP:
			DBG("Jumping to FSBL...\n");
			uint64_t hart_id = csr_read(CSR_MHARTID);
			uint64_t mtimer_cycles = 0;
			#ifndef PLAT_NO_MTIMER
				/* Wake them all up in 100msec */
				mtimer_cycles = timer_nsecs_to_cycles(CLOCK_REALTIME, 100000000);
			#endif
			hart_wakeup_all_with_addr((uintptr_t)(PAYLOAD_BASE), hart_id, fdt_base, mtimer_cycles);
		default:
			return -EPROTO;
	}
	return 0;
}

REGISTER_UNIT_CB(UNIT_ID_SELF, unit_handler_self);

#else /* !defined(HOST_TEST) */

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

/* Global state for current mmap region */
static void *current_mmap = NULL;
static size_t current_mmap_size = 0;
static int current_part_id = 0;
static size_t part0_size = 0;  /* Track actual sizes for truncation */
static size_t part1_size = 0;

#define FSBL_SIZE (256 * 1024 * 1024)  /* 256MB */
#define DTB_SIZE  (64 * 1024)           /* 64KB */

/* Helper to get partition size for truncation */
size_t
test_get_partition_size(int part_id) {
	if (part_id == 0) return part0_size;
	if (part_id == 1) return part1_size;
	return 0;
}

static void
cleanup_mmap(void)
{
	if (current_mmap != NULL) {
		msync(current_mmap, current_mmap_size, MS_SYNC);
		munmap(current_mmap, current_mmap_size);
		current_mmap = NULL;
		current_mmap_size = 0;
	}
}

int
unit_handler_self(unit_cmd_t cmd, uintptr_t *img_base, size_t *max_img_size)
{
	DBG("[HOST_TEST] unit_handler_self: cmd=%d\n", cmd);
	switch(cmd) {
		case UNIT_CMD_GET_REGION: {
			/* Clean up previous mapping */
			cleanup_mmap();

			unsigned int type = (*img_base & 0xF);
			DBG("[HOST_TEST] GET_REGION: type=%u part=%d\n", type, current_part_id);

			/* For DTB (partition 1), max_img_size contains partition 0's actual size */
			if (current_part_id == 1 && type == IMG_TYPE_DTB) {
				part0_size = *max_img_size;
				DBG("[HOST_TEST] Part 0 actual size: %zu bytes\n", part0_size);
			}

			size_t size = 0;
			char filename[32];

			switch (type) {
				case IMG_TYPE_BOOT_STEP:
				case IMG_TYPE_FBSL:
					size = FSBL_SIZE;
					snprintf(filename, sizeof(filename), "/tmp/part%d.bin", current_part_id);
					break;
				case IMG_TYPE_DTB:
					size = DTB_SIZE;
					snprintf(filename, sizeof(filename), "/tmp/part%d.bin", current_part_id);
					break;
				default:
					return -EPROTO;
			}

			/* Create and size the file */
			int fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0644);
			if (fd < 0) {
				ERR("open %s: %s\n", filename, strerror(errno));
				return -errno;
			}

			if (ftruncate(fd, size) < 0) {
				ERR("ftruncate %s: %s\n", filename, strerror(errno));
				close(fd);
				return -errno;
			}

			/* mmap the file */
			void *addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
			close(fd);  /* Can close fd after mmap */

			if (addr == MAP_FAILED) {
				ERR("mmap %s: %s\n", filename, strerror(errno));
				return -errno;
			}

			/* Store state */
			current_mmap = addr;
			current_mmap_size = size;
			*img_base = (uintptr_t)addr;
			*max_img_size = size;

			DBG("[HOST_TEST] Part %d: %s (%zu bytes) at %p\n",
			       current_part_id, filename, size, addr);
			current_part_id++;

			return 0;
		}
		case UNIT_CMD_EXEC_IMAGE:
			/* Not supported in HOST_TEST */
			return -EPROTO;
		case UNIT_CMD_FSBL_JUMP:
			/* Clean up and finish */
			cleanup_mmap();
			DBG("[HOST_TEST] FSBL_JUMP: done\n");
			return 0;
		default:
			return -EPROTO;
	}
	return 0;
}

unit_handler_fn
imgp_get_unit_handler(uint32_t unit_id) {
	(void)unit_id;
	return unit_handler_self;
}
#endif /* !defined(HOST_TEST) */