/*
 * Supplementary linker script for NetBoot.
 * This extends the base linker script without modifying it.
 *
 * Creates a read-only unit callbacks array section that is
 * grouped with .rodata in the same loadable segment (PT_LOAD
 * with :rodata program header).
 *
 * Implementation notes:
 * - Input section __uid_cbs won't match the base script's
 *   .rodata.* wildcard, preventing them from being consumed by
 *   the base .rodata output section.
 * - Output sections are placed in rom region after .data's LMA
 * - KEEP() prevents garbage collection during linking
 * - No runtime copying needed - accessed directly from ROM like .rodata
 */

SECTIONS
{
	.uid_cbs : {
		__start_rodata_uid_cbs = .;
		KEEP(*(__uid_cbs))
		. = ALIGN(16);
		__stop_rodata_uid_cbs = .;
	} > rom :rodata
}
