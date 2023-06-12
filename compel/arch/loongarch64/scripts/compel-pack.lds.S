OUTPUT_ARCH(loongarch)
EXTERN(__export_parasite_head_start)

SECTIONS
{
	.crblob 0x0 : {
		*(.head.text)
		ASSERT(DEFINED(__export_parasite_head_start),
			"Symbol __export_parasite_head_start is missing");
		*(.text*)
		. = ALIGN(32);
		*(.data*)
		. = ALIGN(32);
		*(.rodata*)
		. = ALIGN(32);
		*(.bss*)
		. = ALIGN(32);
		*(.got*)
		. = ALIGN(32);
		*(.toc*)
		. = ALIGN(32);
	} =0x00000000,

	/DISCARD/ : {
		*(.debug*)
		*(.comment*)
		*(.note*)
		*(.group*)
		*(.eh_frame*)
		*(*)
	}
}
