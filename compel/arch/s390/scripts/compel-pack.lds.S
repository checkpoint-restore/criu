OUTPUT_ARCH(s390:64-bit)
EXTERN(__export_parasite_head_start)

SECTIONS
{
	.text : {
		*(.head.text)
		ASSERT(DEFINED(__export_parasite_head_start),
			"Symbol __export_parasite_head_start is missing");
		*(.text*)
		*(.compel.exit)
		*(.compel.init)
	}

	.data : ALIGN(0x1000) {
		*(.data*)
		*(.bss*)
	}

	.rodata : {
		*(.rodata*)
		*(.got*)
	}

	.toc : ALIGN(8) {
		*(.toc*)
	}

	/DISCARD/ : {
		*(.debug*)
		*(.comment*)
		*(.note*)
		*(.group*)
		*(.eh_frame*)
	}
}
