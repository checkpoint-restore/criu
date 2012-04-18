OUTPUT_ARCH(i386:x86-64)

SECTIONS
{
	.crblob 0x0 : {
		*(.head.text)
		*(.text)
		. = ALIGN(32);
		*(.data*)
		. = ALIGN(32);
		*(.rodata*)
		. = ALIGN(32);
		*(.bss*)
		. = ALIGN(32);
	} =0x00000000

	/DISCARD/ : {
		*(.debug*)
		*(.comment*)
		*(.note*)
		*(.group*)
		*(.eh_frame*)
		*(*)
	}
}
