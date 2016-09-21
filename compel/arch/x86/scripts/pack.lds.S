OUTPUT_ARCH(i386:x86-64)
SECTIONS
{
	. = ALIGN(64);
	.text : {
		*(.compel.prologue.text)
		*(.text*)
	} =0x0

	. = ALIGN(64);
	.compel.init : {
		*(.compel.init)
	} =0xff

	. = ALIGN(64);
	.data : {
		*(.data*)
		*(.bss*)
		*(.rodata*)
	} =0x0

	/DISCARD/ : {
		*(.debug*)
		*(.comment*)
		*(.note*)
		*(.group*)
		*(.eh_frame*)
		*(*)
	}
}
