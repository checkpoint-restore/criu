OUTPUT_FORMAT("binary")
OUTPUT_ARCH(i386:x86-64)

SECTIONS
{
	. = 0;
	.text : {
		*(.head.text)
		*(.text)
		. = ALIGN(8);
	}
	.data : {
		*(.data)
		*(.rodata)
		*(.bss)
		. = ALIGN(8);
	}
}
