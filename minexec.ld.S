OUTPUT_FORMAT("elf64-x86-64", "elf64-x86-64", "elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)

SECTIONS
{
	. = 0x400000;
	ENTRY(_start)

	.text : {
		*(.text)
		. = ALIGN(8);
	}

	.data ALIGN(0x2000) : {
		*(.data)
		*(.bss)
		. = ALIGN(8);
	}
}
