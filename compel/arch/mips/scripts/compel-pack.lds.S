OUTPUT_ARCH(mips)
EXTERN(__export_parasite_head_start)

SECTIONS
{
/*		. = 0x120000000 + SIZEOF_HEADERS; */
		. = ALIGN(32);	
	.text : {  
		*(.head.text)
		ASSERT(DEFINED(__export_parasite_head_start),	
			"Symbol __export_parasite_head_start is missing");
		. = ALIGN(32);	
        	*(.text*)
		. = ALIGN(32);
		*(.compel.exit)
		. = ALIGN(32);
		*(.compel.init)
		. = ALIGN(32);
		/* .rodata section*/
		*(.rodata*)
		. = ALIGN(32);
		*(.got*)
		. = ALIGN(32);
	       /* .data section */
		. = ALIGN(32);
		*(.data*)
		. = ALIGN(32);
		*(.bss*)
		. = ALIGN(32);
		*(.sbss*)
		. = ALIGN(32);
		*(.toc*)
	}

	/DISCARD/ : { /*释义：需要丢弃的输入文件段*/
		*(.debug*)
		*(.pdr)	
		*(.comment*)
		*(.note*)
		*(.group*)
		*(.eh_frame*)
		*(.MIPS.options)
		*(.gnu.attributes)
	}

/* Parasite args should have 4 bytes align, as we have futex inside. */
. = ALIGN(32);
__export_parasite_args = .;
}
