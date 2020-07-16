OUTPUT_ARCH(mips)
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
		/* .rodata section*/
		*(.rodata*)
		*(.got*)
	       /* .data section */
		*(.data*)
		*(.bss*)
		*(.sbss*)
		*(.toc*)
	}

	/DISCARD/ : { /*segments need to discard */
		*(.debug*)
		*(.pdr)	
		*(.comment*)
		*(.note*)
		*(.group*)
		*(.eh_frame*)
		*(.MIPS.options)
		*(.gnu.attributes)
	}
}
