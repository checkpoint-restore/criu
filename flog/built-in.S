SECTIONS
{
	.rodata : { _rodata_start = . ; *(.rodata*) ; _rodata_end = . ;}
}
