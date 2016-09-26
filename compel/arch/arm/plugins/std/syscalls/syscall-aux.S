nr_sys_mmap:
	.long	192

ENTRY(sys_mmap)
	push	{r4, r5, r7, lr}
	ldr		r4, [sp, #16]
	ldr		r5, [sp, #20]
	lsr		r5, #12
	adr		r7, nr_sys_mmap
	ldr		r7, [r7]
	svc		0x00000000
	pop		{r4, r5, r7, pc}
END(sys_mmap)
