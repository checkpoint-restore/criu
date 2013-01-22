        ENTRY(sys_mmap)
        push    { %r4, %r5, %r7 }
        ldr     %r4, [%sp, #12]
        ldr     %r5, [%sp, #16]
	lsr	%r5, #12
        do_sys  192
        pop     { %r4, %r5, %r7 }
        bx      %lr
        END(sys_mmap)