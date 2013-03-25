#include "asm/linkage.h"

        .macro mov_r7 imm
        mov %r7, #\imm
        .endm


        // Call the kernel

        .macro do_sys opcode
        movw    %r7, #\opcode
        svc     #0
        .endm


        // a syscall with 0-4 arguments

        .macro syscall0 name, opcode
        ENTRY(\name)
        push    { %r7 }
        do_sys  \opcode
        pop     { %r7 }
        bx      %lr
        END(\name)
        .endm


        // a syscall with 5 arguments

        .macro syscall5 name, opcode
        ENTRY(\name)
        push    { %r4, %r7 }
        ldr     %r4, [%sp, #8]
        do_sys  \opcode
        pop     { %r4, %r7 }
        bx      %lr
        END(\name)
        .endm


        // a syscall with 6 arguments

        .macro syscall6 name, opcode
        ENTRY(\name)
        push    { %r4, %r5, %r7 }
        ldr     %r4, [%sp, #12]
        ldr     %r5, [%sp, #16]
        do_sys  \opcode
        pop     { %r4, %r5, %r7 }
        bx      %lr
        END(\name)
        .endm

ENTRY(__cr_restore_rt)
	do_sys __NR_rt_sigreturn
END(__cr_restore_rt)
