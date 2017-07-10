#include "common/asm/linkage.h"
#include "compel/plugins/std/syscall-codes.h"

	.text
ENTRY(__export_unmap_compat)
	.code32
	mov	bootstrap_start, %ebx
	mov	bootstrap_len, %ecx
	sub	vdso_rt_size, %ecx
	movl	$__NR32_munmap, %eax
	int	$0x80
	int	$0x03 /* Guard */
	.code64
