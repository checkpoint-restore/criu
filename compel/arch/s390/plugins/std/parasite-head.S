#include "common/asm/linkage.h"

	.section .head.text, "ax"

/*
 * Entry point for parasite_service()
 *
 * Addresses of symbols are exported in auto-generated criu/pie/parasite-blob.h
 *
 * Function is called via parasite_run(). The command for parasite_service()
 * is stored in global variable __export_parasite_cmd.
 *
 * Load parameters for parasite_service(unsigned int cmd, void *args):
 *
 *  - Parameter 1 (cmd) : %r2 = *(uint32 *)(__export_parasite_cmd + pc)
 *  - Parameter 2 (args): %r3 = __export_parasite_args + pc
 */
ENTRY(__export_parasite_head_start)
	larl	%r14,__export_parasite_cmd
	llgf	%r2,0(%r14)
	larl	%r3,__export_parasite_args
	brasl	%r14,parasite_service
	.long 0x00010001	/* S390_BREAKPOINT_U16: Generates SIGTRAP */
__export_parasite_cmd:
	.long 0
END(__export_parasite_head_start)
