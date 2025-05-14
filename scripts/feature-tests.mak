define FEATURE_TEST_TCP_REPAIR

#include <netinet/tcp.h>

int main(void)
{
	struct tcp_repair_opt opts;
	opts.opt_code = TCP_NO_QUEUE;
	opts.opt_val = 0;

	return opts.opt_val;
}
endef

define FEATURE_TEST_TCP_REPAIR_WINDOW

#include <netinet/tcp.h>

int main(void)
{
	struct tcp_repair_window opts;

	opts.snd_wl1 = 0;

	return opts.snd_wl1;
}
endef

define FEATURE_TEST_LIBBSD_DEV
#include <bsd/string.h>

int main(void)
{
	return 0;
}
endef

define FEATURE_TEST_PTRACE_PEEKSIGINFO

#include <sys/ptrace.h>

int main(void)
{
	struct ptrace_peeksiginfo_args args = {};

	return 0;
}

endef

define FEATURE_TEST_SETPROCTITLE_INIT

#include <bsd/unistd.h>

int main(int argc, char *argv[], char *envp[])
{
	setproctitle_init(argc, argv, envp);

	return 0;
}

endef

define FEATURE_TEST_X86_COMPAT
#define __ALIGN         .align 4, 0x90
#define ENTRY(name)             \
        .globl name;            \
        .type name, @function;  \
        __ALIGN;                \
        name:

#define END(sym)                \
        .size sym, . - sym

#define __USER32_CS     0x23
#define __USER_CS       0x33

        .text

ENTRY(call32_from_64)
        /* Push return address and 64-bit segment descriptor */
        sub \$$4, %rsp
        movl \$$__USER_CS,(%rsp)
        sub \$$4, %rsp
        /* Using rip-relative addressing to get rid of R_X86_64_32S relocs */
        leaq 2f(%rip),%r12
        movl %r12d,(%rsp)

        /* Switch into compatibility mode */
        pushq \$$__USER32_CS
        /* Using rip-relative addressing to get rid of R_X86_64_32S relocs */
        leaq 1f(%rip), %r12
        pushq %r12
        lretq

1:	.code32
        /* Run function and switch back */
        call *%esi
        lret

2:	.code64
        /* Restore the stack */
        mov (%rsp),%rsp
        add \$$8, %rdi
END(call32_from_64)

ENTRY(main)
        nop
END(main)
endef

define FEATURE_TEST_NFTABLES_LIB_API_0

#include <string.h>

#include <nftables/libnftables.h>

int main(int argc, char **argv)
{
	return nft_run_cmd_from_buffer(nft_ctx_new(NFT_CTX_DEFAULT), \"cmd\", strlen(\"cmd\"));
}

endef

define FEATURE_TEST_NFTABLES_LIB_API_1

#include <nftables/libnftables.h>

int main(int argc, char **argv)
{
	return nft_run_cmd_from_buffer(nft_ctx_new(NFT_CTX_DEFAULT), \"cmd\");
}

endef

define FEATURE_TEST_MEMFD_CREATE

#include <sys/mman.h>
#include <stddef.h>

int main(void)
{
	return memfd_create(NULL, 0);
}
endef

define FEATURE_TEST_OPENAT2

#include <linux/openat2.h>

int main(void)
{
	if (RESOLVE_NO_XDEV > 0)
		return 0;
	return 0;
}
endef

define FEATURE_TEST_NO_LIBC_RSEQ_DEFS

#ifdef __has_include
#if __has_include(\"sys/rseq.h\")
#include <sys/rseq.h>
#endif
#endif

enum rseq_cpu_id_state {
	RSEQ_CPU_ID_UNINITIALIZED = -1,
	RSEQ_CPU_ID_REGISTRATION_FAILED = -2,
};

int main(void)
{
	return 0;
}
endef
