#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "compiler.h"
#include "types.h"
#include "syscall.h"
#include "util.h"
#include "image.h"

#include "crtools.h"
#include "restorer.h"

#define get_rt_sigframe_addr(stack)					\
	(struct rt_sigframe *)(stack - sizeof(long))

#define lea_args_off(p)							\
	do {								\
		asm volatile(						\
			"leaq restore_args__(%%rip), %%rax	\n\t"	\
			"movq %%rax, %0				\n\t"	\
			: "=m"(p)					\
			:						\
			: "memory");					\
	} while (0)

#define add_ord(c)			\
	do {				\
		if (c < 10)		\
			c += '0';	\
		else			\
			c += 'a' - 10;	\
	} while (0)

#define inline_memcpy(d,s,l)	__builtin_memcpy(d,s,l)
#define inline_memset(d,c,l)	__builtin_memset(d,c,l)
#define inline_memzero(d,l)	__builtin_memset(d,0,l)
#define inline_memzero_p(d)	__builtin_memset(d,0,sizeof(*(d)))

#define sigframe_addr(p)	((long)p)

static void always_inline write_char(char c)
{
	sys_write(1, &c, 1);
}

static void always_inline write_string(char *str)
{
	int len = 0;

	while (str[len])
		len++;

	sys_write(1, str, len);
}

static void always_inline write_string_n(char *str)
{
	char new_line = '\n';

	write_string(str);
	sys_write(1, &new_line, 1);
}

static void always_inline write_hex_n(unsigned long num)
{
	unsigned char *s = (unsigned char *)&num;
	unsigned char c;
	int i;

	for (i = sizeof(long)/sizeof(char) - 1; i >= 0; i--) {
		c = (s[i] & 0xf0) >> 4;
		add_ord(c);
		sys_write(1, &c, 1);

		c = (s[i] & 0x0f);
		add_ord(c);
		sys_write(1, &c, 1);
	}

	c = '\n';
	sys_write(1, &c, 1);
}

static void always_inline local_sleep(long seconds)
{
	struct timespec req, rem;

	req = (struct timespec){
		.tv_sec		= seconds,
		.tv_nsec	= 0,
	};

	sys_nanosleep(&req, &rem);
}

long restorer(long cmd)
{
	long ret = -1;

	asm volatile(
		"jmp 1f						\n\t"
		"restore_args__:				\n\t"
		".skip "__stringify(RESTORER_ARGS_SIZE)",0	\n\t"
		"1:						\n\t"
		:
		:
		: "memory");

	switch (cmd) {
	case RESTORER_CMD__PR_ARG_STRING:
	{
		char *str = NULL;

		lea_args_off(str);
		write_string(str);

		ret = 0;
	}
		break;

	case RESTORER_CMD__GET_ARG_OFFSET:
		lea_args_off(ret);
		break;

	case RESTORER_CMD__GET_SELF_LEN:
		goto self_len_start;
self_len_end:
		break;

	/*
	 * This one is very special, we never return there
	 * but use sigreturn facility to restore core registers
	 * and jump execution to some predefined ip read from
	 * core file.
	 */
	case RESTORER_CMD__RESTORE_CORE:
	{
		struct restore_core_args *args;
		int fd_self_vmas;
		int fd_core;

		struct core_entry core_entry;
		struct vma_entry vma_entry;
		u64 va;

		struct user_fpregs_entry *fpregs;
		struct user_regs_entry *gpregs;
		struct rt_sigframe *rt_sigframe;

		unsigned long new_sp, *stack;

		lea_args_off(args);

		write_string_n(args->core_path);
		write_string_n(args->self_vmas_path);

		fd_core = sys_open(args->core_path, O_RDONLY, CR_FD_PERM);
		if (fd_core < 0)
			goto core_restore_end;

		sys_lseek(fd_core, MAGIC_OFFSET, SEEK_SET);
		ret = sys_read(fd_core, &core_entry, sizeof(core_entry));
		if (ret != sizeof(core_entry))
			goto core_restore_end;

		fd_self_vmas = sys_open(args->self_vmas_path, O_RDONLY, CR_FD_PERM);
		if (fd_self_vmas < 0)
			goto core_restore_end;

		/* Note no magic constant on fd_self_vmas */
		sys_lseek(fd_self_vmas, 0, SEEK_SET);
		while (1) {
			ret = sys_read(fd_self_vmas, &vma_entry, sizeof(vma_entry));
			if (!ret)
				break;
			if (ret != sizeof(vma_entry))
				goto core_restore_end;

			if (!(vma_entry.status & VMA_AREA_REGULAR))
				continue;

			if (sys_munmap((void *)vma_entry.start,
				       vma_entry.end - vma_entry.start))
				goto core_restore_end;
		}

		sys_close(fd_self_vmas);
		sys_unlink(args->self_vmas_path);

		/*
		 * OK, lets try to map new one.
		 */
		sys_lseek(fd_core, GET_FILE_OFF_AFTER(struct core_entry), SEEK_SET);
		while (1) {
			ret = sys_read(fd_core, &vma_entry, sizeof(vma_entry));
			if (!ret)
				break;
			if (ret != sizeof(vma_entry))
				goto core_restore_end;

			if (!vma_entry.start)
				break;

			if (!(vma_entry.status & VMA_AREA_REGULAR))
				continue;

			vma_entry.fd	= -1UL; /* for a while */
			vma_entry.pgoff	= 0;

			/*
			 * Should map memory here. Note we map them as
			 * writable since we're going to restore page
			 * contents.
			 */
			va = sys_mmap((void *)vma_entry.start,
				      vma_entry.end - vma_entry.start,
				      vma_entry.prot | PROT_WRITE,
				      (vma_entry.flags		|
						MAP_ANONYMOUS	|
						MAP_FIXED	|
						MAP_PRIVATE) & ~MAP_SHARED,
				      vma_entry.fd,
				      vma_entry.pgoff);

                        if (va != vma_entry.start) {
                                write_hex_n(vma_entry.start);
                                write_hex_n(va);
                                goto core_restore_end;
                        }
		}

		/*
		 * Read page contents.
		 */
		while (1) {
			ret = sys_read(fd_core, &va, sizeof(va));
			if (!ret)
				break;
			if (ret != sizeof(va))
				goto core_restore_end;
			if (!va)
				break;

			ret = sys_read(fd_core, (void *)va, PAGE_SIZE);
			if (ret != PAGE_SIZE) {
				write_hex_n(ret);
				goto core_restore_end;
			}
		}

		/*
		 * Walk though all VMAs again to drop PROT_WRITE
		 * if it was not there.
		 */
		sys_lseek(fd_core, GET_FILE_OFF_AFTER(struct core_entry), SEEK_SET);
		while (1) {
			ret = sys_read(fd_core, &vma_entry, sizeof(vma_entry));
			if (!ret)
				break;
			if (ret != sizeof(vma_entry))
				goto core_restore_end;

			if (!vma_entry.start)
				break;

			if (!(vma_entry.status & VMA_AREA_REGULAR))
				continue;

			if (vma_entry.prot & PROT_WRITE)
				continue;

			sys_mprotect(vma_entry.start,
				     vma_entry.end - vma_entry.start,
				     vma_entry.prot);
		}

		sys_close(fd_core);

		/*
		 * We need to prepare a valid sigframe here, so
		 * after sigreturn the kernel will pick up the
		 * registers from the frame, set them up and
		 * finally pass execution to the new IP.
		 */

		/*
		 * The sigframe should be on the stack, also
		 * note the kernel uses this stack not only
		 * for restoring registers and such but it
		 * save pt_regs there after sigframe, so make
		 * sure the stack is big enough to keep all
		 * this, otherwise the application get killed
		 * by the kernel with stack overflow error.
		 */

		rt_sigframe = args->rt_sigframe;
		write_hex_n((long)rt_sigframe);
		write_hex_n((long)&rt_sigframe->uc);

#define CPREG1(d)	rt_sigframe->uc.uc_mcontext.d = core_entry.u.arch.gpregs.d
#define CPREG2(d,s)	rt_sigframe->uc.uc_mcontext.d = core_entry.u.arch.gpregs.s

		CPREG1(r8);
		CPREG1(r9);
		CPREG1(r10);
		CPREG1(r11);
		CPREG1(r12);
		CPREG1(r13);
		CPREG1(r14);
		CPREG1(r15);
		CPREG2(rdi, di);
		CPREG2(rsi, si);
		CPREG2(rbp, bp);
		CPREG2(rbx, bx);
		CPREG2(rdx, dx);
		CPREG2(rax, ax);
		CPREG2(rcx, cx);
		CPREG2(rsp, sp);
		CPREG2(rip, ip);
		CPREG2(eflags, flags);
		CPREG1(cs);
		CPREG1(gs);
		CPREG1(fs);

		/* FIXME: What with cr2 and friends which are rest there? */

		new_sp = core_entry.u.arch.gpregs.sp - 8;
		write_hex_n(new_sp);
		stack = (void *)new_sp;
		*stack = (long)rt_sigframe;

		/*
		 * Prepare the stack and call for sigreturn,
		 * pure assembly since we don't need any additional
		 * code insns from gcc.
		 */
		asm volatile(
			"movq %0, %%rax					\t\n"
			"movq %%rax, %%rsp				\t\n"
			"movl $"__stringify(__NR_rt_sigreturn)", %%eax	\t\n"
			"syscall					\t\n"
			:
			: "r"(new_sp)
			: "rax","rsp","memory");

core_restore_end:
		write_hex_n(sys_getpid());
		for (;;)
			local_sleep(5);
		sys_exit(0);
	}
		break;

	default:
		ret = -1;
		break;
	}

	return ret;

self_len_start:
	asm volatile(
		".align 64				\t\n"
		"self:					\t\n"
		"leaq self(%%rip), %%rax		\t\n"
		"addq $64, %%rax			\t\n"
		"andq $~63, %%rax			\t\n"
		"movq %%rax, %0				\t\n"
		: "=r"(ret)
		:
		: "memory");
	goto self_len_end;
}
