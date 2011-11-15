#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sched.h>

#include "compiler.h"
#include "types.h"
#include "syscall.h"
#include "util.h"
#include "image.h"

#include "crtools.h"
#include "restorer.h"

#define lea_args_off(to, label)						\
	do {								\
		asm volatile(						\
			"leaq " #label "(%%rip), %%rax		\n"	\
			"movq %%rax, %0				\n"	\
			: "=m"(to)					\
			:						\
			: "memory");					\
	} while (0)


long restore_thread(long cmd, struct thread_restore_args *args)
{
	long ret = -1;

	switch (cmd) {
	case RESTORE_CMD__RESTORE_THREAD:
	{
		struct core_entry *core_entry;

		struct user_fpregs_entry *fpregs;
		struct user_regs_entry *gpregs;
		struct rt_sigframe *rt_sigframe;

		unsigned long new_sp, fsgs_base;

		core_entry = &args->core_entry;

		sys_lseek(args->fd_core, MAGIC_OFFSET, SEEK_SET);
		ret = sys_read(args->fd_core, core_entry, sizeof(*core_entry));
		if (ret != sizeof(*core_entry)) {
			write_hex_n(__LINE__);
			goto core_restore_end;
		}

		sys_close(args->fd_core);

		rt_sigframe = (void *)args->rt_sigframe + 8;

#define CPREGT1(d)	rt_sigframe->uc.uc_mcontext.d = core_entry->u.arch.gpregs.d
#define CPREGT2(d,s)	rt_sigframe->uc.uc_mcontext.d = core_entry->u.arch.gpregs.s

		CPREGT1(r8);
		CPREGT1(r9);
		CPREGT1(r10);
		CPREGT1(r11);
		CPREGT1(r12);
		CPREGT1(r13);
		CPREGT1(r14);
		CPREGT1(r15);
		CPREGT2(rdi, di);
		CPREGT2(rsi, si);
		CPREGT2(rbp, bp);
		CPREGT2(rbx, bx);
		CPREGT2(rdx, dx);
		CPREGT2(rax, ax);
		CPREGT2(rcx, cx);
		CPREGT2(rsp, sp);
		CPREGT2(rip, ip);
		CPREGT2(eflags, flags);
		CPREGT1(cs);
		CPREGT1(gs);
		CPREGT1(fs);

		fsgs_base = core_entry->u.arch.gpregs.fs_base;
		ret = sys_arch_prctl(ARCH_SET_FS, (void *)fsgs_base);
		if (ret) {
			write_hex_n(__LINE__);
			write_hex_n(ret);
			goto core_restore_end;
		}

		fsgs_base = core_entry->u.arch.gpregs.gs_base;
		ret = sys_arch_prctl(ARCH_SET_GS, (void *)fsgs_base);
		if (ret) {
			write_hex_n(__LINE__);
			write_hex_n(ret);
			goto core_restore_end;
		}

		//r_unlock(args->lock);

		new_sp = (long)rt_sigframe + 8;
		asm volatile(
			"movq %0, %%rax					\n"
			"movq %%rax, %%rsp				\n"
			"movl $"__stringify(__NR_rt_sigreturn)", %%eax	\n"
			"syscall					\n"
			:
			: "r"(new_sp)
			: "rax","rsp","memory");
core_restore_end:
		write_hex_n(__LINE__);
		write_hex_n(sys_getpid());
		for (;;)
			local_sleep(5);
		sys_exit(0);
	}
		break;

	case RESTORE_CMD__GET_SELF_LEN:
		goto self_len_start;
self_len_end:
		break;

	default:
		goto core_restore_end;
		break;
	}

	return ret;

self_len_start:
	asm volatile(
		".align 64				\n"
		"self_thread:				\n"
		"leaq self_thread(%%rip), %%rax		\n"
		"addq $64, %%rax			\n"
		"andq $~63, %%rax			\n"
		"movq %%rax, %0				\n"
		: "=r"(ret)
		:
		: "memory");
	goto self_len_end;
}

long restore_task(long cmd)
{
	long ret = -1;

	asm volatile(
		"jmp 1f						\n"
		"restore_args__:				\n"
		".skip "__stringify(RESTORE_ARGS_SIZE)",0	\n"
		"1:						\n"
		:
		:
		: "memory");

#define restore_lea_args_off(to)	\
	lea_args_off(to, restore_args__)

	switch (cmd) {
	case RESTORE_CMD__PR_ARG_STRING:
	{
		char *str = NULL;

		restore_lea_args_off(str);
		write_string(str);

		ret = 0;
	}
		break;

	case RESTORE_CMD__GET_ARG_OFFSET:
		restore_lea_args_off(ret);
		break;

	case RESTORE_CMD__GET_SELF_LEN:
		goto self_len_start;
self_len_end:
		break;

	/*
	 * This one is very special, we never return there
	 * but use sigreturn facility to restore core registers
	 * and jump execution to some predefined ip read from
	 * core file.
	 */
	case RESTORE_CMD__RESTORE_CORE:
	{
		struct task_restore_core_args *args;
		int fd_core, fd_thread;
		int fd_self_vmas;

		struct core_entry core_entry;
		struct vma_entry vma_entry;
		u64 va;

		struct user_fpregs_entry *fpregs;
		struct user_regs_entry *gpregs;
		struct rt_sigframe *rt_sigframe;

		unsigned long new_sp, fsgs_base;

		restore_lea_args_off(args);

		write_string_n(args->core_path);
		write_string_n(args->self_vmas_path);

		fd_core = sys_open(args->core_path, O_RDONLY, CR_FD_PERM);
		if (fd_core < 0) {
			write_hex_n(__LINE__);
			goto core_restore_end;
		}

		sys_lseek(fd_core, MAGIC_OFFSET, SEEK_SET);
		ret = sys_read(fd_core, &core_entry, sizeof(core_entry));
		if (ret != sizeof(core_entry)) {
			write_hex_n(__LINE__);
			goto core_restore_end;
		}

		fd_self_vmas = sys_open(args->self_vmas_path, O_RDONLY, CR_FD_PERM);
		if (fd_self_vmas < 0) {
			write_hex_n(__LINE__);
			goto core_restore_end;
		}

		/* Note no magic constant on fd_self_vmas */
		sys_lseek(fd_self_vmas, 0, SEEK_SET);
		while (1) {
			ret = sys_read(fd_self_vmas, &vma_entry, sizeof(vma_entry));
			if (!ret)
				break;
			if (ret != sizeof(vma_entry)) {
				write_hex_n(__LINE__);
				write_hex_n(ret);
				goto core_restore_end;
			}

			if (!vma_entry_is(&vma_entry, VMA_AREA_REGULAR))
				continue;

			if (sys_munmap((void *)vma_entry.start, vma_entry_len(&vma_entry))) {
				write_hex_n(__LINE__);
				goto core_restore_end;
			}
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
			if (ret != sizeof(vma_entry)) {
				write_hex_n(__LINE__);
				write_hex_n(ret);
				goto core_restore_end;
			}

			if (final_vma_entry(&vma_entry))
				break;

			if (vma_entry_is(&vma_entry, VMA_AREA_VDSO)) {
				ret = sys_prctl(PR_CKPT_CTL, PR_CKPT_CTL_SETUP_VDSO_AT,
						vma_entry.start, 0, 0);
				if (ret) {
					write_hex_n(__LINE__);
					write_hex_n(ret);
					goto core_restore_end;
				}
				continue;
			}

			if (!vma_entry_is(&vma_entry, VMA_AREA_REGULAR))
				continue;

			/*
			 * Restore or shared mappings are tricky, since
			 * we open anonymous mapping via map_files/
			 * MAP_ANONYMOUS should be eliminated so fd would
			 * be taken into account by a kernel.
			 */
			if (vma_entry_is(&vma_entry, VMA_ANON_SHARED)) {
				if (vma_entry.fd != -1UL)
					vma_entry.flags &= ~MAP_ANONYMOUS;
			}

			/*
			 * Should map memory here. Note we map them as
			 * writable since we're going to restore page
			 * contents.
			 */
			va = sys_mmap((void *)vma_entry.start,
				      vma_entry_len(&vma_entry),
				      vma_entry.prot | PROT_WRITE,
				      vma_entry.flags | MAP_FIXED,
				      vma_entry.fd,
				      vma_entry.pgoff);

			if (va != vma_entry.start) {
				write_hex_n(__LINE__);
				write_hex_n(vma_entry.start);
				write_hex_n(vma_entry.end);
				write_hex_n(vma_entry.prot);
				write_hex_n(vma_entry.flags);
				write_hex_n(vma_entry.fd);
				write_hex_n(vma_entry.pgoff);
				write_hex_n(va);
				goto core_restore_end;
			}

			if (vma_entry.fd != -1UL)
				sys_close(vma_entry.fd);
		}

		/*
		 * Read page contents.
		 */
		while (1) {
			ret = sys_read(fd_core, &va, sizeof(va));
			if (!ret)
				break;
			if (ret != sizeof(va)) {
				write_hex_n(__LINE__);
				write_hex_n(ret);
				goto core_restore_end;
			}
			if (final_page_va(va))
				break;

			ret = sys_read(fd_core, (void *)va, PAGE_SIZE);
			if (ret != PAGE_SIZE) {
				write_hex_n(__LINE__);
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
			if (ret != sizeof(vma_entry)) {
				write_hex_n(__LINE__);
				write_hex_n(ret);
				goto core_restore_end;
			}

			if (final_vma_entry(&vma_entry))
				break;

			if (!(vma_entry_is(&vma_entry, VMA_AREA_REGULAR)))
				continue;

			if (vma_entry.prot & PROT_WRITE)
				continue;

			sys_mprotect(vma_entry.start,
				     vma_entry_len(&vma_entry),
				     vma_entry.prot);
		}

		sys_close(fd_core);

		/*
		 * Tune up the task fields.
		 */
		sys_prctl(PR_SET_NAME, (long)core_entry.task_comm, 0, 0, 0);
		sys_prctl(PR_CKPT_CTL, PR_CKPT_CTL_SET_MM_START_CODE,	(long)core_entry.mm_start_code, 0, 0);
		sys_prctl(PR_CKPT_CTL, PR_CKPT_CTL_SET_MM_END_CODE,	(long)core_entry.mm_end_code, 0, 0);
		sys_prctl(PR_CKPT_CTL, PR_CKPT_CTL_SET_MM_START_DATA,	(long)core_entry.mm_start_data, 0, 0);
		sys_prctl(PR_CKPT_CTL, PR_CKPT_CTL_SET_MM_END_DATA,	(long)core_entry.mm_end_data, 0, 0);
		sys_prctl(PR_CKPT_CTL, PR_CKPT_CTL_SET_MM_START_STACK,	(long)core_entry.mm_start_stack, 0, 0);
		sys_prctl(PR_CKPT_CTL, PR_CKPT_CTL_SET_MM_START_BRK,	(long)core_entry.mm_start_brk, 0, 0);
		sys_prctl(PR_CKPT_CTL, PR_CKPT_CTL_SET_MM_BRK,		(long)core_entry.mm_brk, 0, 0);

		/*
		 * We need to prepare a valid sigframe here, so
		 * after sigreturn the kernel will pick up the
		 * registers from the frame, set them up and
		 * finally pass execution to the new IP.
		 */
		rt_sigframe = args->rt_sigframe - sizeof(*rt_sigframe);

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

		fsgs_base = core_entry.u.arch.gpregs.fs_base;
		ret = sys_arch_prctl(ARCH_SET_FS, (void *)fsgs_base);
		if (ret) {
			write_hex_n(__LINE__);
			write_hex_n(ret);
			goto core_restore_end;
		}

		fsgs_base = core_entry.u.arch.gpregs.gs_base;
		ret = sys_arch_prctl(ARCH_SET_GS, (void *)fsgs_base);
		if (ret) {
			write_hex_n(__LINE__);
			write_hex_n(ret);
			goto core_restore_end;
		}

		/*
		 * Blocked signals.
		 */
		rt_sigframe->uc.uc_sigmask.sig[0] = core_entry.task_sigset;

		/*
		 * Threads restoration. This requires some more comments. This
		 * restorer routine and thread restorer routine has the following
		 * memory map, prepared by a caller code.
		 *
		 * | <-- low addresses                                   high addresses --> |
		 * +------------------------------------------------+-----------------------+
		 * | own stack | rt_sigframe space | this proc body | thread restore zone   |
		 * +------------------------------------------------+-----------------------+
		 *        %sp->|       call %rip ->|
		 *   params->|
		 *
		 * where each thread restore zone is the following
		 *
		 * | <-- low addresses                                     high addresses --> |
		 * +--------------------------------------------------------------------------+
		 * | thread restore proc | thread1 stack | thread1 heap | thread1 rt_sigframe |
		 * +--------------------------------------------------------------------------+
		 * |<- call %rip                   %sp ->|              |
		 *                             params->| |              |
		 *                                       |<-heap        |
		 *                                                      |<-frame
		 */

		if (args->nr_threads) {
			struct thread_restore_args *thread_args = args->thread_args;
			long clone_flags = CLONE_VM | CLONE_FILES | CLONE_SIGHAND	|
					   CLONE_THREAD | CLONE_SYSVSEM			|
					   CLONE_CHILD_USEPID;
			long parent_tid;
			int i;

			for (i = 0; i < args->nr_threads; i++) {

				/* skip self */
				if (thread_args[i].pid == args->pid)
					continue;

				new_sp = (long)thread_args[i].stack +
						sizeof(thread_args[i].stack) -
						ABI_RED_ZONE;

				/* Threads will unlock it */
				//r_lock(args->lock);

				/*
				 * To achieve functionality like libc's clone()
				 * we need a pure assembly here, because clone()'ed
				 * thread will run with own stack and we must not
				 * have any additional instructions... oh, dear...
				 */
				asm volatile(
					"clone_emul:				\n"
					"movq %2, %%rsi				\n"
					"subq $24, %%rsi			\n"
					"movq %7, %%rdi				\n"
					"movq %%rdi,16(%%rsi)			\n"
					"movq %6, %%rdi				\n"
					"movq %%rdi, 8(%%rsi)			\n"
					"movq %5, %%rdi				\n"
					"movq %%rdi, 0(%%rsi)			\n"
					"movq %1, %%rdi				\n"
					"movq %3, %%rdx				\n"
					"movq %4, %%r10				\n"
					"movl $"__stringify(__NR_clone)", %%eax	\n"
					"syscall				\n"

					"testq %%rax,%%rax			\n"
					"jz thread_run				\n"

					"movq %%rax, %0				\n"
					"jmp clone_end				\n"

					"thread_run:				\n"	/* new stack here */
					"xorq %%rbp, %%rbp			\n"	/* clear ABI frame pointer */
					"popq %%rax				\n"	/* clone_restore_fn  -- restore_thread */
					"popq %%rdi				\n"	/* arguments */
					"popq %%rsi				\n"
					"callq *%%rax				\n"

					"clone_end:				\n"
					: "=r"(ret)
					:	"g"(clone_flags),
						"g"(new_sp),
						"g"(&parent_tid),
						"g"(&thread_args[i].pid),
						"g"(args->clone_restore_fn),
						"g"(RESTORE_CMD__RESTORE_THREAD),
						"g"(&thread_args[i])
					: "rax", "rdi", "rsi", "rdx", "r10", "memory");

				//r_wait_unlock(args->lock);
			}
		}

		//r_lock(args->lock);

		/*
		 * sigframe is on stack.
		 */
		new_sp = (long)rt_sigframe + 8;

		/*
		 * Prepare the stack and call for sigreturn,
		 * pure assembly since we don't need any additional
		 * code insns from gcc.
		 */
		asm volatile(
			"movq %0, %%rax					\n"
			"movq %%rax, %%rsp				\n"
			"movl $"__stringify(__NR_rt_sigreturn)", %%eax	\n"
			"syscall					\n"
			:
			: "r"(new_sp)
			: "rax","rsp","memory");

core_restore_end:
		write_hex_n(__LINE__);
		write_hex_n(sys_getpid());
		for (;;)
			local_sleep(5);
		sys_exit(0);
	}
		break;

	default:
		goto core_restore_end;
		break;
	}

	return ret;

self_len_start:
	asm volatile(
		".align 64				\n"
		"self:					\n"
		"leaq self(%%rip), %%rax		\n"
		"addq $64, %%rax			\n"
		"andq $~63, %%rax			\n"
		"movq %%rax, %0				\n"
		: "=r"(ret)
		:
		: "memory");
	goto self_len_end;
}
