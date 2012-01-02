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
#include "lock.h"
#include "restorer.h"

/*
 * Threads restoration via sigreturn. Note it's locked
 * routine and calls for unlock at the end.
 */
long restore_thread(long cmd, struct thread_restore_args *args)
{
	long ret = -1;

	switch (cmd) {
	case RESTORE_CMD__RESTORE_THREAD:
	{
		struct core_entry *core_entry;
		struct rt_sigframe *rt_sigframe;
		unsigned long new_sp, fsgs_base;
		int my_pid = sys_gettid();

		if (my_pid != args->pid) {
			write_num_n(__LINE__);
			write_num_n(my_pid);
			write_num_n(args->pid);
			goto core_restore_end;
		}

		core_entry = (struct core_entry *)&args->mem_zone.heap;

		sys_lseek(args->fd_core, MAGIC_OFFSET, SEEK_SET);
		ret = sys_read(args->fd_core, core_entry, sizeof(*core_entry));
		if (ret != sizeof(*core_entry)) {
			write_num_n(__LINE__);
			goto core_restore_end;
		}

		/* We're to close it! */
		sys_close(args->fd_core);

		rt_sigframe = (void *)args->mem_zone.rt_sigframe + 8;

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
			write_num_n(__LINE__);
			write_num_n(ret);
			goto core_restore_end;
		}

		fsgs_base = core_entry->u.arch.gpregs.gs_base;
		ret = sys_arch_prctl(ARCH_SET_GS, (void *)fsgs_base);
		if (ret) {
			write_num_n(__LINE__);
			write_num_n(ret);
			goto core_restore_end;
		}

		cr_mutex_unlock(args->rst_lock);

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
		write_num_n(__LINE__);
		write_num_n(sys_getpid());
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

/*
 * The main routine to restore task via sigreturn.
 */
long restore_task(long cmd, struct task_restore_core_args *args)
{
	long ret = -1;

	switch (cmd) {

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
		struct core_entry *core_entry;
		struct vma_entry *vma_entry;
		u64 va;

		struct rt_sigframe *rt_sigframe;
		unsigned long new_sp, fsgs_base;

		core_entry	= first_on_heap(core_entry, args->mem_zone.heap);
		vma_entry	= next_on_heap(vma_entry, core_entry);

#if 0
		write_hex_n((long)args);
		write_hex_n((long)args->mem_zone.heap);
		write_hex_n((long)core_entry);
		write_hex_n((long)vma_entry);
#endif

		sys_lseek(args->fd_core, MAGIC_OFFSET, SEEK_SET);
		ret = sys_read(args->fd_core, core_entry, sizeof(*core_entry));
		if (ret != sizeof(*core_entry)) {
			write_num_n(__LINE__);
			goto core_restore_end;
		}

		/* Note no magic constant on fd_self_vmas */
		ret = sys_lseek(args->fd_self_vmas, 0, SEEK_SET);
		while (1) {
			ret = sys_read(args->fd_self_vmas, vma_entry, sizeof(*vma_entry));
			if (!ret)
				break;
			if (ret != sizeof(*vma_entry)) {
				write_num_n(__LINE__);
				write_num_n(ret);
				goto core_restore_end;
			}

			if (!vma_entry_is(vma_entry, VMA_AREA_REGULAR))
				continue;

			if (sys_munmap((void *)vma_entry->start, vma_entry_len(vma_entry))) {
				write_num_n(__LINE__);
				goto core_restore_end;
			}
		}

		sys_close(args->fd_self_vmas);
		sys_unlink(args->self_vmas_path);

		/*
		 * OK, lets try to map new one.
		 */
		sys_lseek(args->fd_core, GET_FILE_OFF_AFTER(struct core_entry), SEEK_SET);
		while (1) {
			int prot;

			ret = sys_read(args->fd_core, vma_entry, sizeof(*vma_entry));
			if (!ret)
				break;
			if (ret != sizeof(*vma_entry)) {
				write_num_n(__LINE__);
				write_num_n(ret);
				goto core_restore_end;
			}

			if (final_vma_entry(vma_entry))
				break;

			if (!vma_entry_is(vma_entry, VMA_AREA_REGULAR))
				continue;

			/*
			 * Restore or shared mappings are tricky, since
			 * we open anonymous mapping via map_files/
			 * MAP_ANONYMOUS should be eliminated so fd would
			 * be taken into account by a kernel.
			 */
			if (vma_entry_is(vma_entry, VMA_ANON_SHARED)) {
				if (vma_entry->fd != -1UL)
					vma_entry->flags &= ~MAP_ANONYMOUS;
			}

			prot = vma_entry->prot;

			/* A mapping of file with MAP_SHARED is up to date */
			if (vma_entry->fd == -1 || !(vma_entry->flags & MAP_SHARED))
				prot |= PROT_WRITE;

			/*
			 * Should map memory here. Note we map them as
			 * writable since we're going to restore page
			 * contents.
			 */
			va = sys_mmap((void *)vma_entry->start,
				      vma_entry_len(vma_entry),
				      prot,
				      vma_entry->flags | MAP_FIXED,
				      vma_entry->fd,
				      vma_entry->pgoff);

			if (va != vma_entry->start) {
				write_num_n(__LINE__);
				write_hex_n(vma_entry->start);
				write_hex_n(vma_entry->end);
				write_hex_n(vma_entry->prot);
				write_hex_n(vma_entry->flags);
				write_hex_n(vma_entry->fd);
				write_hex_n(vma_entry->pgoff);
				write_hex_n(va);
				goto core_restore_end;
			}

			if (vma_entry->fd != -1UL)
				sys_close(vma_entry->fd);

		}

		/*
		 * Read page contents.
		 */
		while (1) {
			ret = sys_read(args->fd_core, &va, sizeof(va));
			if (!ret)
				break;
			if (ret != sizeof(va)) {
				write_num_n(__LINE__);
				write_num_n(ret);
				goto core_restore_end;
			}
			if (final_page_va(va))
				break;

			ret = sys_read(args->fd_core, (void *)va, PAGE_SIZE);
			if (ret != PAGE_SIZE) {
				write_num_n(__LINE__);
				write_num_n(ret);
				goto core_restore_end;
			}
		}

		/*
		 * Walk though all VMAs again to drop PROT_WRITE
		 * if it was not there.
		 */
		sys_lseek(args->fd_core, GET_FILE_OFF_AFTER(struct core_entry), SEEK_SET);
		while (1) {
			ret = sys_read(args->fd_core, vma_entry, sizeof(*vma_entry));
			if (!ret)
				break;
			if (ret != sizeof(*vma_entry)) {
				write_num_n(__LINE__);
				write_num_n(ret);
				goto core_restore_end;
			}

			if (final_vma_entry(vma_entry))
				break;

			if (!(vma_entry_is(vma_entry, VMA_AREA_REGULAR)))
				continue;

			if (vma_entry_is(vma_entry, VMA_ANON_SHARED) &&
			    vma_entry->fd == -1UL) {
				struct shmem_info *entry;

				entry = find_shmem_by_pid(args->shmems,
							  vma_entry->start,
							  sys_getpid());
				if (!entry) {
					write_num_n(__LINE__);
					write_hex_n(vma_entry->start);
					goto core_restore_end;
				}

				cr_wait_set(&entry->lock, 1);
			}

			if (vma_entry->prot & PROT_WRITE)
				continue;

			sys_mprotect(vma_entry->start,
				     vma_entry_len(vma_entry),
				     vma_entry->prot);
		}

		sys_close(args->fd_core);

		ret = sys_munmap(args->shmems, SHMEMS_SIZE);
		if (ret < 0) {
			write_num_n(__LINE__);
			write_num_n(ret);
			goto core_restore_end;
		}

		/*
		 * Tune up the task fields.
		 */

#define sys_prctl_safe(opcode, val1, val2)			\
	do {							\
		ret = sys_prctl(opcode, val1, val2, 0, 0);	\
		if (ret) {					\
			write_num_n(__LINE__);			\
			write_num_n(ret);			\
		}						\
	} while (0)

		sys_prctl_safe(PR_SET_NAME, (long)core_entry->task_comm, 0);
		sys_prctl_safe(PR_SET_MM, PR_SET_MM_START_CODE,	(long)core_entry->mm_start_code);
		sys_prctl_safe(PR_SET_MM, PR_SET_MM_END_CODE,	(long)core_entry->mm_end_code);
		sys_prctl_safe(PR_SET_MM, PR_SET_MM_START_DATA,	(long)core_entry->mm_start_data);
		sys_prctl_safe(PR_SET_MM, PR_SET_MM_END_DATA,	(long)core_entry->mm_end_data);
		sys_prctl_safe(PR_SET_MM, PR_SET_MM_START_STACK,(long)core_entry->mm_start_stack);
		sys_prctl_safe(PR_SET_MM, PR_SET_MM_START_BRK,	(long)core_entry->mm_start_brk);
		sys_prctl_safe(PR_SET_MM, PR_SET_MM_BRK,	(long)core_entry->mm_brk);

		/*
		 * We need to prepare a valid sigframe here, so
		 * after sigreturn the kernel will pick up the
		 * registers from the frame, set them up and
		 * finally pass execution to the new IP.
		 */
		rt_sigframe = (void *)args->mem_zone.rt_sigframe + 8;

#define CPREG1(d)	rt_sigframe->uc.uc_mcontext.d = core_entry->u.arch.gpregs.d
#define CPREG2(d,s)	rt_sigframe->uc.uc_mcontext.d = core_entry->u.arch.gpregs.s

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

		fsgs_base = core_entry->u.arch.gpregs.fs_base;
		ret = sys_arch_prctl(ARCH_SET_FS, (void *)fsgs_base);
		if (ret) {
			write_num_n(__LINE__);
			write_num_n(ret);
			goto core_restore_end;
		}

		fsgs_base = core_entry->u.arch.gpregs.gs_base;
		ret = sys_arch_prctl(ARCH_SET_GS, (void *)fsgs_base);
		if (ret) {
			write_num_n(__LINE__);
			write_num_n(ret);
			goto core_restore_end;
		}

		/*
		 * Blocked signals.
		 */
		rt_sigframe->uc.uc_sigmask.sig[0] = core_entry->task_sigset;

		/*
		 * Threads restoration. This requires some more comments. This
		 * restorer routine and thread restorer routine has the following
		 * memory map, prepared by a caller code.
		 *
		 * | <-- low addresses                                          high addresses --> |
		 * +-------------------------------------------------------+-----------------------+
		 * | this proc body | own stack | heap | rt_sigframe space | thread restore zone   |
		 * +-------------------------------------------------------+-----------------------+
		 *
		 * where each thread restore zone is the following
		 *
		 * | <-- low addresses                                     high addresses --> |
		 * +--------------------------------------------------------------------------+
		 * | thread restore proc | thread1 stack | thread1 heap | thread1 rt_sigframe |
		 * +--------------------------------------------------------------------------+
		 */

		if (args->nr_threads) {
			struct thread_restore_args *thread_args = args->thread_args;
			long clone_flags = CLONE_VM | CLONE_FILES | CLONE_SIGHAND	|
					   CLONE_THREAD | CLONE_SYSVSEM;
			long last_pid_len;
			long parent_tid;
			int i, fd;

			fd = sys_open(args->ns_last_pid_path, O_RDWR, LAST_PID_PERM);
			if (fd < 0) {
				write_num_n(__LINE__);
				write_num_n(fd);
				goto core_restore_end;
			}

			ret = sys_flock(fd, LOCK_EX);
			if (ret) {
				write_num_n(__LINE__);
				write_num_n(ret);
				goto core_restore_end;
			}

			for (i = 0; i < args->nr_threads; i++) {

				/* skip self */
				if (thread_args[i].pid == args->pid)
					continue;

				cr_mutex_lock(&args->rst_lock);

				new_sp =
					RESTORE_ALIGN_STACK((long)thread_args[i].mem_zone.stack,
							    sizeof(thread_args[i].mem_zone.stack));

				last_pid_len = vprint_num(args->last_pid_buf, thread_args[i].pid - 1);
				ret = sys_write(fd, args->last_pid_buf, last_pid_len - 1);
				if (ret < 0) {
					write_num_n(__LINE__);
					write_num_n(ret);
					write_string_n(args->last_pid_buf);
					goto core_restore_end;
				}

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
			}

			ret = sys_flock(fd, LOCK_UN);
			if (ret) {
				write_num_n(__LINE__);
				write_num_n(ret);
				goto core_restore_end;
			}
		}

		/*
		 * Sigframe stack.
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
		write_num_n(__LINE__);
		write_num_n(sys_getpid());
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
