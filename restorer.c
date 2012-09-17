#define CR_NOGLIBC
#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/shm.h>
#include <fcntl.h>
#include <unistd.h>
#include <sched.h>

#include "compiler.h"
#include "types.h"
#include "syscall.h"
#include "restorer-log.h"
#include "util.h"
#include "image.h"
#include "sk-inet.h"

#include "crtools.h"
#include "lock.h"
#include "restorer.h"

#include "protobuf/creds.pb-c.h"

#define sys_prctl_safe(opcode, val1, val2, val3)			\
	({								\
		long __ret = sys_prctl(opcode, val1, val2, val3, 0);	\
		if (__ret) {						\
			write_num_n_err(__LINE__);			\
			write_num_n_err(__ret);				\
		}							\
		__ret;							\
	})

static struct task_entries *task_entries;

static void sigchld_handler(int signal, siginfo_t *siginfo, void *data)
{
	write_num_info(siginfo->si_pid);
	if (siginfo->si_code & CLD_EXITED)
		write_str_info(" exited, status=");
	else if (siginfo->si_code & CLD_KILLED)
		write_str_info(" killed by signal ");
	write_num_n_info(siginfo->si_status);

	futex_abort_and_wake(&task_entries->nr_in_progress);
	/* sa_restorer may be unmaped, so we can't go back to userspace*/
	sys_kill(sys_getpid(), SIGSTOP);
	sys_exit_group(1);
}

static void restore_creds(CredsEntry *ce)
{
	int b, i;
	struct cap_header hdr;
	struct cap_data data[_LINUX_CAPABILITY_U32S_3];

	/*
	 * We're still root here and thus can do it without failures.
	 */

	if (ce == NULL)
		return;

	/*
	 * First -- set the SECURE_NO_SETUID_FIXUP bit not to
	 * lose caps bits when changing xids.
	 */

	sys_prctl(PR_SET_SECUREBITS, 1 << SECURE_NO_SETUID_FIXUP, 0, 0, 0);

	/*
	 * Second -- restore xids. Since we still have the CAP_SETUID
	 * capability nothing should fail. But call the setfsXid last
	 * to override the setresXid settings.
	 */

	sys_setresuid(ce->uid, ce->euid, ce->suid);
	sys_setfsuid(ce->fsuid);
	sys_setresgid(ce->gid, ce->egid, ce->sgid);
	sys_setfsgid(ce->fsgid);

	/*
	 * Third -- restore securebits. We don't need them in any
	 * special state any longer.
	 */

	sys_prctl(PR_SET_SECUREBITS, ce->secbits, 0, 0, 0);

	/*
	 * Fourth -- trim bset. This can only be done while
	 * having the CAP_SETPCAP capablity.
	 */

	for (b = 0; b < CR_CAP_SIZE; b++) {
		for (i = 0; i < 32; i++) {
			if (ce->cap_bnd[b] & (1 << i))
				/* already set */
				continue;

			sys_prctl(PR_CAPBSET_DROP, i + b * 32, 0, 0, 0);
		}
	}

	/*
	 * Fifth -- restore caps. Nothing but cap bits are changed
	 * at this stage, so just do it.
	 */

	hdr.version = _LINUX_CAPABILITY_VERSION_3;
	hdr.pid = 0;

	BUILD_BUG_ON(_LINUX_CAPABILITY_U32S_3 != CR_CAP_SIZE);

	for (i = 0; i < CR_CAP_SIZE; i++) {
		data[i].eff = ce->cap_eff[i];
		data[i].prm = ce->cap_prm[i];
		data[i].inh = ce->cap_inh[i];
	}

	sys_capset(&hdr, data);
}

/*
 * Threads restoration via sigreturn. Note it's locked
 * routine and calls for unlock at the end.
 */
long __export_restore_thread(struct thread_restore_args *args)
{
	long ret = -1;
	struct rt_sigframe *rt_sigframe;
	unsigned long new_sp, fsgs_base;
	int my_pid = sys_gettid();

	if (my_pid != args->pid) {
		write_num_n_err(__LINE__);
		write_num_n_err(my_pid);
		write_num_n_err(args->pid);
		goto core_restore_end;
	}

	sys_set_tid_address((int *)args->clear_tid_addr);

	if (args->has_futex) {
		if (sys_set_robust_list((void *)args->futex_rla, args->futex_rla_len)) {
			write_num_n_err(__LINE__);
			write_num_n_err(my_pid);
			write_num_n_err(args->pid);
			goto core_restore_end;
		}
	}

	rt_sigframe = (void *)args->mem_zone.rt_sigframe + 8;

#define CPREGT1(d)	rt_sigframe->uc.uc_mcontext.d = args->gpregs.d
#define CPREGT2(d, s)	rt_sigframe->uc.uc_mcontext.d = args->gpregs.s

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

	fsgs_base = args->gpregs.fs_base;
	ret = sys_arch_prctl(ARCH_SET_FS, fsgs_base);
	if (ret) {
		write_num_n_err(__LINE__);
		write_num_n_err(ret);
		goto core_restore_end;
	}

	fsgs_base = args->gpregs.gs_base;
	ret = sys_arch_prctl(ARCH_SET_GS, fsgs_base);
	if (ret) {
		write_num_n_err(__LINE__);
		write_num_n_err(ret);
		goto core_restore_end;
	}

	mutex_unlock(args->rst_lock);

	/*
	 * FIXME -- threads do not share creds, but it looks like
	 * nobody tries to mess with this crap. That said we should
	 * pass the master thread creds here
	 */

	restore_creds(NULL);
	futex_dec_and_wake(&task_entries->nr_in_progress);

	write_num_info(sys_gettid());
	write_str_n_info(": Restored");

	futex_wait_while(&task_entries->start, CR_STATE_RESTORE);
	futex_dec_and_wake(&task_entries->nr_in_progress);

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
	write_num_n_err(__LINE__);
	write_num_n_err(sys_getpid());
	sys_exit_group(1);
	return -1;
}

static long restore_self_exe_late(struct task_restore_core_args *args)
{
	int fd = args->fd_exe_link;

	write_str_info("Restoring EXE\n");
	sys_prctl_safe(PR_SET_MM, PR_SET_MM_EXE_FILE, fd, 0);
	sys_close(fd);

	/* FIXME Once kernel side stabilized -- fix error reporting */
	return 0;
}

static u64 restore_mapping(const VmaEntry *vma_entry)
{
	int prot	= vma_entry->prot;
	int flags	= vma_entry->flags | MAP_FIXED;
	u64 addr;

	if (vma_entry_is(vma_entry, VMA_AREA_SYSVIPC))
		return sys_shmat(vma_entry->fd, (void *)vma_entry->start,
				 (vma_entry->prot & PROT_WRITE) ? 0 : SHM_RDONLY);

	/*
	 * Restore or shared mappings are tricky, since
	 * we open anonymous mapping via map_files/
	 * MAP_ANONYMOUS should be eliminated so fd would
	 * be taken into account by a kernel.
	 */
	if (vma_entry_is(vma_entry, VMA_ANON_SHARED) && (vma_entry->fd != -1UL))
		flags &= ~MAP_ANONYMOUS;

	/* A mapping of file with MAP_SHARED is up to date */
	if (vma_entry->fd == -1 || !(vma_entry->flags & MAP_SHARED))
		prot |= PROT_WRITE;

	/*
	 * Should map memory here. Note we map them as
	 * writable since we're going to restore page
	 * contents.
	 */
	addr = sys_mmap((void *)vma_entry->start,
			vma_entry_len(vma_entry),
			prot, flags,
			vma_entry->fd,
			vma_entry->pgoff);

	if (vma_entry->fd != -1)
		sys_close(vma_entry->fd);

	return addr;
}

static void rst_tcp_socks_all(int *arr, int size)
{
	int i;

	if (size == 0)
		return;

	for (i =0; arr[i] >= 0; i++)
		tcp_repair_off(arr[i]);

	sys_munmap(arr, size);
}

/*
 * The main routine to restore task via sigreturn.
 * This one is very special, we never return there
 * but use sigreturn facility to restore core registers
 * and jump execution to some predefined ip read from
 * core file.
 */
long __export_restore_task(struct task_restore_core_args *args)
{
	long ret = -1;
	VmaEntry *vma_entry;
	u64 va;

	struct rt_sigframe *rt_sigframe;
	unsigned long new_sp, fsgs_base;
	pid_t my_pid = sys_getpid();
	rt_sigaction_t act;

	task_entries = args->task_entries;
	sys_sigaction(SIGCHLD, NULL, &act, sizeof(rt_sigset_t));
	act.rt_sa_handler = sigchld_handler;
	sys_sigaction(SIGCHLD, &act, NULL, sizeof(rt_sigset_t));

	restorer_set_logfd(args->logfd);
	restorer_set_loglevel(args->loglevel);

	for (vma_entry = args->self_vmas; vma_entry->start != 0; vma_entry++) {
		if (!vma_entry_is(vma_entry, VMA_AREA_REGULAR))
			continue;

		if (sys_munmap((void *)vma_entry->start, vma_entry_len(vma_entry))) {
			write_num_n_err(__LINE__);
			goto core_restore_end;
		}
	}

	sys_munmap(args->self_vmas,
			((void *)(vma_entry + 1) - ((void *)args->self_vmas)));

	/*
	 * OK, lets try to map new one.
	 */
	for (vma_entry = args->tgt_vmas; vma_entry->start != 0; vma_entry++) {
		if (!vma_entry_is(vma_entry, VMA_AREA_REGULAR))
			continue;

		va = restore_mapping(vma_entry);

		if (va != vma_entry->start) {
			write_num_n_err(__LINE__);
			write_hex_n_err(vma_entry->start);
			write_hex_n_err(vma_entry->end);
			write_hex_n_err(vma_entry->prot);
			write_hex_n_err(vma_entry->flags);
			write_hex_n_err(vma_entry->fd);
			write_hex_n_err(vma_entry->pgoff);
			write_hex_n_err(va);
			goto core_restore_end;
		}
	}

	/*
	 * Read page contents.
	 */
	while (1) {
		ret = sys_read(args->fd_pages, &va, sizeof(va));
		if (!ret)
			break;

		if (ret != sizeof(va)) {
			write_num_n_err(__LINE__);
			write_num_n_err(ret);
			goto core_restore_end;
		}

		ret = sys_read(args->fd_pages, (void *)va, PAGE_SIZE);
		if (ret != PAGE_SIZE) {
			write_num_n_err(__LINE__);
			write_num_n_err(ret);
			goto core_restore_end;
		}
	}

	sys_close(args->fd_pages);

	/*
	 * Walk though all VMAs again to drop PROT_WRITE
	 * if it was not there.
	 */
	for (vma_entry = args->tgt_vmas; vma_entry->start != 0; vma_entry++) {
		if (!(vma_entry_is(vma_entry, VMA_AREA_REGULAR)))
			continue;

		if (vma_entry_is(vma_entry, VMA_ANON_SHARED)) {
			struct shmem_info *entry;

			entry = find_shmem(args->shmems,
						  vma_entry->shmid);
			if (entry && entry->pid == my_pid &&
			    entry->start == vma_entry->start)
				futex_set_and_wake(&entry->lock, 1);
		}

		if (vma_entry->prot & PROT_WRITE)
			continue;

		sys_mprotect((void *)vma_entry->start,
			     vma_entry_len(vma_entry),
			     vma_entry->prot);
	}

	sys_munmap(args->tgt_vmas,
			((void *)(vma_entry + 1) - ((void *)args->tgt_vmas)));

	ret = sys_munmap(args->shmems, SHMEMS_SIZE);
	if (ret < 0) {
		write_num_n_err(__LINE__);
		write_num_n_err(ret);
		goto core_restore_end;
	}

	sys_set_tid_address((int *)args->clear_tid_addr);

	/*
	 * Tune up the task fields.
	 */
	ret |= sys_prctl_safe(PR_SET_NAME, (long)args->comm, 0, 0);

	ret |= sys_prctl_safe(PR_SET_MM, PR_SET_MM_START_CODE,	(long)args->mm.mm_start_code, 0);
	ret |= sys_prctl_safe(PR_SET_MM, PR_SET_MM_END_CODE,	(long)args->mm.mm_end_code, 0);
	ret |= sys_prctl_safe(PR_SET_MM, PR_SET_MM_START_DATA,	(long)args->mm.mm_start_data, 0);
	ret |= sys_prctl_safe(PR_SET_MM, PR_SET_MM_END_DATA,	(long)args->mm.mm_end_data, 0);
	ret |= sys_prctl_safe(PR_SET_MM, PR_SET_MM_START_STACK,	(long)args->mm.mm_start_stack, 0);
	ret |= sys_prctl_safe(PR_SET_MM, PR_SET_MM_START_BRK,	(long)args->mm.mm_start_brk, 0);
	ret |= sys_prctl_safe(PR_SET_MM, PR_SET_MM_BRK,		(long)args->mm.mm_brk, 0);
	ret |= sys_prctl_safe(PR_SET_MM, PR_SET_MM_ARG_START,	(long)args->mm.mm_arg_start, 0);
	ret |= sys_prctl_safe(PR_SET_MM, PR_SET_MM_ARG_END,	(long)args->mm.mm_arg_end, 0);
	ret |= sys_prctl_safe(PR_SET_MM, PR_SET_MM_ENV_START,	(long)args->mm.mm_env_start, 0);
	ret |= sys_prctl_safe(PR_SET_MM, PR_SET_MM_ENV_END,	(long)args->mm.mm_env_end, 0);
	ret |= sys_prctl_safe(PR_SET_MM, PR_SET_MM_AUXV,	(long)args->mm_saved_auxv,
								sizeof(args->mm_saved_auxv));
	if (ret)
		goto core_restore_end;

	/*
	 * Because of requirements applied from kernel side
	 * we need to restore /proc/pid/exe symlink late,
	 * after old existing VMAs are superseded with
	 * new ones from image file.
	 */
	ret = restore_self_exe_late(args);
	if (ret)
		goto core_restore_end;

	if (args->has_futex) {
		if (sys_set_robust_list((void *)args->futex_rla, args->futex_rla_len)) {
			write_num_n_err(__LINE__);
			write_num_n_err(my_pid);
			write_num_n_err(args->pid);
			goto core_restore_end;
		}
	}

	/*
	 * We need to prepare a valid sigframe here, so
	 * after sigreturn the kernel will pick up the
	 * registers from the frame, set them up and
	 * finally pass execution to the new IP.
	 */
	rt_sigframe = (void *)args->mem_zone.rt_sigframe + 8;

#define CPREG1(d)	rt_sigframe->uc.uc_mcontext.d = args->gpregs.d
#define CPREG2(d, s)	rt_sigframe->uc.uc_mcontext.d = args->gpregs.s

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

	fsgs_base = args->gpregs.fs_base;
	ret = sys_arch_prctl(ARCH_SET_FS, fsgs_base);
	if (ret) {
		write_num_n_err(__LINE__);
		write_num_n_err(ret);
		goto core_restore_end;
	}

	fsgs_base = args->gpregs.gs_base;
	ret = sys_arch_prctl(ARCH_SET_GS, fsgs_base);
	if (ret) {
		write_num_n_err(__LINE__);
		write_num_n_err(ret);
		goto core_restore_end;
	}

	/*
	 * Blocked signals.
	 */
	rt_sigframe->uc.uc_sigmask.sig[0] = args->blk_sigset;

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

	if (args->nr_threads > 1) {
		struct thread_restore_args *thread_args = args->thread_args;
		long clone_flags = CLONE_VM | CLONE_FILES | CLONE_SIGHAND	|
				   CLONE_THREAD | CLONE_SYSVSEM;
		long last_pid_len;
		long parent_tid;
		int i, fd;

		fd = sys_open(LAST_PID_PATH, O_RDWR, LAST_PID_PERM);
		if (fd < 0) {
			write_num_n_err(__LINE__);
			write_num_n_err(fd);
			goto core_restore_end;
		}

		ret = sys_flock(fd, LOCK_EX);
		if (ret) {
			write_num_n_err(__LINE__);
			write_num_n_err(ret);
			goto core_restore_end;
		}

		for (i = 0; i < args->nr_threads; i++) {
			char last_pid_buf[16];

			/* skip self */
			if (thread_args[i].pid == args->pid)
				continue;

			mutex_lock(&args->rst_lock);

			new_sp =
				RESTORE_ALIGN_STACK((long)thread_args[i].mem_zone.stack,
						    sizeof(thread_args[i].mem_zone.stack));

			last_pid_len = vprint_num(last_pid_buf, thread_args[i].pid - 1);
			ret = sys_write(fd, last_pid_buf, last_pid_len - 1);
			if (ret < 0) {
				write_num_n_err(__LINE__);
				write_num_n_err(ret);
				write_str_n_err(last_pid_buf);
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
				"subq $16, %%rsi			\n"
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
				"callq *%%rax				\n"

				"clone_end:				\n"
				: "=r"(ret)
				:	"g"(clone_flags),
					"g"(new_sp),
					"g"(&parent_tid),
					"g"(&thread_args[i].pid),
					"g"(args->clone_restore_fn),
					"g"(&thread_args[i])
				: "rax", "rdi", "rsi", "rdx", "r10", "memory");
		}

		ret = sys_flock(fd, LOCK_UN);
		if (ret) {
			write_num_n_err(__LINE__);
			write_num_n_err(ret);
			goto core_restore_end;
		}

		sys_close(fd);
	}

	/*
	 * Restore creds late to avoid potential problems with
	 * insufficient caps for restoring this or that before
	 */

	restore_creds(&args->creds);

	futex_dec_and_wake(&args->task_entries->nr_in_progress);

	write_num_info(sys_getpid());
	write_str_n_info(": Restored");

	futex_wait_while(&args->task_entries->start, CR_STATE_RESTORE);

	sys_sigaction(SIGCHLD, &args->sigchld_act, NULL, sizeof(rt_sigset_t));

	futex_dec_and_wake(&args->task_entries->nr_in_progress);

	futex_wait_while(&args->task_entries->start, CR_STATE_RESTORE_SIGCHLD);

	rst_tcp_socks_all(args->rst_tcp_socks, args->rst_tcp_socks_size);

	sys_close(args->logfd);

	/*
	 * The code that prepared the itimers makes shure the
	 * code below doesn't fail due to bad timing values.
	 */

#define itimer_armed(args, i)				\
		(args->itimers[i].it_interval.tv_sec ||	\
		 args->itimers[i].it_interval.tv_usec)

	if (itimer_armed(args, 0))
		sys_setitimer(ITIMER_REAL, &args->itimers[0], NULL);
	if (itimer_armed(args, 1))
		sys_setitimer(ITIMER_VIRTUAL, &args->itimers[1], NULL);
	if (itimer_armed(args, 2))
		sys_setitimer(ITIMER_PROF, &args->itimers[2], NULL);

	ret = sys_munmap(args->task_entries, TASK_ENTRIES_SIZE);
	if (ret < 0) {
		ret = ((long)__LINE__ << 32) | -ret;
		goto core_restore_failed;
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
	write_num_n_err(__LINE__);
	write_num_n_err(sys_getpid());
	sys_exit_group(1);
	return -1;

core_restore_failed:
	asm volatile(
		"movq %0, %%rsp				\n"
		"movq 0, %%rax				\n"
		"jmp *%%rax				\n"
		:
		: "r"(ret)
		: );
	return ret;
}
