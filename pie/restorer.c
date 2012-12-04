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
#include <sys/resource.h>

#include "compiler.h"
#include "types.h"
#include "syscall.h"
#include "log.h"
#include "util.h"
#include "image.h"
#include "sk-inet.h"

#include "crtools.h"
#include "lock.h"
#include "restorer.h"

#include "creds.pb-c.h"

#define sys_prctl_safe(opcode, val1, val2, val3)			\
	({								\
		long __ret = sys_prctl(opcode, val1, val2, val3, 0);	\
		if (__ret) 						\
			 pr_err("prctl failed @%d with %ld\n", __LINE__, __ret);\
		__ret;							\
	})

static struct task_entries *task_entries;
static futex_t thread_inprogress;

static void sigchld_handler(int signal, siginfo_t *siginfo, void *data)
{
	char *r;

	if (siginfo->si_code & CLD_EXITED)
		r = " exited, status=";
	else if (siginfo->si_code & CLD_KILLED)
		r = " killed by signal ";
	else
		r = "disappeared with ";

	pr_info("Task %d %s %d\n", siginfo->si_pid, r, siginfo->si_status);

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

static void restore_sched_info(struct rst_sched_param *p)
{
	struct sched_param parm;

	if ((p->policy == SCHED_OTHER) && (p->nice == 0))
		return;

	pr_info("Restoring scheduler params %d.%d.%d\n",
			p->policy, p->nice, p->prio);

	sys_setpriority(PRIO_PROCESS, 0, p->nice);
	parm.sched_priority = p->prio;
	sys_sched_setscheduler(0, p->policy, &parm);
}

static int restore_gpregs(struct rt_sigframe *f, UserX86RegsEntry *r)
{
	long ret;
	unsigned long fsgs_base;

#define CPREG1(d)	f->uc.uc_mcontext.d = r->d
#define CPREG2(d, s)	f->uc.uc_mcontext.d = r->s

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

	fsgs_base = r->fs_base;
	ret = sys_arch_prctl(ARCH_SET_FS, fsgs_base);
	if (ret) {
		pr_info("SET_FS fail %ld\n", ret);
		return -1;
	}

	fsgs_base = r->gs_base;
	ret = sys_arch_prctl(ARCH_SET_GS, fsgs_base);
	if (ret) {
		pr_info("SET_GS fail %ld\n", ret);
		return -1;
	}

	return 0;
}

static int restore_thread_common(struct rt_sigframe *sigframe,
		struct thread_restore_args *args)
{
	sys_set_tid_address((int *)args->clear_tid_addr);

	if (args->has_futex) {
		if (sys_set_robust_list((void *)args->futex_rla, args->futex_rla_len)) {
			pr_err("Robust list err\n");
			return -1;
		}
	}

	if (args->has_blk_sigset)
		sigframe->uc.uc_sigmask.sig[0] = args->blk_sigset;

	restore_sched_info(&args->sp);

	return restore_gpregs(sigframe, &args->gpregs);
}

/*
 * Threads restoration via sigreturn. Note it's locked
 * routine and calls for unlock at the end.
 */
long __export_restore_thread(struct thread_restore_args *args)
{
	struct rt_sigframe *rt_sigframe;
	unsigned long new_sp;
	int my_pid = sys_gettid();

	if (my_pid != args->pid) {
		pr_err("Thread pid mismatch %d/%d\n", my_pid, args->pid);
		goto core_restore_end;
	}

	rt_sigframe = (void *)args->mem_zone.rt_sigframe + 8;

	if (restore_thread_common(rt_sigframe, args))
		goto core_restore_end;

	mutex_unlock(&args->ta->rst_lock);

	restore_creds(&args->ta->creds);


	pr_info("%ld: Restored\n", sys_gettid());

	restore_finish_stage(CR_STATE_RESTORE);
	restore_finish_stage(CR_STATE_RESTORE_SIGCHLD);

	futex_dec_and_wake(&thread_inprogress);

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
	pr_err("Restorer abnormal termination for %ld\n", sys_getpid());
	sys_exit_group(1);
	return -1;
}

static long restore_self_exe_late(struct task_restore_core_args *args)
{
	int fd = args->fd_exe_link;

	pr_info("Restoring EXE link\n");
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

	pr_debug("\tmmap(%lx -> %lx, %x %x %d\n",
			vma_entry->start, vma_entry->end,
			prot, flags, (int)vma_entry->fd);
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

static int vma_remap(unsigned long src, unsigned long dst, unsigned long len)
{
	unsigned long guard = 0, tmp;

	pr_info("Remap %lx->%lx len %lx\n", src, dst, len);

	if (src - dst < len)
		guard = dst;
	else if (dst - src < len)
		guard = dst + len - PAGE_SIZE;

	if (src == dst)
		return 0;

	if (guard != 0) {
		/*
		 * mremap() returns an error if a target and source vma-s are
		 * overlapped. In this case the source vma are remapped in
		 * a temporary place and then remapped to the target address.
		 * Here is one hack to find non-ovelapped temporary place.
		 *
		 * 1. initial placement. We need to move src -> tgt.
		 * |       |+++++src+++++|
		 * |-----tgt-----|       |
		 *
		 * 2. map a guard page at the non-ovelapped border of a target vma.
		 * |       |+++++src+++++|
		 * |G|----tgt----|       |
		 *
		 * 3. remap src to any other place.
		 *    G prevents src from being remaped on tgt again
		 * |       |-------------| -> |+++++src+++++|
		 * |G|---tgt-----|                          |
		 *
		 * 4. remap src to tgt, no overlapping any longer
		 * |+++++src+++++|   <----    |-------------|
		 * |G|---tgt-----|                          |
		 */

		unsigned long addr;

		/* Map guard page (step 2) */
		tmp = sys_mmap((void *) guard, PAGE_SIZE, PROT_NONE,
					MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
		if (tmp != guard) {
			pr_err("Unable to map a guard page %lx (%lx)\n", guard, tmp);
			return -1;
		}

		/* Move src to non-overlapping place (step 3) */
		addr = sys_mmap(NULL, len, PROT_NONE,
					MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
		if (addr == (unsigned long) MAP_FAILED) {
			pr_err("Unable to reserve memory (%lx)\n", addr);
			return -1;
		}

		tmp = sys_mremap(src, len, len,
					MREMAP_MAYMOVE | MREMAP_FIXED, addr);
		if (tmp != addr) {
			pr_err("Unable to remap %lx -> %lx (%lx)\n", src, addr, tmp);
			return -1;
		}

		src = addr;
	}

	tmp = sys_mremap(src, len, len, MREMAP_MAYMOVE | MREMAP_FIXED, dst);
	if (tmp != dst) {
		pr_err("Unable to remap %lx -> %lx\n", src, dst);
		return -1;
	}

	return 0;
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
	unsigned long premmapped_end = args->premmapped_addr + args->premmapped_len;

	struct rt_sigframe *rt_sigframe;
	unsigned long new_sp;
	pid_t my_pid = sys_getpid();
	rt_sigaction_t act;

	task_entries = args->task_entries;
	sys_sigaction(SIGCHLD, NULL, &act, sizeof(rt_sigset_t));
	act.rt_sa_handler = sigchld_handler;
	sys_sigaction(SIGCHLD, &act, NULL, sizeof(rt_sigset_t));

	log_set_fd(args->logfd);
	log_set_loglevel(args->loglevel);

	pr_info("Switched to the restorer %d\n", my_pid);

	for (vma_entry = args->self_vmas; vma_entry->start != 0; vma_entry++) {
		unsigned long addr = vma_entry->start;
		unsigned long len;

		if (!vma_entry_is(vma_entry, VMA_AREA_REGULAR))
			continue;

		pr_debug("Examine %lx-%lx\n", vma_entry->start, vma_entry->end);

		if (addr < args->premmapped_addr) {
			if (vma_entry->end >= args->premmapped_addr)
				len = args->premmapped_addr - addr;
			else
				len = vma_entry->end - vma_entry->start;
			if (sys_munmap((void *) addr, len)) {
				pr_err("munmap fail for %lx - %lx\n", addr, addr + len);
				goto core_restore_end;
			}
		}

		if (vma_entry->end > premmapped_end) {
			if (vma_entry->start < premmapped_end)
				addr = premmapped_end;
			len = vma_entry->end - addr;
			if (sys_munmap((void *) addr, len)) {
				pr_err("munmap fail for %lx - %lx\n", addr, addr + len);
				goto core_restore_end;
			}
		}
	}

	sys_munmap(args->self_vmas,
			((void *)(vma_entry + 1) - ((void *)args->self_vmas)));

	/* Shift private vma-s to the left */
	for (vma_entry = args->tgt_vmas; vma_entry->start != 0; vma_entry++) {
		if (!vma_entry_is(vma_entry, VMA_AREA_REGULAR))
			continue;

		if (!vma_priv(vma_entry))
			continue;

		if (vma_entry->start > vma_entry->shmid)
			break;

		if (vma_remap(vma_premmaped_start(vma_entry),
				vma_entry->start, vma_entry_len(vma_entry)))
			goto core_restore_end;
	}

	/* Shift private vma-s to the right */
	for (vma_entry = args->tgt_vmas + args->nr_vmas -1;
				vma_entry >= args->tgt_vmas; vma_entry--) {
		if (!vma_entry_is(vma_entry, VMA_AREA_REGULAR))
			continue;

		if (!vma_priv(vma_entry))
			continue;

		if (vma_entry->start < vma_entry->shmid)
			break;

		if (vma_remap(vma_premmaped_start(vma_entry),
				vma_entry->start, vma_entry_len(vma_entry)))
			goto core_restore_end;
	}

	/*
	 * OK, lets try to map new one.
	 */
	for (vma_entry = args->tgt_vmas; vma_entry->start != 0; vma_entry++) {
		if (!vma_entry_is(vma_entry, VMA_AREA_REGULAR))
			continue;

		if (vma_priv(vma_entry))
			continue;

		va = restore_mapping(vma_entry);

		if (va != vma_entry->start) {
			pr_err("Can't restore %lx mapping with %lx\n", vma_entry->start, va);
			goto core_restore_end;
		}
	}

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

	/*
	 * Finally restore madivse() bits
	 */
	for (vma_entry = args->tgt_vmas; vma_entry->start != 0; vma_entry++) {
		unsigned long i;

		if (!vma_entry->has_madv || !vma_entry->madv)
			continue;
		for (i = 0; i < sizeof(vma_entry->madv) * 8; i++) {
			if (vma_entry->madv & (1ul << i)) {
				ret = sys_madvise(vma_entry->start,
						  vma_entry_len(vma_entry),
						  i);
				if (ret) {
					pr_err("madvise(%lx, %ld, %ld) "
					       "failed with %ld\n",
						vma_entry->start,
						vma_entry_len(vma_entry),
						i, ret);
					goto core_restore_end;
				}
			}
		}
	}

	sys_munmap(args->tgt_vmas,
			((void *)(vma_entry + 1) - ((void *)args->tgt_vmas)));

	ret = sys_munmap(args->shmems, SHMEMS_SIZE);
	if (ret < 0) {
		pr_err("Can't unmap shmem %ld\n", ret);
		goto core_restore_end;
	}

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
	ret |= sys_prctl_safe(PR_SET_MM, PR_SET_MM_AUXV,	(long)args->mm_saved_auxv, args->mm_saved_auxv_size);
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

	/*
	 * We need to prepare a valid sigframe here, so
	 * after sigreturn the kernel will pick up the
	 * registers from the frame, set them up and
	 * finally pass execution to the new IP.
	 */
	rt_sigframe = (void *)args->t.mem_zone.rt_sigframe + 8;

	if (restore_thread_common(rt_sigframe, &args->t))
		goto core_restore_end;

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
			pr_err("Can't open last_pid %d\n", fd);
			goto core_restore_end;
		}

		ret = sys_flock(fd, LOCK_EX);
		if (ret) {
			pr_err("Can't lock last_pid %d\n", fd);
			goto core_restore_end;
		}

		for (i = 0; i < args->nr_threads; i++) {
			char last_pid_buf[16], *s;

			/* skip self */
			if (thread_args[i].pid == args->t.pid)
				continue;

			mutex_lock(&args->rst_lock);

			new_sp =
				RESTORE_ALIGN_STACK((long)thread_args[i].mem_zone.stack,
						    sizeof(thread_args[i].mem_zone.stack));

			last_pid_len = vprint_num(last_pid_buf, sizeof(last_pid_buf), thread_args[i].pid - 1, &s);
			ret = sys_write(fd, s, last_pid_len);
			if (ret < 0) {
				pr_err("Can't set last_pid %ld/%s\n", ret, last_pid_buf);
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
			pr_err("Can't unlock last_pid %ld\n", ret);
			goto core_restore_end;
		}

		sys_close(fd);
	}

	/* 
	 * Writing to last-pid is CAP_SYS_ADMIN protected, thus restore
	 * creds _after_ all threads creation.
	 */

	restore_creds(&args->creds);

	pr_info("%ld: Restored\n", sys_getpid());

	restore_finish_stage(CR_STATE_RESTORE);

	sys_sigaction(SIGCHLD, &args->sigchld_act, NULL, sizeof(rt_sigset_t));

	futex_set_and_wake(&thread_inprogress, args->nr_threads);

	restore_finish_stage(CR_STATE_RESTORE_SIGCHLD);

	/* Wait until children stop to use args->task_entries */
	futex_wait_while_gt(&thread_inprogress, 1);

	rst_tcp_socks_all(args->rst_tcp_socks, args->rst_tcp_socks_size);

	log_set_fd(-1);

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
	pr_err("Restorer fail %ld\n", sys_getpid());
	sys_exit_group(1);
	return -1;

core_restore_failed:
	asm volatile(
		"movq %0, %%rsp				\n"
		"movq 0, %%rax				\n"
		"jmp *%%rax				\n"
		:
		: "r"(ret)
		: "memory");
	return ret;
}
