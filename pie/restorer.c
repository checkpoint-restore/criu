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
#include <signal.h>

#include "compiler.h"
#include "asm/types.h"
#include "syscall.h"
#include "log.h"
#include "util.h"
#include "image.h"
#include "sk-inet.h"

#include "crtools.h"
#include "lock.h"
#include "restorer.h"

#include "protobuf/creds.pb-c.h"

#include "asm/restorer.h"

#define sys_prctl_safe(opcode, val1, val2, val3)			\
	({								\
		long __ret = sys_prctl(opcode, val1, val2, val3, 0);	\
		if (__ret) 						\
			 pr_err("prctl failed @%d with %ld\n", __LINE__, __ret);\
		__ret;							\
	})

static struct task_entries *task_entries;
static futex_t thread_inprogress;
static futex_t zombies_inprogress;
static int cap_last_cap;

extern void cr_restore_rt (void) asm ("__cr_restore_rt")
			__attribute__ ((visibility ("hidden")));

static void sigchld_handler(int signal, siginfo_t *siginfo, void *data)
{
	char *r;

	if (futex_get(&task_entries->start) == CR_STATE_RESTORE_SIGCHLD) {
		pr_debug("%ld: Collect a zombie with (pid %d, %d)\n",
			sys_getpid(), siginfo->si_pid, siginfo->si_pid);
		futex_dec_and_wake(&task_entries->nr_in_progress);
		futex_dec_and_wake(&zombies_inprogress);
		task_entries->nr_threads--;
		task_entries->nr_tasks--;
		mutex_unlock(&task_entries->zombie_lock);
		return;
	}

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

static int restore_creds(CredsEntry *ce)
{
	int b, i, ret;
	struct cap_header hdr;
	struct cap_data data[_LINUX_CAPABILITY_U32S_3];

	/*
	 * We're still root here and thus can do it without failures.
	 */

	/*
	 * First -- set the SECURE_NO_SETUID_FIXUP bit not to
	 * lose caps bits when changing xids.
	 */

	ret = sys_prctl(PR_SET_SECUREBITS, 1 << SECURE_NO_SETUID_FIXUP, 0, 0, 0);
	if (ret) {
		pr_err("Unable to set SECURE_NO_SETUID_FIXUP: %d\n", ret);
		return -1;
	}

	/*
	 * Second -- restore xids. Since we still have the CAP_SETUID
	 * capability nothing should fail. But call the setfsXid last
	 * to override the setresXid settings.
	 */

	ret = sys_setresuid(ce->uid, ce->euid, ce->suid);
	if (ret) {
		pr_err("Unable to set real, effective and saved user ID: %d\n", ret);
		return -1;
	}

	sys_setfsuid(ce->fsuid);
	if (sys_setfsuid(-1) != ce->fsuid) {
		pr_err("Unable to set fsuid\n");
		return -1;
	}

	ret = sys_setresgid(ce->gid, ce->egid, ce->sgid);
	if (ret) {
		pr_err("Unable to set real, effective and saved group ID: %d\n", ret);
		return -1;
	}

	sys_setfsgid(ce->fsgid);
	if (sys_setfsgid(-1) != ce->fsgid) {
		pr_err("Unable to set fsgid\n");
		return -1;
	}

	/*
	 * Third -- restore securebits. We don't need them in any
	 * special state any longer.
	 */

	ret = sys_prctl(PR_SET_SECUREBITS, ce->secbits, 0, 0, 0);
	if (ret) {
		pr_err("Unable to set PR_SET_SECUREBITS: %d\n", ret);
		return -1;
	}

	/*
	 * Fourth -- trim bset. This can only be done while
	 * having the CAP_SETPCAP capablity.
	 */

	for (b = 0; b < CR_CAP_SIZE; b++) {
		for (i = 0; i < 32; i++) {
			if (b * 32 + i > cap_last_cap)
				break;
			if (ce->cap_bnd[b] & (1 << i))
				/* already set */
				continue;
			ret = sys_prctl(PR_CAPBSET_DROP, i + b * 32, 0, 0, 0);
			if (ret) {
				pr_err("Unable to drop capability %d: %d\n",
								i + b * 32, ret);
				return -1;
			}
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

	ret = sys_capset(&hdr, data);
	if (ret) {
		pr_err("Unable to restore capabilities: %d\n", ret);
		return -1;
	}

	return 0;
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

static void restore_rlims(struct task_restore_core_args *ta)
{
	int r;

	for (r = 0; r < ta->nr_rlim; r++) {
		struct krlimit krlim;

		krlim.rlim_cur = ta->rlims[r].rlim_cur;
		krlim.rlim_max = ta->rlims[r].rlim_max;
		sys_setrlimit(r, &krlim);
	}
}

static int restore_signals(siginfo_t *ptr, int nr, bool group)
{
	int ret, i;
	k_rtsigset_t to_block;

	ksigfillset(&to_block);
	ret = sys_sigprocmask(SIG_SETMASK, &to_block, NULL, sizeof(k_rtsigset_t));
	if (ret) {
		pr_err("Unable to block signals %d", ret);
		return -1;
	}

	for (i = 0; i < nr; i++) {
		siginfo_t *info = ptr + i;

		pr_info("Restore signal %d group %d\n", info->si_signo, group);
		if (group)
			ret = sys_rt_sigqueueinfo(sys_getpid(), info->si_signo, info);
		else
			ret = sys_rt_tgsigqueueinfo(sys_getpid(),
						sys_gettid(), info->si_signo, info);
		if (ret) {
			pr_err("Unable to send siginfo %d %x with code %d\n",
					info->si_signo, info->si_code, ret);
			return -1;;
		}
	}

	return 0;
}

static int restore_thread_common(struct rt_sigframe *sigframe,
		struct thread_restore_args *args)
{
	sys_set_tid_address((int *)decode_pointer(args->clear_tid_addr));

	if (args->has_futex && args->futex_rla_len) {
		int ret;

		ret = sys_set_robust_list(decode_pointer(args->futex_rla),
					  args->futex_rla_len);
		if (ret) {
			pr_err("Failed to recover futex robust list: %d\n", ret);
			return -1;
		}
	}

	if (args->has_blk_sigset)
		RT_SIGFRAME_UC(sigframe).uc_sigmask = args->blk_sigset;

	restore_sched_info(&args->sp);
	if (restore_fpu(sigframe, args))
		return -1;

	if (restore_gpregs(sigframe, &args->gpregs))
		return -1;

	restore_tls(args->tls);

	return 0;
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
	int ret;

	if (my_pid != args->pid) {
		pr_err("Thread pid mismatch %d/%d\n", my_pid, args->pid);
		goto core_restore_end;
	}

	rt_sigframe = (void *)args->mem_zone.rt_sigframe + 8;

	if (restore_thread_common(rt_sigframe, args))
		goto core_restore_end;

	mutex_unlock(&args->ta->rst_lock);

	ret = restore_creds(&args->ta->creds);
	if (ret)
		goto core_restore_end;

	pr_info("%ld: Restored\n", sys_gettid());

	restore_finish_stage(CR_STATE_RESTORE);

	if (restore_signals(args->siginfo, args->siginfo_nr, false))
		goto core_restore_end;

	restore_finish_stage(CR_STATE_RESTORE_SIGCHLD);
	restore_finish_stage(CR_STATE_RESTORE_CREDS);
	futex_dec_and_wake(&thread_inprogress);

	new_sp = (long)rt_sigframe + SIGFRAME_OFFSET;
	ARCH_RT_SIGRETURN(new_sp);

core_restore_end:
	pr_err("Restorer abnormal termination for %ld\n", sys_getpid());
	futex_abort_and_wake(&task_entries->nr_in_progress);
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
		return sys_shmat(vma_entry->fd, decode_pointer(vma_entry->start),
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

	pr_debug("\tmmap(%"PRIx64" -> %"PRIx64", %x %x %d\n",
			vma_entry->start, vma_entry->end,
			prot, flags, (int)vma_entry->fd);
	/*
	 * Should map memory here. Note we map them as
	 * writable since we're going to restore page
	 * contents.
	 */
	addr = sys_mmap(decode_pointer(vma_entry->start),
			vma_entry_len(vma_entry),
			prot, flags,
			vma_entry->fd,
			vma_entry->pgoff);

	if (vma_entry->fd != -1)
		sys_close(vma_entry->fd);

	return addr;
}

static void rst_tcp_repair_off(struct rst_tcp_sock *rts)
{
	int aux, ret;

	aux = rts->reuseaddr;
	pr_debug("pie: Turning repair off for %d (reuse %d)\n", rts->sk, aux);
	tcp_repair_off(rts->sk);

	ret = sys_setsockopt(rts->sk, SOL_SOCKET, SO_REUSEADDR, &aux, sizeof(aux));
	if (ret < 0)
		pr_perror("Failed to restore of SO_REUSEADDR on socket (%d)", ret);
}

static void rst_tcp_socks_all(struct rst_tcp_sock *arr, int size)
{
	int i;

	if (size == 0)
		return;

	for (i =0; arr[i].sk >= 0; i++)
		rst_tcp_repair_off(arr + i);

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

	ksigfillset(&act.rt_sa_mask);
	act.rt_sa_handler = sigchld_handler;
	act.rt_sa_flags = SA_SIGINFO | SA_RESTORER | SA_RESTART;
	act.rt_sa_restorer = cr_restore_rt;
	sys_sigaction(SIGCHLD, &act, NULL, sizeof(k_rtsigset_t));

	log_set_fd(args->logfd);
	log_set_loglevel(args->loglevel);

	cap_last_cap = args->cap_last_cap;

	pr_info("Switched to the restorer %d\n", my_pid);

	for (vma_entry = args->self_vmas; vma_entry->start != 0; vma_entry++) {
		unsigned long addr = vma_entry->start;
		unsigned long len;

		if (!vma_entry_is(vma_entry, VMA_AREA_REGULAR))
			continue;

		pr_debug("Examine %"PRIx64"-%"PRIx64"\n", vma_entry->start, vma_entry->end);

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

		if (vma_entry->end >= TASK_SIZE)
			continue;

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

		if (vma_entry->end >= TASK_SIZE)
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

		if (vma_entry->start > TASK_SIZE)
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
			pr_err("Can't restore %"PRIx64" mapping with %"PRIx64"\n", vma_entry->start, va);
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

		sys_mprotect(decode_pointer(vma_entry->start),
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
					pr_err("madvise(%"PRIx64", %"PRIu64", %ld) "
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
	rt_sigframe = (void *)args->t->mem_zone.rt_sigframe + 8;

	if (restore_thread_common(rt_sigframe, args->t))
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
			if (thread_args[i].pid == args->t->pid)
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

			RUN_CLONE_RESTORE_FN(ret, clone_flags, new_sp, parent_tid, thread_args, args->clone_restore_fn);
		}

		ret = sys_flock(fd, LOCK_UN);
		if (ret) {
			pr_err("Can't unlock last_pid %ld\n", ret);
			goto core_restore_end;
		}

		sys_close(fd);
	}

	restore_rlims(args);

	pr_info("%ld: Restored\n", sys_getpid());

	futex_set(&zombies_inprogress, args->nr_zombies);

	restore_finish_stage(CR_STATE_RESTORE);

	futex_wait_while_gt(&zombies_inprogress, 0);

	sys_sigaction(SIGCHLD, &args->sigchld_act, NULL, sizeof(k_rtsigset_t));

	ret = restore_signals(args->siginfo, args->siginfo_nr, true);
	if (ret)
		goto core_restore_end;

	ret = restore_signals(args->t->siginfo, args->t->siginfo_nr, false);
	if (ret)
		goto core_restore_end;

	restore_finish_stage(CR_STATE_RESTORE_SIGCHLD);

	if (args->siginfo_size) {
		ret = sys_munmap(args->siginfo, args->siginfo_size);
		if (ret < 0) {
			pr_err("Can't unmap signals %ld\n", ret);
			goto core_restore_failed;
		}
	}

	rst_tcp_socks_all(args->rst_tcp_socks, args->rst_tcp_socks_size);

	/* 
	 * Writing to last-pid is CAP_SYS_ADMIN protected,
	 * turning off TCP repair is CAP_SYS_NED_ADMIN protected,
	 * thus restore* creds _after_ all of the above.
	 */

	ret = restore_creds(&args->creds);

	futex_set_and_wake(&thread_inprogress, args->nr_threads);

	restore_finish_stage(CR_STATE_RESTORE_CREDS);

	if (ret)
		BUG();

	/* Wait until children stop to use args->task_entries */
	futex_wait_while_gt(&thread_inprogress, 1);

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
		ret = ((long)__LINE__ << 16) | ((-ret) & 0xffff);
		goto core_restore_failed;
	}

	/*
	 * Sigframe stack.
	 */
	new_sp = (long)rt_sigframe + SIGFRAME_OFFSET;

	/*
	 * Prepare the stack and call for sigreturn,
	 * pure assembly since we don't need any additional
	 * code insns from gcc.
	 */
	ARCH_RT_SIGRETURN(new_sp);

core_restore_end:
	futex_abort_and_wake(&task_entries->nr_in_progress);
	pr_err("Restorer fail %ld\n", sys_getpid());
	sys_exit_group(1);
	return -1;

core_restore_failed:
	ARCH_FAIL_CORE_RESTORE;

	return ret;
}
