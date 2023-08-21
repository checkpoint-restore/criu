#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <sched.h>
#include <sys/resource.h>

#include "types.h"
#include "protobuf.h"
#include "images/fdinfo.pb-c.h"
#include "images/fs.pb-c.h"
#include "images/mm.pb-c.h"
#include "images/creds.pb-c.h"
#include "images/core.pb-c.h"
#include "images/file-lock.pb-c.h"
#include "images/rlimit.pb-c.h"
#include "images/siginfo.pb-c.h"

#include "common/list.h"
#include "imgset.h"
#include "file-ids.h"
#include "kcmp-ids.h"
#include "common/compiler.h"
#include "crtools.h"
#include "cr_options.h"
#include "servicefd.h"
#include "string.h"
#include "ptrace-compat.h"
#include "util.h"
#include "namespaces.h"
#include "image.h"
#include "proc_parse.h"
#include "parasite.h"
#include "parasite-syscall.h"
#include "compel/ptrace.h"
#include "files.h"
#include "files-reg.h"
#include "shmem.h"
#include "sk-inet.h"
#include "pstree.h"
#include "mount.h"
#include "tty.h"
#include "net.h"
#include "sk-packet.h"
#include "cpu.h"
#include "elf.h"
#include "cgroup.h"
#include "cgroup-props.h"
#include "file-lock.h"
#include "page-xfer.h"
#include "kerndat.h"
#include "stats.h"
#include "mem.h"
#include "page-pipe.h"
#include "posix-timer.h"
#include "vdso.h"
#include "vma.h"
#include "cr-service.h"
#include "plugin.h"
#include "irmap.h"
#include "sysfs_parse.h"
#include "action-scripts.h"
#include "aio.h"
#include "lsm.h"
#include "seccomp.h"
#include "seize.h"
#include "fault-injection.h"
#include "dump.h"
#include "eventpoll.h"
#include "memfd.h"
#include "timens.h"
#include "img-streamer.h"
#include "pidfd-store.h"
#include "apparmor.h"
#include "asm/dump.h"

/*
 * Architectures can overwrite this function to restore register sets that
 * are not covered by ptrace_set/get_regs().
 *
 * with_threads = false: Only the register sets of the tasks are restored
 * with_threads = true : The register sets of the tasks with all their threads
 *			 are restored
 */
int __attribute__((weak)) arch_set_thread_regs(struct pstree_item *item, bool with_threads)
{
	return 0;
}

#define PERSONALITY_LENGTH 9
static char loc_buf[PERSONALITY_LENGTH];

void free_mappings(struct vm_area_list *vma_area_list)
{
	struct vma_area *vma_area, *p;

	list_for_each_entry_safe(vma_area, p, &vma_area_list->h, list) {
		if (!vma_area->file_borrowed)
			free(vma_area->vmst);
		free(vma_area);
	}

	vm_area_list_init(vma_area_list);
}

int collect_mappings(pid_t pid, struct vm_area_list *vma_area_list, dump_filemap_t dump_file)
{
	int ret = -1;

	pr_info("\n");
	pr_info("Collecting mappings (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	ret = parse_smaps(pid, vma_area_list, dump_file);
	if (ret < 0)
		goto err;

	pr_info("Collected, longest area occupies %lu pages\n", vma_area_list->nr_priv_pages_longest);
	pr_info_vma_list(&vma_area_list->h);

	pr_info("----------------------------------------\n");
err:
	return ret;
}

static int dump_sched_info(int pid, ThreadCoreEntry *tc)
{
	int ret;
	struct sched_param sp;

	BUILD_BUG_ON(SCHED_OTHER != 0); /* default in proto message */

	/*
	 * In musl-libc sched_getscheduler and sched_getparam don't call
	 * syscalls and instead the always return -ENOSYS
	 */
	ret = syscall(__NR_sched_getscheduler, pid);
	if (ret < 0) {
		pr_perror("Can't get sched policy for %d", pid);
		return -1;
	}

	pr_info("%d has %d sched policy\n", pid, ret);
	tc->has_sched_policy = true;
	tc->sched_policy = ret;

	if ((ret == SCHED_RR) || (ret == SCHED_FIFO)) {
		ret = syscall(__NR_sched_getparam, pid, &sp);
		if (ret < 0) {
			pr_perror("Can't get sched param for %d", pid);
			return -1;
		}

		pr_info("\tdumping %d prio for %d\n", sp.sched_priority, pid);
		tc->has_sched_prio = true;
		tc->sched_prio = sp.sched_priority;
	}

	/*
	 * The nice is ignored for RT sched policies, but is stored
	 * in kernel. Thus we have to take it with us in the image.
	 */

	errno = 0;
	ret = getpriority(PRIO_PROCESS, pid);
	if (ret == -1 && errno) {
		pr_perror("Can't get nice for %d ret %d", pid, ret);
		return -1;
	}

	pr_info("\tdumping %d nice for %d\n", ret, pid);
	tc->has_sched_nice = true;
	tc->sched_nice = ret;

	return 0;
}

static int check_thread_rseq(pid_t tid, const struct parasite_check_rseq *ti_rseq)
{
	if (!kdat.has_rseq || kdat.has_ptrace_get_rseq_conf)
		return 0;

	pr_debug("%d has rseq_inited = %d\n", tid, ti_rseq->rseq_inited);

	/*
	 * We have no kdat.has_ptrace_get_rseq_conf and user
	 * process has rseq() used, let's fail dump.
	 */
	if (ti_rseq->rseq_inited) {
		pr_err("%d has rseq but kernel lacks get_rseq_conf feature\n", tid);
		return -1;
	}

	return 0;
}

struct cr_imgset *glob_imgset;

static int collect_fds(pid_t pid, struct parasite_drain_fd **dfds)
{
	struct dirent *de;
	DIR *fd_dir;
	int size = 0;
	int n;

	pr_info("\n");
	pr_info("Collecting fds (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	fd_dir = opendir_proc(pid, "fd");
	if (!fd_dir)
		return -1;

	n = 0;
	while ((de = readdir(fd_dir))) {
		if (dir_dots(de))
			continue;

		if (sizeof(struct parasite_drain_fd) + sizeof(int) * (n + 1) > size) {
			struct parasite_drain_fd *t;

			size += PAGE_SIZE;
			t = xrealloc(*dfds, size);
			if (!t) {
				closedir(fd_dir);
				return -1;
			}
			*dfds = t;
		}

		(*dfds)->fds[n++] = atoi(de->d_name);
	}

	(*dfds)->nr_fds = n;
	pr_info("Found %d file descriptors\n", n);
	pr_info("----------------------------------------\n");

	closedir(fd_dir);

	return 0;
}

static int fill_fd_params_special(int fd, struct fd_parms *p)
{
	*p = FD_PARMS_INIT;

	if (fstat(fd, &p->stat) < 0) {
		pr_perror("Can't fstat exe link");
		return -1;
	}

	if (get_fd_mntid(fd, &p->mnt_id))
		return -1;

	return 0;
}

static long get_fs_type(int lfd)
{
	struct statfs fst;

	if (fstatfs(lfd, &fst)) {
		pr_perror("Unable to statfs fd %d", lfd);
		return -1;
	}
	return fst.f_type;
}

static int dump_one_reg_file_cond(int lfd, u32 *id, struct fd_parms *parms)
{
	if (fd_id_generate_special(parms, id)) {
		parms->fs_type = get_fs_type(lfd);
		if (parms->fs_type < 0)
			return -1;
		return dump_one_reg_file(lfd, *id, parms);
	}
	return 0;
}

static int dump_task_exe_link(pid_t pid, MmEntry *mm)
{
	struct fd_parms params;
	int fd, ret = 0;

	fd = open_proc_path(pid, "exe");
	if (fd < 0)
		return -1;

	if (fill_fd_params_special(fd, &params))
		return -1;

	ret = dump_one_reg_file_cond(fd, &mm->exe_file_id, &params);

	close(fd);
	return ret;
}

static int dump_task_fs(pid_t pid, struct parasite_dump_misc *misc, struct cr_imgset *imgset)
{
	struct fd_parms p;
	FsEntry fe = FS_ENTRY__INIT;
	int fd, ret;

	fe.has_umask = true;
	fe.umask = misc->umask;

	fd = open_proc_path(pid, "cwd");
	if (fd < 0)
		return -1;

	if (fill_fd_params_special(fd, &p))
		return -1;

	ret = dump_one_reg_file_cond(fd, &fe.cwd_id, &p);
	if (ret < 0)
		return ret;

	close(fd);

	fd = open_proc_path(pid, "root");
	if (fd < 0)
		return -1;

	if (fill_fd_params_special(fd, &p))
		return -1;

	ret = dump_one_reg_file_cond(fd, &fe.root_id, &p);
	if (ret < 0)
		return ret;

	close(fd);

	pr_info("Dumping task cwd id %#x root id %#x\n", fe.cwd_id, fe.root_id);

	return pb_write_one(img_from_set(imgset, CR_FD_FS), &fe, PB_FS);
}

static inline rlim_t encode_rlim(rlim_t val)
{
	return val == RLIM_INFINITY ? -1 : val;
}

static int dump_task_rlimits(int pid, TaskRlimitsEntry *rls)
{
	int res;

	for (res = 0; res < rls->n_rlimits; res++) {
		struct rlimit64 lim;

		if (syscall(__NR_prlimit64, pid, res, NULL, &lim)) {
			pr_perror("Can't get rlimit %d", res);
			return -1;
		}

		rls->rlimits[res]->cur = encode_rlim(lim.rlim_cur);
		rls->rlimits[res]->max = encode_rlim(lim.rlim_max);
	}

	return 0;
}

static int dump_pid_misc(pid_t pid, TaskCoreEntry *tc)
{
	int ret;

	if (kdat.luid != LUID_NONE) {
		pr_info("dumping /proc/%d/loginuid\n", pid);

		tc->has_loginuid = true;
		tc->loginuid = parse_pid_loginuid(pid, &ret, false);
		tc->loginuid = userns_uid(tc->loginuid);
		/*
		 * loginuid dumping is critical, as if not correctly
		 * restored, you may loss ability to login via SSH to CT
		 */
		if (ret < 0)
			return ret;
	} else {
		tc->has_loginuid = false;
	}

	pr_info("dumping /proc/%d/oom_score_adj\n", pid);

	tc->oom_score_adj = parse_pid_oom_score_adj(pid, &ret);
	/*
	 * oom_score_adj dumping is not very critical, as it will affect
	 * on victim in OOM situation and one will find dumping error in log
	 */
	if (ret < 0)
		tc->has_oom_score_adj = false;
	else
		tc->has_oom_score_adj = true;

	return 0;
}

static int dump_filemap(struct vma_area *vma_area, int fd)
{
	struct fd_parms p = FD_PARMS_INIT;
	VmaEntry *vma = vma_area->e;
	int ret = 0;
	u32 id;

	BUG_ON(!vma_area->vmst);
	p.stat = *vma_area->vmst;
	p.mnt_id = vma_area->mnt_id;

	/*
	 * AUFS support to compensate for the kernel bug
	 * exposing branch pathnames in map_files.
	 *
	 * If the link found in vma_get_mapfile() pointed
	 * inside a branch, we should use the pathname
	 * from root that was saved in vma_area->aufs_rpath.
	 */
	if (vma_area->aufs_rpath) {
		struct fd_link aufs_link;

		__strlcpy(aufs_link.name, vma_area->aufs_rpath, sizeof(aufs_link.name));
		aufs_link.len = strlen(aufs_link.name);
		p.link = &aufs_link;
	}

	/* Flags will be set during restore in open_filmap() */

	if (vma->status & VMA_AREA_MEMFD)
		ret = dump_one_memfd_cond(fd, &id, &p);
	else
		ret = dump_one_reg_file_cond(fd, &id, &p);

	vma->shmid = id;
	return ret;
}

static int check_sysvipc_map_dump(pid_t pid, VmaEntry *vma)
{
	if (root_ns_mask & CLONE_NEWIPC)
		return 0;

	pr_err("Task %d with SysVIPC shmem map @%" PRIx64 " doesn't live in IPC ns\n", pid, vma->start);
	return -1;
}

static int get_task_auxv(pid_t pid, MmEntry *mm)
{
	auxv_t mm_saved_auxv[AT_VECTOR_SIZE];
	int fd, i, ret;

	pr_info("Obtaining task auvx ...\n");

	fd = open_proc(pid, "auxv");
	if (fd < 0)
		return -1;

	ret = read(fd, mm_saved_auxv, sizeof(mm_saved_auxv));
	if (ret < 0) {
		ret = -1;
		pr_perror("Error reading %d's auxv", pid);
		goto err;
	} else {
		mm->n_mm_saved_auxv = ret / sizeof(auxv_t);
		for (i = 0; i < mm->n_mm_saved_auxv; i++)
			mm->mm_saved_auxv[i] = (u64)mm_saved_auxv[i];
	}

	ret = 0;
err:
	close_safe(&fd);
	return ret;
}

static int dump_task_mm(pid_t pid, const struct proc_pid_stat *stat, const struct parasite_dump_misc *misc,
			const struct vm_area_list *vma_area_list, const struct cr_imgset *imgset)
{
	MmEntry mme = MM_ENTRY__INIT;
	struct vma_area *vma_area;
	int ret = -1, i = 0;

	pr_info("\n");
	pr_info("Dumping mm (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	mme.n_vmas = vma_area_list->nr;
	mme.vmas = xmalloc(mme.n_vmas * sizeof(VmaEntry *));
	if (!mme.vmas)
		return -1;

	list_for_each_entry(vma_area, &vma_area_list->h, list) {
		VmaEntry *vma = vma_area->e;

		pr_info_vma(vma_area);

		if (!vma_entry_is(vma, VMA_AREA_REGULAR))
			ret = 0;
		else if (vma_entry_is(vma, VMA_AREA_SYSVIPC))
			ret = check_sysvipc_map_dump(pid, vma);
		else if (vma_entry_is(vma, VMA_AREA_SOCKET))
			ret = dump_socket_map(vma_area);
		else
			ret = 0;
		if (ret)
			goto err;

		mme.vmas[i++] = vma;

		if (vma_entry_is(vma, VMA_AREA_AIORING)) {
			ret = dump_aio_ring(&mme, vma_area);
			if (ret)
				goto err;
		}
	}

	mme.mm_start_code = stat->start_code;
	mme.mm_end_code = stat->end_code;
	mme.mm_start_data = stat->start_data;
	mme.mm_end_data = stat->end_data;
	mme.mm_start_stack = stat->start_stack;
	mme.mm_start_brk = stat->start_brk;

	mme.mm_arg_start = stat->arg_start;
	mme.mm_arg_end = stat->arg_end;
	mme.mm_env_start = stat->env_start;
	mme.mm_env_end = stat->env_end;

	mme.mm_brk = misc->brk;

	mme.dumpable = misc->dumpable;
	mme.has_dumpable = true;

	mme.thp_disabled = misc->thp_disabled;
	mme.has_thp_disabled = true;

	mme.n_mm_saved_auxv = AT_VECTOR_SIZE;
	mme.mm_saved_auxv = xmalloc(pb_repeated_size(&mme, mm_saved_auxv));
	if (!mme.mm_saved_auxv)
		goto err;

	if (get_task_auxv(pid, &mme))
		goto err;

	if (dump_task_exe_link(pid, &mme))
		goto err;

	ret = pb_write_one(img_from_set(imgset, CR_FD_MM), &mme, PB_MM);
	xfree(mme.mm_saved_auxv);
	free_aios(&mme);
err:
	xfree(mme.vmas);
	return ret;
}

static int get_task_futex_robust_list(pid_t pid, ThreadCoreEntry *info)
{
	struct robust_list_head *head = NULL;
	size_t len = 0;
	int ret;

	ret = syscall(SYS_get_robust_list, pid, &head, &len);
	if (ret < 0 && errno == ENOSYS) {
		/*
		 * If the kernel says get_robust_list is not implemented, then
		 * check whether set_robust_list is also not implemented, in
		 * that case we can assume it is empty, since set_robust_list
		 * is the only way to populate it. This case is possible when
		 * "futex_cmpxchg_enabled" is unset in the kernel.
		 *
		 * The following system call should always fail, even if it is
		 * implemented, in which case it will return -EINVAL because
		 * len should be greater than zero.
		 */
		ret = syscall(SYS_set_robust_list, NULL, 0);
		if (ret == 0 || (ret < 0 && errno != ENOSYS))
			goto err;

		head = NULL;
		len = 0;
	} else if (ret) {
		goto err;
	}

	info->futex_rla = encode_pointer(head);
	info->futex_rla_len = (u32)len;

	return 0;

err:
	pr_err("Failed obtaining futex robust list on %d\n", pid);
	return -1;
}

static int get_task_personality(pid_t pid, u32 *personality)
{
	int fd, ret = -1;

	pr_info("Obtaining personality ... \n");

	fd = open_proc(pid, "personality");
	if (fd < 0)
		goto err;

	ret = read(fd, loc_buf, sizeof(loc_buf) - 1);
	close(fd);

	if (ret >= 0) {
		loc_buf[ret] = '\0';
		*personality = atoi(loc_buf);
	}
err:
	return ret;
}

static DECLARE_KCMP_TREE(vm_tree, KCMP_VM);
static DECLARE_KCMP_TREE(fs_tree, KCMP_FS);
static DECLARE_KCMP_TREE(files_tree, KCMP_FILES);
static DECLARE_KCMP_TREE(sighand_tree, KCMP_SIGHAND);

static int dump_task_kobj_ids(struct pstree_item *item)
{
	int new;
	struct kid_elem elem;
	int pid = item->pid->real;
	TaskKobjIdsEntry *ids = item->ids;

	elem.pid = pid;
	elem.idx = 0;	/* really 0 for all */
	elem.genid = 0; /* FIXME optimize */

	new = 0;
	ids->vm_id = kid_generate_gen(&vm_tree, &elem, &new);
	if (!ids->vm_id || !new) {
		pr_err("Can't make VM id for %d\n", pid);
		return -1;
	}

	new = 0;
	ids->fs_id = kid_generate_gen(&fs_tree, &elem, &new);
	if (!ids->fs_id || !new) {
		pr_err("Can't make FS id for %d\n", pid);
		return -1;
	}

	new = 0;
	ids->files_id = kid_generate_gen(&files_tree, &elem, &new);
	if (!ids->files_id || (!new && !shared_fdtable(item))) {
		pr_err("Can't make FILES id for %d\n", pid);
		return -1;
	}

	new = 0;
	ids->sighand_id = kid_generate_gen(&sighand_tree, &elem, &new);
	if (!ids->sighand_id || !new) {
		pr_err("Can't make IO id for %d\n", pid);
		return -1;
	}

	return 0;
}

int get_task_ids(struct pstree_item *item)
{
	int ret;

	item->ids = xmalloc(sizeof(*item->ids));
	if (!item->ids)
		goto err;

	task_kobj_ids_entry__init(item->ids);

	if (item->pid->state != TASK_DEAD) {
		ret = dump_task_kobj_ids(item);
		if (ret)
			goto err_free;

		ret = dump_task_ns_ids(item);
		if (ret)
			goto err_free;
	}

	return 0;

err_free:
	xfree(item->ids);
	item->ids = NULL;
err:
	return -1;
}

static int dump_task_ids(struct pstree_item *item, const struct cr_imgset *cr_imgset)
{
	return pb_write_one(img_from_set(cr_imgset, CR_FD_IDS), item->ids, PB_IDS);
}

int dump_thread_core(int pid, CoreEntry *core, const struct parasite_dump_thread *ti)

{
	int ret;
	ThreadCoreEntry *tc = core->thread_core;

	/*
	 * XXX: It's possible to set two: 32-bit and 64-bit
	 * futex list's heads. That makes about no sense, but
	 * it's possible. Until we meet such application, dump
	 * only one: native or compat futex's list pointer.
	 */
	if (!core_is_compat(core))
		ret = get_task_futex_robust_list(pid, tc);
	else
		ret = get_task_futex_robust_list_compat(pid, tc);
	if (!ret)
		ret = dump_sched_info(pid, tc);
	if (!ret) {
		core_put_tls(core, ti->tls);
		CORE_THREAD_ARCH_INFO(core)->clear_tid_addr = encode_pointer(ti->tid_addr);
		BUG_ON(!tc->sas);
		copy_sas(tc->sas, &ti->sas);
		if (ti->pdeath_sig) {
			tc->has_pdeath_sig = true;
			tc->pdeath_sig = ti->pdeath_sig;
		}
		tc->comm = xstrdup(ti->comm);
		if (tc->comm == NULL)
			return -1;
	}
	if (!ret)
		ret = seccomp_dump_thread(pid, tc);

	/*
	 * We are dumping rseq() in the dump_thread_rseq() function,
	 * *before* processes gets infected (because of ptrace requests
	 * API restriction). At this point, if the kernel lacks
	 * kdat.has_ptrace_get_rseq_conf support we have to ensure
	 * that dumpable processes haven't initialized rseq() or
	 * fail dump if rseq() was used.
	 */
	if (!ret)
		ret = check_thread_rseq(pid, &ti->rseq);

	return ret;
}

static int dump_task_core_all(struct parasite_ctl *ctl, struct pstree_item *item, const struct proc_pid_stat *stat,
			      const struct cr_imgset *cr_imgset, const struct parasite_dump_misc *misc)
{
	struct cr_img *img;
	CoreEntry *core = item->core[0];
	pid_t pid = item->pid->real;
	int ret = -1;
	struct parasite_dump_cgroup_args cgroup_args, *info = NULL;
	u32 *cg_set;

	BUILD_BUG_ON(sizeof(cgroup_args) < PARASITE_ARG_SIZE_MIN);

	pr_info("\n");
	pr_info("Dumping core (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	core->tc->child_subreaper = misc->child_subreaper;
	core->tc->has_child_subreaper = true;

	if (misc->membarrier_registration_mask) {
		core->tc->membarrier_registration_mask = misc->membarrier_registration_mask;
		core->tc->has_membarrier_registration_mask = true;
	}

	ret = get_task_personality(pid, &core->tc->personality);
	if (ret < 0)
		goto err;

	__strlcpy((char *)core->tc->comm, stat->comm, TASK_COMM_LEN);
	core->tc->flags = stat->flags;
	core->tc->task_state = item->pid->state;
	core->tc->exit_code = 0;

	core->thread_core->creds->lsm_profile = dmpi(item)->thread_lsms[0]->profile;
	core->thread_core->creds->lsm_sockcreate = dmpi(item)->thread_lsms[0]->sockcreate;

	if (core->tc->task_state == TASK_STOPPED) {
		core->tc->has_stop_signo = true;
		core->tc->stop_signo = item->pid->stop_signo;
	}

	ret = parasite_dump_thread_leader_seized(ctl, pid, core);
	if (ret)
		goto err;

	ret = dump_pid_misc(pid, core->tc);
	if (ret)
		goto err;

	ret = dump_task_rlimits(pid, core->tc->rlimits);
	if (ret)
		goto err;

	/* For now, we only need to dump the root task's cgroup ns, because we
	 * know all the tasks are in the same cgroup namespace because we don't
	 * allow nesting.
	 */
	if (item->ids->has_cgroup_ns_id && !item->parent) {
		info = &cgroup_args;
		strcpy(cgroup_args.thread_cgrp, "self/cgroup");
		ret = parasite_dump_cgroup(ctl, &cgroup_args);
		if (ret)
			goto err;
	}

	core->thread_core->has_cg_set = true;
	cg_set = &core->thread_core->cg_set;
	ret = dump_thread_cgroup(item, cg_set, info, -1);
	if (ret)
		goto err;

	img = img_from_set(cr_imgset, CR_FD_CORE);
	ret = pb_write_one(img, core, PB_CORE);

err:
	pr_info("----------------------------------------\n");

	return ret;
}

static int collect_pstree_ids_predump(void)
{
	struct pstree_item *item;
	struct pid pid;
	struct {
		struct pstree_item i;
		struct dmp_info d;
	} crt = {
		.i.pid = &pid,
	};

	/*
	 * This thing is normally done inside
	 * write_img_inventory().
	 */

	crt.i.pid->state = TASK_ALIVE;
	crt.i.pid->real = getpid();

	if (predump_task_ns_ids(&crt.i))
		return -1;

	for_each_pstree_item(item) {
		if (item->pid->state == TASK_DEAD)
			continue;

		if (predump_task_ns_ids(item))
			return -1;
	}

	return 0;
}

int collect_pstree_ids(void)
{
	struct pstree_item *item;

	for_each_pstree_item(item)
		if (get_task_ids(item))
			return -1;

	return 0;
}

static int collect_file_locks(void)
{
	return parse_file_locks();
}

static bool task_in_rseq(struct criu_rseq_cs *rseq_cs, uint64_t addr)
{
	return addr >= rseq_cs->start_ip && addr < rseq_cs->start_ip + rseq_cs->post_commit_offset;
}

static int fixup_thread_rseq(const struct pstree_item *item, int i)
{
	CoreEntry *core = item->core[i];
	struct criu_rseq_cs *rseq_cs = &dmpi(item)->thread_rseq_cs[i];
	pid_t tid = item->threads[i].real;

	if (!kdat.has_ptrace_get_rseq_conf)
		return 0;

	/* equivalent to (struct rseq)->rseq_cs is NULL */
	if (!rseq_cs->start_ip)
		return 0;

	pr_debug(
		"fixup_thread_rseq for %d: rseq_cs start_ip = %llx abort_ip = %llx post_commit_offset = %llx flags = %x version = %x; IP = %lx\n",
		tid, rseq_cs->start_ip, rseq_cs->abort_ip, rseq_cs->post_commit_offset, rseq_cs->flags,
		rseq_cs->version, (unsigned long)TI_IP(core));

	if (rseq_cs->version != 0) {
		pr_err("unsupported RSEQ ABI version = %d\n", rseq_cs->version);
		return -1;
	}

	if (task_in_rseq(rseq_cs, TI_IP(core))) {
		struct pid *tid = &item->threads[i];

		/*
		 * We need to fixup task instruction pointer from
		 * the original one (which lays inside rseq critical section)
		 * to rseq abort handler address. But we need to look on rseq_cs->flags
		 * (please refer to struct rseq -> flags field description).
		 * Naive idea of flags support may be like... let's change instruction pointer (IP)
		 * to rseq_cs->abort_ip if !(rseq_cs->flags & RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL).
		 * But unfortunately, it doesn't work properly, because the kernel does
		 * clean up of rseq_cs field in the struct rseq (modifies userspace memory).
		 * So, we need to preserve original value of (struct rseq)->rseq_cs field in the
		 * image and restore it's value before releasing threads (see restore_rseq_cs()).
		 *
		 * It's worth to mention that we need to fixup IP in CoreEntry
		 * (used when full dump/restore is performed) and also in
		 * the parasite regs storage (used if --leave-running option is used,
		 * or if dump error occurred and process execution is resumed).
		 */

		if (!(rseq_cs->flags & RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL)) {
			pr_warn("The %d task is in rseq critical section. IP will be set to rseq abort handler addr\n",
				tid->real);

			TI_IP(core) = rseq_cs->abort_ip;

			if (item->pid->real == tid->real) {
				compel_set_leader_ip(dmpi(item)->parasite_ctl, rseq_cs->abort_ip);
			} else {
				compel_set_thread_ip(dmpi(item)->thread_ctls[i], rseq_cs->abort_ip);
			}
		}
	}

	return 0;
}

static int dump_task_thread(struct parasite_ctl *parasite_ctl, const struct pstree_item *item, int id)
{
	struct parasite_thread_ctl *tctl = dmpi(item)->thread_ctls[id];
	struct pid *tid = &item->threads[id];
	CoreEntry *core = item->core[id];
	pid_t pid = tid->real;
	int ret = -1;
	struct cr_img *img;

	pr_info("\n");
	pr_info("Dumping core for thread (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	ret = parasite_dump_thread_seized(tctl, parasite_ctl, id, tid, core);
	if (ret) {
		pr_err("Can't dump thread for pid %d\n", pid);
		goto err;
	}
	pstree_insert_pid(tid);

	core->thread_core->creds->lsm_profile = dmpi(item)->thread_lsms[id]->profile;
	core->thread_core->creds->lsm_sockcreate = dmpi(item)->thread_lsms[0]->sockcreate;

	ret = fixup_thread_rseq(item, id);
	if (ret) {
		pr_err("Can't fixup rseq for pid %d\n", pid);
		goto err;
	}

	img = open_image(CR_FD_CORE, O_DUMP, tid->ns[0].virt);
	if (!img)
		goto err;

	ret = pb_write_one(img, core, PB_CORE);

	close_image(img);
err:
	compel_release_thread(tctl);
	pr_info("----------------------------------------\n");
	return ret;
}

static int dump_one_zombie(const struct pstree_item *item, const struct proc_pid_stat *pps)
{
	CoreEntry *core;
	int ret = -1;
	struct cr_img *img;

	core = core_entry_alloc(0, 1);
	if (!core)
		return -1;

	__strlcpy((char *)core->tc->comm, pps->comm, TASK_COMM_LEN);
	core->tc->task_state = TASK_DEAD;
	core->tc->exit_code = pps->exit_code;

	img = open_image(CR_FD_CORE, O_DUMP, vpid(item));
	if (!img)
		goto err;

	ret = pb_write_one(img, core, PB_CORE);
	close_image(img);
err:
	core_entry_free(core);
	return ret;
}

#define SI_BATCH 32

static int dump_signal_queue(pid_t tid, SignalQueueEntry **sqe, bool group)
{
	struct ptrace_peeksiginfo_args arg;
	int ret;
	SignalQueueEntry *queue = NULL;

	pr_debug("Dump %s signals of %d\n", group ? "shared" : "private", tid);

	arg.nr = SI_BATCH;
	arg.flags = 0;
	if (group)
		arg.flags |= PTRACE_PEEKSIGINFO_SHARED;
	arg.off = 0;

	queue = xmalloc(sizeof(*queue));
	if (!queue)
		return -1;

	signal_queue_entry__init(queue);

	while (1) {
		int nr, si_pos;
		siginfo_t *si;

		si = xmalloc(SI_BATCH * sizeof(*si));
		if (!si) {
			ret = -1;
			break;
		}

		nr = ret = ptrace(PTRACE_PEEKSIGINFO, tid, &arg, si);
		if (ret == 0) {
			xfree(si);
			break; /* Finished */
		}

		if (ret < 0) {
			if (errno == EIO) {
				pr_warn("ptrace doesn't support PTRACE_PEEKSIGINFO\n");
				ret = 0;
			} else
				pr_perror("ptrace");

			xfree(si);
			break;
		}

		queue->n_signals += nr;
		queue->signals = xrealloc(queue->signals, sizeof(*queue->signals) * queue->n_signals);
		if (!queue->signals) {
			ret = -1;
			xfree(si);
			break;
		}

		for (si_pos = queue->n_signals - nr; si_pos < queue->n_signals; si_pos++) {
			SiginfoEntry *se;

			se = xmalloc(sizeof(*se));
			if (!se) {
				ret = -1;
				break;
			}

			siginfo_entry__init(se);
			se->siginfo.len = sizeof(siginfo_t);
			se->siginfo.data = (void *)si++; /* XXX we don't free cores, but when
							  * we will, this would cause problems
							  */
			queue->signals[si_pos] = se;
		}

		if (ret < 0)
			break;

		arg.off += nr;
	}

	*sqe = queue;
	return ret;
}

static int dump_task_signals(pid_t pid, struct pstree_item *item)
{
	int i, ret;

	/* Dump private signals for each thread */
	for (i = 0; i < item->nr_threads; i++) {
		ret = dump_signal_queue(item->threads[i].real, &item->core[i]->thread_core->signals_p, false);
		if (ret) {
			pr_err("Can't dump private signals for thread %d\n", item->threads[i].real);
			return -1;
		}
	}

	/* Dump shared signals */
	ret = dump_signal_queue(pid, &item->core[0]->tc->signals_s, true);
	if (ret) {
		pr_err("Can't dump shared signals (pid: %d)\n", pid);
		return -1;
	}

	return 0;
}

static int read_rseq_cs(pid_t tid, struct __ptrace_rseq_configuration *rseqc, struct criu_rseq_cs *rseq_cs,
			struct criu_rseq *rseq)
{
	int ret;

	/* rseq is not registered */
	if (!rseqc->rseq_abi_pointer)
		return 0;

	/*
	 * We need to cover the case when victim process was inside rseq critical section
	 * at the moment when CRIU comes and seized it. We need to determine the borders
	 * of rseq critical section at first. To achieve that we need to access thread
	 * memory and read pointer to struct rseq_cs.
	 *
	 * We have two ways to access thread memory: from the parasite and using ptrace().
	 * But it this case we can't use parasite, because if victim process returns to the
	 * execution, on the kernel side __rseq_handle_notify_resume hook will be called,
	 * then rseq_ip_fixup() -> clear_rseq_cs() and user space memory with struct rseq
	 * will be cleared. So, let's use ptrace(PTRACE_PEEKDATA).
	 */
	ret = ptrace_peek_area(tid, rseq, decode_pointer(rseqc->rseq_abi_pointer), sizeof(struct criu_rseq));
	if (ret) {
		pr_err("ptrace_peek_area(%d, %lx, %lx, %lx): fail to read rseq struct\n", tid, (unsigned long)rseq,
		       (unsigned long)(rseqc->rseq_abi_pointer), (unsigned long)sizeof(uint64_t));
		return -1;
	}

	if (!rseq->rseq_cs)
		return 0;

	ret = ptrace_peek_area(tid, rseq_cs, decode_pointer(rseq->rseq_cs), sizeof(struct criu_rseq_cs));
	if (ret) {
		pr_err("ptrace_peek_area(%d, %lx, %lx, %lx): fail to read rseq_cs struct\n", tid,
		       (unsigned long)rseq_cs, (unsigned long)rseq->rseq_cs,
		       (unsigned long)sizeof(struct criu_rseq_cs));
		return -1;
	}

	return 0;
}

static int dump_thread_rseq(struct pstree_item *item, int i)
{
	struct __ptrace_rseq_configuration rseqc;
	RseqEntry *rseqe = NULL;
	int ret;
	CoreEntry *core = item->core[i];
	RseqEntry **rseqep = &core->thread_core->rseq_entry;
	struct criu_rseq rseq = {};
	struct criu_rseq_cs *rseq_cs = &dmpi(item)->thread_rseq_cs[i];
	pid_t tid = item->threads[i].real;

	/*
	 * If we are here it means that rseq() syscall is supported,
	 * but ptrace(PTRACE_GET_RSEQ_CONFIGURATION) isn't supported,
	 * we can just fail dump here. But this is bad idea, IMHO.
	 *
	 * So, we will try to detect if victim process was used rseq().
	 * See check_rseq() and check_thread_rseq() functions.
	 */
	if (!kdat.has_ptrace_get_rseq_conf)
		return 0;

	ret = ptrace(PTRACE_GET_RSEQ_CONFIGURATION, tid, sizeof(rseqc), &rseqc);
	if (ret != sizeof(rseqc)) {
		pr_perror("ptrace(PTRACE_GET_RSEQ_CONFIGURATION, %d) = %d", tid, ret);
		return -1;
	}

	if (rseqc.flags != 0) {
		pr_err("something wrong with ptrace(PTRACE_GET_RSEQ_CONFIGURATION, %d) flags = 0x%x\n", tid,
		       rseqc.flags);
		return -1;
	}

	pr_info("Dump rseq of %d: ptr = 0x%lx sign = 0x%x\n", tid, (unsigned long)rseqc.rseq_abi_pointer,
		rseqc.signature);

	rseqe = xmalloc(sizeof(*rseqe));
	if (!rseqe)
		return -1;

	rseq_entry__init(rseqe);

	rseqe->rseq_abi_pointer = rseqc.rseq_abi_pointer;
	rseqe->rseq_abi_size = rseqc.rseq_abi_size;
	rseqe->signature = rseqc.signature;

	if (read_rseq_cs(tid, &rseqc, rseq_cs, &rseq))
		goto err;

	/* we won't save rseq_cs to the image (only pointer),
	 * so let's combine flags from both struct rseq and struct rseq_cs
	 * (kernel does the same when interpreting RSEQ_CS_FLAG_*)
	 */
	rseq_cs->flags |= rseq.flags;

	if (rseq_cs->flags & RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL) {
		rseqe->has_rseq_cs_pointer = true;
		rseqe->rseq_cs_pointer = rseq.rseq_cs;
	}

	/* save rseq entry to the image */
	*rseqep = rseqe;

	return 0;

err:
	xfree(rseqe);
	return -1;
}

static int dump_task_rseq(pid_t pid, struct pstree_item *item)
{
	int i;
	struct criu_rseq_cs *thread_rseq_cs;

	/* if rseq() syscall isn't supported then nothing to dump */
	if (!kdat.has_rseq)
		return 0;

	thread_rseq_cs = xzalloc(sizeof(*thread_rseq_cs) * item->nr_threads);
	if (!thread_rseq_cs)
		return -1;

	dmpi(item)->thread_rseq_cs = thread_rseq_cs;

	for (i = 0; i < item->nr_threads; i++) {
		if (dump_thread_rseq(item, i))
			goto free_rseq;
	}

	return 0;

free_rseq:
	xfree(thread_rseq_cs);
	dmpi(item)->thread_rseq_cs = NULL;
	return -1;
}

static struct proc_pid_stat pps_buf;

static int dump_task_threads(struct parasite_ctl *parasite_ctl, const struct pstree_item *item)
{
	int i, ret = 0;

	for (i = 0; i < item->nr_threads; i++) {
		/* Leader is already dumped */
		if (item->pid->real == item->threads[i].real) {
			item->threads[i].ns[0].virt = vpid(item);
			continue;
		}
		ret = dump_task_thread(parasite_ctl, item, i);
		if (ret)
			break;
	}

	xfree(dmpi(item)->thread_rseq_cs);
	dmpi(item)->thread_rseq_cs = NULL;
	return ret;
}

/*
 * What this routine does is just reads pid-s of dead
 * tasks in item's children list from item's ns proc.
 *
 * It does *not* find which real pid corresponds to
 * which virtual one, but it's not required -- all we
 * need to dump for zombie can be found in the same
 * ns proc.
 */

static int fill_zombies_pids(struct pstree_item *item)
{
	struct pstree_item *child;
	int i, nr;
	pid_t *ch;

	/*
	 * Pids read here are virtual -- caller has set up
	 * the proc of target pid namespace.
	 */
	if (parse_children(vpid(item), &ch, &nr) < 0)
		return -1;

	/*
	 * Step 1 -- filter our ch's pid of alive tasks
	 */
	list_for_each_entry(child, &item->children, sibling) {
		if (vpid(child) < 0)
			continue;
		for (i = 0; i < nr; i++) {
			if (ch[i] == vpid(child)) {
				ch[i] = -1;
				break;
			}
		}
	}

	/*
	 * Step 2 -- assign remaining pids from ch on
	 * children's items in arbitrary order. The caller
	 * will then re-read everything needed to dump
	 * zombies using newly obtained virtual pids.
	 */
	i = 0;
	list_for_each_entry(child, &item->children, sibling) {
		if (vpid(child) > 0)
			continue;
		for (; i < nr; i++) {
			if (ch[i] < 0)
				continue;
			child->pid->ns[0].virt = ch[i];
			ch[i] = -1;
			break;
		}
		BUG_ON(i == nr);
	}

	xfree(ch);

	return 0;
}

static int dump_zombies(void)
{
	struct pstree_item *item;
	int ret = -1;
	int pidns = root_ns_mask & CLONE_NEWPID;

	if (pidns) {
		int fd;

		fd = get_service_fd(CR_PROC_FD_OFF);
		if (fd < 0)
			return -1;

		if (set_proc_fd(fd))
			return -1;
	}

	/*
	 * We dump zombies separately because for pid-ns case
	 * we'd have to resolve their pids w/o parasite via
	 * target ns' proc.
	 */

	for_each_pstree_item(item) {
		if (item->pid->state != TASK_DEAD)
			continue;

		if (vpid(item) < 0) {
			if (!pidns)
				item->pid->ns[0].virt = item->pid->real;
			else if (root_item == item) {
				pr_err("A root task is dead\n");
				goto err;
			} else if (fill_zombies_pids(item->parent))
				goto err;
		}

		pr_info("Obtaining zombie stat ... \n");
		if (parse_pid_stat(vpid(item), &pps_buf) < 0)
			goto err;

		item->sid = pps_buf.sid;
		item->pgid = pps_buf.pgid;

		BUG_ON(!list_empty(&item->children));

		if (!item->sid) {
			pr_err("A session leader of zombie process %d(%d) is outside of its pid namespace\n",
			       item->pid->real, vpid(item));
			goto err;
		}

		if (dump_one_zombie(item, &pps_buf) < 0)
			goto err;
	}

	ret = 0;
err:
	if (pidns)
		close_proc();

	return ret;
}

static int dump_task_cgroup(struct parasite_ctl *parasite_ctl, const struct pstree_item *item)
{
	struct parasite_dump_cgroup_args cgroup_args, *info;
	int i;

	BUILD_BUG_ON(sizeof(cgroup_args) < PARASITE_ARG_SIZE_MIN);
	for (i = 0; i < item->nr_threads; i++) {
		CoreEntry *core = item->core[i];

		/* Leader is already dumped */
		if (item->pid->real == item->threads[i].real)
			continue;

		/* For now, we only need to dump the root task's cgroup ns, because we
		 * know all the tasks are in the same cgroup namespace because we don't
		 * allow nesting.
		 */
		info = NULL;
		if (item->ids->has_cgroup_ns_id && !item->parent) {
			info = &cgroup_args;
			sprintf(cgroup_args.thread_cgrp, "self/task/%d/cgroup", item->threads[i].ns[0].virt);
			if (parasite_dump_cgroup(parasite_ctl, &cgroup_args))
				return -1;
		}

		core->thread_core->has_cg_set = true;
		if (dump_thread_cgroup(item, &core->thread_core->cg_set, info, i))
			return -1;
	}

	return 0;
}

static int pre_dump_one_task(struct pstree_item *item, InventoryEntry *parent_ie)
{
	pid_t pid = item->pid->real;
	struct vm_area_list vmas;
	struct parasite_ctl *parasite_ctl;
	int ret = -1;
	struct parasite_dump_misc misc;
	struct mem_dump_ctl mdc;

	vm_area_list_init(&vmas);

	pr_info("========================================\n");
	pr_info("Pre-dumping task (pid: %d comm: %s)\n", pid, __task_comm_info(pid));
	pr_info("========================================\n");

	/*
	 * Add pidfd of task to pidfd_store if it is initialized.
	 * This pidfd will be used in the next pre-dump/dump iteration
	 * in detect_pid_reuse().
	 */
	ret = pidfd_store_add(pid);
	if (ret)
		goto err;

	if (item->pid->state == TASK_STOPPED) {
		pr_warn("Stopped tasks are not supported\n");
		return 0;
	}

	if (item->pid->state == TASK_DEAD)
		return 0;

	ret = collect_mappings(pid, &vmas, NULL);
	if (ret) {
		pr_err("Collect mappings (pid: %d) failed with %d\n", pid, ret);
		goto err;
	}

	ret = -1;
	parasite_ctl = parasite_infect_seized(pid, item, &vmas);
	if (!parasite_ctl) {
		pr_err("Can't infect (pid: %d) with parasite\n", pid);
		goto err_free;
	}

	ret = parasite_fixup_vdso(parasite_ctl, pid, &vmas);
	if (ret) {
		pr_err("Can't fixup vdso VMAs (pid: %d)\n", pid);
		goto err_cure;
	}

	ret = parasite_dump_misc_seized(parasite_ctl, &misc);
	if (ret) {
		pr_err("Can't dump misc (pid: %d)\n", pid);
		goto err_cure;
	}

	ret = predump_task_files(pid);
	if (ret) {
		pr_err("Pre-dumping files failed (pid: %d)\n", pid);
		goto err_cure;
	}

	item->pid->ns[0].virt = misc.pid;

	mdc.pre_dump = true;
	mdc.lazy = false;
	mdc.stat = NULL;
	mdc.parent_ie = parent_ie;

	ret = parasite_dump_pages_seized(item, &vmas, &mdc, parasite_ctl);
	if (ret)
		goto err_cure;

	if (compel_cure_remote(parasite_ctl))
		pr_err("Can't cure (pid: %d) from parasite\n", pid);
err_free:
	free_mappings(&vmas);
err:
	return ret;

err_cure:
	if (compel_cure(parasite_ctl))
		pr_err("Can't cure (pid: %d) from parasite\n", pid);
	goto err_free;
}

static int dump_one_task(struct pstree_item *item, InventoryEntry *parent_ie)
{
	pid_t pid = item->pid->real;
	struct vm_area_list vmas;
	struct parasite_ctl *parasite_ctl;
	int ret, exit_code = -1;
	struct parasite_dump_misc misc;
	struct cr_imgset *cr_imgset = NULL;
	struct parasite_drain_fd *dfds = NULL;
	struct proc_posix_timers_stat proc_args;
	struct mem_dump_ctl mdc;

	vm_area_list_init(&vmas);

	pr_info("========================================\n");
	pr_info("Dumping task (pid: %d comm: %s)\n", pid, __task_comm_info(pid));
	pr_info("========================================\n");

	if (item->pid->state == TASK_DEAD)
		/*
		 * zombies are dumped separately in dump_zombies()
		 */
		return 0;

	pr_info("Obtaining task stat ... \n");
	ret = parse_pid_stat(pid, &pps_buf);
	if (ret < 0)
		goto err;

	ret = collect_mappings(pid, &vmas, dump_filemap);
	if (ret) {
		pr_err("Collect mappings (pid: %d) failed with %d\n", pid, ret);
		goto err;
	}

	if (!shared_fdtable(item)) {
		dfds = xmalloc(sizeof(*dfds));
		if (!dfds)
			goto err;

		ret = collect_fds(pid, &dfds);
		if (ret) {
			pr_err("Collect fds (pid: %d) failed with %d\n", pid, ret);
			goto err;
		}

		parasite_ensure_args_size(drain_fds_size(dfds));
	}

	ret = parse_posix_timers(pid, &proc_args);
	if (ret < 0) {
		pr_err("Can't read posix timers file (pid: %d)\n", pid);
		goto err;
	}

	parasite_ensure_args_size(posix_timers_dump_size(proc_args.timer_n));

	ret = dump_task_signals(pid, item);
	if (ret) {
		pr_err("Dump %d signals failed %d\n", pid, ret);
		goto err;
	}

	ret = dump_task_rseq(pid, item);
	if (ret) {
		pr_err("Dump %d rseq failed %d\n", pid, ret);
		goto err;
	}

	parasite_ctl = parasite_infect_seized(pid, item, &vmas);
	if (!parasite_ctl) {
		pr_err("Can't infect (pid: %d) with parasite\n", pid);
		goto err;
	}

	ret = fixup_thread_rseq(item, 0);
	if (ret) {
		pr_err("Fixup rseq for %d failed %d\n", pid, ret);
		goto err;
	}

	if (fault_injected(FI_DUMP_EARLY)) {
		pr_info("fault: CRIU sudden detach\n");
		kill(getpid(), SIGKILL);
	}

	if (root_ns_mask & CLONE_NEWPID && root_item == item) {
		int pfd;

		pfd = parasite_get_proc_fd_seized(parasite_ctl);
		if (pfd < 0) {
			pr_err("Can't get proc fd (pid: %d)\n", pid);
			goto err_cure;
		}

		if (install_service_fd(CR_PROC_FD_OFF, pfd) < 0)
			goto err_cure;
	}

	ret = parasite_fixup_vdso(parasite_ctl, pid, &vmas);
	if (ret) {
		pr_err("Can't fixup vdso VMAs (pid: %d)\n", pid);
		goto err_cure;
	}

	ret = parasite_collect_aios(parasite_ctl, &vmas); /* FIXME -- merge with above */
	if (ret) {
		pr_err("Failed to check aio rings (pid: %d)\n", pid);
		goto err_cure;
	}

	ret = parasite_dump_misc_seized(parasite_ctl, &misc);
	if (ret) {
		pr_err("Can't dump misc (pid: %d)\n", pid);
		goto err_cure;
	}

	item->pid->ns[0].virt = misc.pid;
	pstree_insert_pid(item->pid);
	item->sid = misc.sid;
	item->pgid = misc.pgid;

	pr_info("sid=%d pgid=%d pid=%d\n", item->sid, item->pgid, vpid(item));

	if (item->sid == 0) {
		pr_err("A session leader of %d(%d) is outside of its pid namespace\n", item->pid->real, vpid(item));
		goto err_cure;
	}

	cr_imgset = cr_task_imgset_open(vpid(item), O_DUMP);
	if (!cr_imgset)
		goto err_cure;

	ret = dump_task_ids(item, cr_imgset);
	if (ret) {
		pr_err("Dump ids (pid: %d) failed with %d\n", pid, ret);
		goto err_cure;
	}

	if (dfds) {
		ret = dump_task_files_seized(parasite_ctl, item, dfds);
		if (ret) {
			pr_err("Dump files (pid: %d) failed with %d\n", pid, ret);
			goto err_cure;
		}
		ret = flush_eventpoll_dinfo_queue();
		if (ret) {
			pr_err("Dump eventpoll (pid: %d) failed with %d\n", pid, ret);
			goto err_cure;
		}
	}

	mdc.pre_dump = false;
	mdc.lazy = opts.lazy_pages;
	mdc.stat = &pps_buf;
	mdc.parent_ie = parent_ie;

	ret = parasite_dump_pages_seized(item, &vmas, &mdc, parasite_ctl);
	if (ret)
		goto err_cure;

	ret = parasite_dump_sigacts_seized(parasite_ctl, item);
	if (ret) {
		pr_err("Can't dump sigactions (pid: %d) with parasite\n", pid);
		goto err_cure;
	}

	ret = parasite_dump_itimers_seized(parasite_ctl, item);
	if (ret) {
		pr_err("Can't dump itimers (pid: %d)\n", pid);
		goto err_cure;
	}

	ret = parasite_dump_posix_timers_seized(&proc_args, parasite_ctl, item);
	if (ret) {
		pr_err("Can't dump posix timers (pid: %d)\n", pid);
		goto err_cure;
	}

	ret = dump_task_core_all(parasite_ctl, item, &pps_buf, cr_imgset, &misc);
	if (ret) {
		pr_err("Dump core (pid: %d) failed with %d\n", pid, ret);
		goto err_cure;
	}

	ret = dump_task_cgroup(parasite_ctl, item);
	if (ret) {
		pr_err("Dump cgroup of threads in process (pid: %d) failed with %d\n", pid, ret);
		goto err_cure;
	}

	ret = compel_stop_daemon(parasite_ctl);
	if (ret) {
		pr_err("Can't stop daemon in parasite (pid: %d)\n", pid);
		goto err_cure;
	}

	ret = dump_task_threads(parasite_ctl, item);
	if (ret) {
		pr_err("Can't dump threads\n");
		goto err_cure;
	}

	/*
	 * On failure local map will be cured in cr_dump_finish()
	 * for lazy pages.
	 */
	if (opts.lazy_pages)
		ret = compel_cure_remote(parasite_ctl);
	else
		ret = compel_cure(parasite_ctl);
	if (ret) {
		pr_err("Can't cure (pid: %d) from parasite\n", pid);
		goto err;
	}

	ret = dump_task_mm(pid, &pps_buf, &misc, &vmas, cr_imgset);
	if (ret) {
		pr_err("Dump mappings (pid: %d) failed with %d\n", pid, ret);
		goto err;
	}

	ret = dump_task_fs(pid, &misc, cr_imgset);
	if (ret) {
		pr_err("Dump fs (pid: %d) failed with %d\n", pid, ret);
		goto err;
	}

	exit_code = 0;
err:
	close_cr_imgset(&cr_imgset);
	close_pid_proc();
	free_mappings(&vmas);
	xfree(dfds);
	return exit_code;

err_cure:
	ret = compel_cure(parasite_ctl);
	if (ret)
		pr_err("Can't cure (pid: %d) from parasite\n", pid);
	goto err;
}

static int alarm_attempts = 0;

bool alarm_timeouted(void)
{
	return alarm_attempts > 0;
}

static void alarm_handler(int signo)
{
	pr_err("Timeout reached. Try to interrupt: %d\n", alarm_attempts);
	if (alarm_attempts++ < 5) {
		alarm(1);
		/* A current syscall will be exited with EINTR */
		return;
	}
	pr_err("FATAL: Unable to interrupt the current operation\n");
	BUG();
}

static int setup_alarm_handler(void)
{
	struct sigaction sa = {
		.sa_handler = alarm_handler, .sa_flags = 0, /* Don't restart syscalls */
	};

	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGALRM);
	if (sigaction(SIGALRM, &sa, NULL)) {
		pr_perror("Unable to setup SIGALRM handler");
		return -1;
	}

	return 0;
}

static int cr_pre_dump_finish(int status)
{
	InventoryEntry he = INVENTORY_ENTRY__INIT;
	struct pstree_item *item;
	int ret;

	/*
	 * Restore registers for tasks only. The threads have not been
	 * infected. Therefore, the thread register sets have not been changed.
	 */
	ret = arch_set_thread_regs(root_item, false);
	if (ret)
		goto err;

	ret = inventory_save_uptime(&he);
	if (ret)
		goto err;

	he.has_pre_dump_mode = true;
	he.pre_dump_mode = opts.pre_dump_mode;

	pstree_switch_state(root_item, TASK_ALIVE);

	timing_stop(TIME_FROZEN);

	if (status < 0) {
		ret = status;
		goto err;
	}

	pr_info("Pre-dumping tasks' memory\n");
	for_each_pstree_item(item) {
		struct parasite_ctl *ctl = dmpi(item)->parasite_ctl;
		struct page_pipe *mem_pp;
		struct page_xfer xfer;

		if (!ctl)
			continue;

		pr_info("\tPre-dumping %d\n", vpid(item));
		timing_start(TIME_MEMWRITE);
		ret = open_page_xfer(&xfer, CR_FD_PAGEMAP, vpid(item));
		if (ret < 0)
			goto err;

		mem_pp = dmpi(item)->mem_pp;

		if (opts.pre_dump_mode == PRE_DUMP_READ) {
			timing_stop(TIME_MEMWRITE);
			ret = page_xfer_predump_pages(item->pid->real, &xfer, mem_pp);
		} else {
			ret = page_xfer_dump_pages(&xfer, mem_pp);
		}

		xfer.close(&xfer);

		if (ret)
			goto err;

		timing_stop(TIME_MEMWRITE);

		destroy_page_pipe(mem_pp);
		if (compel_cure_local(ctl))
			pr_err("Can't cure local: something happened with mapping?\n");
	}

	free_pstree(root_item);
	seccomp_free_entries();

	if (irmap_predump_run()) {
		ret = -1;
		goto err;
	}

err:
	if (unsuspend_lsm())
		ret = -1;

	if (disconnect_from_page_server())
		ret = -1;

	if (bfd_flush_images())
		ret = -1;

	if (write_img_inventory(&he))
		ret = -1;

	if (ret)
		pr_err("Pre-dumping FAILED.\n");
	else {
		write_stats(DUMP_STATS);
		pr_info("Pre-dumping finished successfully\n");
	}
	return ret;
}

int cr_pre_dump_tasks(pid_t pid)
{
	InventoryEntry *parent_ie = NULL;
	struct pstree_item *item;
	int ret = -1;

	/*
	 * We might need a lot of pipes to fetch huge number of pages to dump.
	 */
	rlimit_unlimit_nofile();

	root_item = alloc_pstree_item();
	if (!root_item)
		goto err;
	root_item->pid->real = pid;

	if (!opts.track_mem) {
		pr_info("Enforcing memory tracking for pre-dump.\n");
		opts.track_mem = true;
	}

	if (opts.final_state == TASK_DEAD) {
		pr_info("Enforcing tasks run after pre-dump.\n");
		opts.final_state = TASK_ALIVE;
	}

	if (init_stats(DUMP_STATS))
		goto err;

	if (cr_plugin_init(CR_PLUGIN_STAGE__PRE_DUMP))
		goto err;

	if (lsm_check_opts())
		goto err;

	if (irmap_load_cache())
		goto err;

	if (cpu_init())
		goto err;

	if (vdso_init_dump())
		goto err;

	if (connect_to_page_server_to_send() < 0)
		goto err;

	if (setup_alarm_handler())
		goto err;

	if (collect_pstree())
		goto err;

	if (collect_pstree_ids_predump())
		goto err;

	if (collect_namespaces(false) < 0)
		goto err;

	if (collect_and_suspend_lsm() < 0)
		goto err;

	/* Errors handled later in detect_pid_reuse */
	parent_ie = get_parent_inventory();

	for_each_pstree_item(item)
		if (pre_dump_one_task(item, parent_ie))
			goto err;

	if (parent_ie) {
		inventory_entry__free_unpacked(parent_ie, NULL);
		parent_ie = NULL;
	}

	ret = cr_dump_shmem();
	if (ret)
		goto err;

	if (irmap_predump_prep())
		goto err;

	ret = 0;
err:
	if (parent_ie)
		inventory_entry__free_unpacked(parent_ie, NULL);

	return cr_pre_dump_finish(ret);
}

static int cr_lazy_mem_dump(void)
{
	struct pstree_item *item;
	int ret = 0;

	pr_info("Starting lazy pages server\n");
	ret = cr_page_server(false, true, -1);

	for_each_pstree_item(item) {
		if (item->pid->state != TASK_DEAD) {
			destroy_page_pipe(dmpi(item)->mem_pp);
			if (compel_cure_local(dmpi(item)->parasite_ctl))
				pr_err("Can't cure local: something happened with mapping?\n");
		}
	}

	if (ret)
		pr_err("Lazy pages transfer FAILED.\n");
	else
		pr_info("Lazy pages transfer finished successfully\n");

	return ret;
}

static int cr_dump_finish(int ret)
{
	int post_dump_ret = 0;

	if (disconnect_from_page_server())
		ret = -1;

	close_cr_imgset(&glob_imgset);

	if (bfd_flush_images())
		ret = -1;

	cr_plugin_fini(CR_PLUGIN_STAGE__DUMP, ret);
	cgp_fini();

	if (!ret) {
		/*
		 * It might be a migration case, where we're asked
		 * to dump everything, then some script transfer
		 * image on a new node and we're supposed to kill
		 * dumpee because it continue running somewhere
		 * else.
		 *
		 * Thus ask user via script if we're to break
		 * checkpoint.
		 */
		post_dump_ret = run_scripts(ACT_POST_DUMP);
		if (post_dump_ret) {
			post_dump_ret = WEXITSTATUS(post_dump_ret);
			pr_info("Post dump script passed with %d\n", post_dump_ret);
		}
	}

	/*
	 * Dump is complete at this stage. To choose what
	 * to do next we need to consider the following
	 * scenarios
	 *
	 *  - error happened during checkpoint: just clean up
	 *    everything and continue execution of the dumpee;
	 *
	 *  - dump succeeded but post-dump script returned
	 *    some ret code: same as in previous scenario --
	 *    just clean up everything and continue execution,
	 *    we will return script ret code back to criu caller
	 *    and it's up to a caller what to do with running instance
	 *    of the dumpee -- either kill it, or continue running;
	 *
	 *  - dump succeeded but -R option passed, pointing that
	 *    we're asked to continue execution of the dumpee. It's
	 *    assumed that a user will use post-dump script to keep
	 *    consistency of the FS and other resources, we simply
	 *    start rollback procedure and cleanup everything.
	 */
	if (ret || post_dump_ret || opts.final_state == TASK_ALIVE) {
		unsuspend_lsm();
		network_unlock();
		delete_link_remaps();
		clean_cr_time_mounts();
	}

	if (!ret && opts.lazy_pages)
		ret = cr_lazy_mem_dump();

	if (arch_set_thread_regs(root_item, true) < 0)
		return -1;
	pstree_switch_state(root_item, (ret || post_dump_ret) ? TASK_ALIVE : opts.final_state);
	timing_stop(TIME_FROZEN);
	free_pstree(root_item);
	seccomp_free_entries();
	free_file_locks();
	free_link_remaps();
	free_aufs_branches();
	free_userns_maps();

	close_service_fd(CR_PROC_FD_OFF);
	close_image_dir();

	if (ret || post_dump_ret) {
		pr_err("Dumping FAILED.\n");
	} else {
		write_stats(DUMP_STATS);
		pr_info("Dumping finished successfully\n");
	}
	return post_dump_ret ?: (ret != 0);
}

int cr_dump_tasks(pid_t pid)
{
	InventoryEntry he = INVENTORY_ENTRY__INIT;
	InventoryEntry *parent_ie = NULL;
	struct pstree_item *item;
	int pre_dump_ret = 0;
	int ret = -1;

	pr_info("========================================\n");
	pr_info("Dumping processes (pid: %d comm: %s)\n", pid, __task_comm_info(pid));
	pr_info("========================================\n");

	/*
	 *  We will fetch all file descriptors for each task, their number can
	 *  be bigger than a default file limit, so we need to raise it to the
	 *  maximum.
	 */
	rlimit_unlimit_nofile();

	root_item = alloc_pstree_item();
	if (!root_item)
		goto err;
	root_item->pid->real = pid;

	pre_dump_ret = run_scripts(ACT_PRE_DUMP);
	if (pre_dump_ret != 0) {
		pr_err("Pre dump script failed with %d!\n", pre_dump_ret);
		goto err;
	}
	if (init_stats(DUMP_STATS))
		goto err;

	if (cr_plugin_init(CR_PLUGIN_STAGE__DUMP))
		goto err;

	if (lsm_check_opts())
		goto err;

	if (irmap_load_cache())
		goto err;

	if (cpu_init())
		goto err;

	if (vdso_init_dump())
		goto err;

	if (cgp_init(opts.cgroup_props, opts.cgroup_props ? strlen(opts.cgroup_props) : 0, opts.cgroup_props_file))
		goto err;

	if (parse_cg_info())
		goto err;

	if (prepare_inventory(&he))
		goto err;

	if (opts.cpu_cap & CPU_CAP_IMAGE) {
		if (cpu_dump_cpuinfo())
			goto err;
	}

	if (connect_to_page_server_to_send() < 0)
		goto err;

	if (setup_alarm_handler())
		goto err;

	/*
	 * The collect_pstree will also stop (PTRACE_SEIZE) the tasks
	 * thus ensuring that they don't modify anything we collect
	 * afterwards.
	 */

	if (collect_pstree())
		goto err;

	if (collect_pstree_ids())
		goto err;

	if (network_lock())
		goto err;

	if (rpc_query_external_files())
		goto err;

	if (collect_file_locks())
		goto err;

	if (collect_namespaces(true) < 0)
		goto err;

	glob_imgset = cr_glob_imgset_open(O_DUMP);
	if (!glob_imgset)
		goto err;

	if (seccomp_collect_dump_filters() < 0)
		goto err;

	/* Errors handled later in detect_pid_reuse */
	parent_ie = get_parent_inventory();

	if (collect_and_suspend_lsm() < 0)
		goto err;

	for_each_pstree_item(item) {
		if (dump_one_task(item, parent_ie))
			goto err;
	}

	if (parent_ie) {
		inventory_entry__free_unpacked(parent_ie, NULL);
		parent_ie = NULL;
	}

	/*
	 * It may happen that a process has completed but its files in
	 * /proc/PID/ are still open by another process. If the PID has been
	 * given to some newer thread since then, we may be unable to dump
	 * all this.
	 */
	if (dead_pid_conflict())
		goto err;

	/* MNT namespaces are dumped after files to save remapped links */
	if (dump_mnt_namespaces() < 0)
		goto err;

	if (dump_file_locks())
		goto err;

	if (dump_verify_tty_sids())
		goto err;

	if (dump_zombies())
		goto err;

	if (dump_pstree(root_item))
		goto err;

	/*
	 * TODO: cr_dump_shmem has to be called before dump_namespaces(),
	 * because page_ids is a global variable and it is used to dump
	 * ipc shared memory, but an ipc namespace is dumped in a child
	 * process.
	 */
	ret = cr_dump_shmem();
	if (ret)
		goto err;

	if (root_ns_mask) {
		ret = dump_namespaces(root_item, root_ns_mask);
		if (ret)
			goto err;
	}

	if ((root_ns_mask & CLONE_NEWTIME) == 0) {
		ret = dump_time_ns(0);
		if (ret)
			goto err;
	}

	if (dump_aa_namespaces() < 0)
		goto err;

	ret = dump_cgroups();
	if (ret)
		goto err;

	ret = fix_external_unix_sockets();
	if (ret)
		goto err;

	ret = tty_post_actions();
	if (ret)
		goto err;

	ret = inventory_save_uptime(&he);
	if (ret)
		goto err;

	he.has_pre_dump_mode = false;

	ret = write_img_inventory(&he);
	if (ret)
		goto err;
err:
	if (parent_ie)
		inventory_entry__free_unpacked(parent_ie, NULL);

	return cr_dump_finish(ret);
}
