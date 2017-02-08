#include <sys/time.h>
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
#include <sys/resource.h>
#include <sys/wait.h>

#include <sys/sendfile.h>

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

static char loc_buf[PAGE_SIZE];

void free_mappings(struct vm_area_list *vma_area_list)
{
	struct vma_area *vma_area, *p;

	list_for_each_entry_safe(vma_area, p, &vma_area_list->h, list) {
		if (!vma_area->file_borrowed)
			free(vma_area->vmst);
		free(vma_area);
	}

	INIT_LIST_HEAD(&vma_area_list->h);
	vma_area_list->nr = 0;
}

int collect_mappings(pid_t pid, struct vm_area_list *vma_area_list,
						dump_filemap_t dump_file)
{
	int ret = -1;

	pr_info("\n");
	pr_info("Collecting mappings (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	ret = parse_smaps(pid, vma_area_list, dump_file);
	if (ret < 0)
		goto err;

	pr_info("Collected, longest area occupies %lu pages\n",
			vma_area_list->priv_longest);
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
			if (!t)
				return -1;
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

	pr_info("Dumping task cwd id %#x root id %#x\n",
			fe.cwd_id, fe.root_id);

	return pb_write_one(img_from_set(imgset, CR_FD_FS), &fe, PB_FS);
}

static inline rlim_t encode_rlim(rlim_t val)
{
	return val == RLIM_INFINITY ? -1 : val;
}

static int dump_task_rlimits(int pid, TaskRlimitsEntry *rls)
{
	int res;

	for (res = 0; res <rls->n_rlimits ; res++) {
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

	if (kdat.has_loginuid) {
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

		strlcpy(aufs_link.name, vma_area->aufs_rpath,
				sizeof(aufs_link.name));
		aufs_link.len = strlen(aufs_link.name);
		p.link = &aufs_link;
	}

	/* Flags will be set during restore in open_filmap() */

	ret = dump_one_reg_file_cond(fd, &id, &p);

	vma->shmid = id;
	return ret;
}

static int check_sysvipc_map_dump(pid_t pid, VmaEntry *vma)
{
	if (root_ns_mask & CLONE_NEWIPC)
		return 0;

	pr_err("Task %d with SysVIPC shmem map @%"PRIx64" doesn't live in IPC ns\n",
			pid, vma->start);
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

static int dump_task_mm(pid_t pid, const struct proc_pid_stat *stat,
		const struct parasite_dump_misc *misc,
		const struct vm_area_list *vma_area_list,
		const struct cr_imgset *imgset)
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

	info->futex_rla		= encode_pointer(head);
	info->futex_rla_len	= (u32)len;

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
	elem.idx = 0; /* really 0 for all */
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

	ret = collect_lsm_profile(pid, tc->creds);
	if (!ret)
		ret = get_task_futex_robust_list(pid, tc);
	if (!ret)
		ret = dump_sched_info(pid, tc);
	if (!ret) {
		core_put_tls(core, ti->tls);
		CORE_THREAD_ARCH_INFO(core)->clear_tid_addr =
			encode_pointer(ti->tid_addr);
		BUG_ON(!tc->sas);
		copy_sas(tc->sas, &ti->sas);
		if (ti->pdeath_sig) {
			tc->has_pdeath_sig = true;
			tc->pdeath_sig = ti->pdeath_sig;
		}
	}

	return ret;
}

static int dump_task_core_all(struct parasite_ctl *ctl,
			      struct pstree_item *item,
			      const struct proc_pid_stat *stat,
			      const struct cr_imgset *cr_imgset)
{
	struct cr_img *img;
	CoreEntry *core = item->core[0];
	pid_t pid = item->pid->real;
	int ret = -1;
	struct proc_status_creds *creds;
	struct parasite_dump_cgroup_args cgroup_args, *info = NULL;

	BUILD_BUG_ON(sizeof(cgroup_args) < PARASITE_ARG_SIZE_MIN);

	pr_info("\n");
	pr_info("Dumping core (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	ret = get_task_personality(pid, &core->tc->personality);
	if (ret < 0)
		goto err;

	creds = dmpi(item)->pi_creds;
	if (creds->s.seccomp_mode != SECCOMP_MODE_DISABLED) {
		pr_info("got seccomp mode %d for %d\n", creds->s.seccomp_mode, vpid(item));
		core->tc->has_seccomp_mode = true;
		core->tc->seccomp_mode = creds->s.seccomp_mode;

		if (creds->s.seccomp_mode == SECCOMP_MODE_FILTER) {
			core->tc->has_seccomp_filter = true;
			core->tc->seccomp_filter = creds->last_filter;
		}
	}

	strlcpy((char *)core->tc->comm, stat->comm, TASK_COMM_LEN);
	core->tc->flags = stat->flags;
	core->tc->task_state = item->pid->state;
	core->tc->exit_code = 0;

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
		ret = parasite_dump_cgroup(ctl, &cgroup_args);
		if (ret)
			goto err;
	}

	core->tc->has_cg_set = true;
	ret = dump_task_cgroup(item, &core->tc->cg_set, info);
	if (ret)
		goto err;

	img = img_from_set(cr_imgset, CR_FD_CORE);
	ret = pb_write_one(img, core, PB_CORE);
	if (ret < 0)
		goto err;

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
	} crt = { .i.pid = &pid, };

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

static int dump_task_thread(struct parasite_ctl *parasite_ctl,
				const struct pstree_item *item, int id)
{
	struct pid *tid = &item->threads[id];
	CoreEntry *core = item->core[id];
	pid_t pid = tid->real;
	int ret = -1;
	struct cr_img *img;

	pr_info("\n");
	pr_info("Dumping core for thread (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	ret = parasite_dump_thread_seized(parasite_ctl, id, tid, core);
	if (ret) {
		pr_err("Can't dump thread for pid %d\n", pid);
		goto err;
	}
	pstree_insert_pid(tid);

	img = open_image(CR_FD_CORE, O_DUMP, tid->ns[0].virt);
	if (!img)
		goto err;

	ret = pb_write_one(img, core, PB_CORE);

	close_image(img);
err:
	pr_info("----------------------------------------\n");
	return ret;
}

static int dump_one_zombie(const struct pstree_item *item,
			   const struct proc_pid_stat *pps)
{
	CoreEntry *core;
	int ret = -1;
	struct cr_img *img;

	core = core_entry_alloc(0, 1);
	if (!core)
		return -1;

	strlcpy((char *)core->tc->comm, pps->comm, TASK_COMM_LEN);
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

#define SI_BATCH	32

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
		if (ret == 0)
			break; /* Finished */

		if (ret < 0) {
			if (errno == EIO) {
				pr_warn("ptrace doesn't support PTRACE_PEEKSIGINFO\n");
				ret = 0;
			} else
				pr_perror("ptrace");

			break;
		}

		queue->n_signals += nr;
		queue->signals = xrealloc(queue->signals, sizeof(*queue->signals) * queue->n_signals);
		if (!queue->signals) {
			ret = -1;
			break;
		}

		for (si_pos = queue->n_signals - nr;
				si_pos < queue->n_signals; si_pos++) {
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

static struct proc_pid_stat pps_buf;

static int dump_task_threads(struct parasite_ctl *parasite_ctl,
			     const struct pstree_item *item)
{
	int i;

	for (i = 0; i < item->nr_threads; i++) {
		/* Leader is already dumped */
		if (item->pid->real == item->threads[i].real) {
			item->threads[i].ns[0].virt = vpid(item);
			continue;
		}
		if (dump_task_thread(parasite_ctl, item, i))
			return -1;
	}

	return 0;
}

/*
 * What this routine does is just reads pid-s of dead
 * tasks in item's children list from item's ns proc.
 *
 * It does *not* find wihch real pid corresponds to
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

	if (pidns && set_proc_fd(get_service_fd(CR_PROC_FD_OFF)))
		return -1;

	/*
	 * We dump zombies separately becase for pid-ns case
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
		if (dump_one_zombie(item, &pps_buf) < 0)
			goto err;
	}

	ret = 0;
err:
	if (pidns)
		close_proc();

	return ret;
}

static int pre_dump_one_task(struct pstree_item *item)
{
	pid_t pid = item->pid->real;
	struct vm_area_list vmas;
	struct parasite_ctl *parasite_ctl;
	int ret = -1;
	struct parasite_dump_misc misc;
	struct mem_dump_ctl mdc;

	INIT_LIST_HEAD(&vmas.h);
	vmas.nr = 0;

	pr_info("========================================\n");
	pr_info("Pre-dumping task (pid: %d)\n", pid);
	pr_info("========================================\n");

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

static int dump_one_task(struct pstree_item *item)
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

	INIT_LIST_HEAD(&vmas.h);
	vmas.nr = 0;

	pr_info("========================================\n");
	pr_info("Dumping task (pid: %d)\n", pid);
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

	parasite_ctl = parasite_infect_seized(pid, item, &vmas);
	if (!parasite_ctl) {
		pr_err("Can't infect (pid: %d) with parasite\n", pid);
		goto err;
	}

	if (fault_injected(FI_DUMP_EARLY)) {
		pr_info("fault: CRIU sudden detach\n");
		BUG();
	}

	if (root_ns_mask & CLONE_NEWPID && root_item == item) {
		int pfd;

		pfd = parasite_get_proc_fd_seized(parasite_ctl);
		if (pfd < 0) {
			pr_err("Can't get proc fd (pid: %d)\n", pid);
			goto err_cure_imgset;
		}

		if (install_service_fd(CR_PROC_FD_OFF, pfd) < 0)
			goto err_cure_imgset;

		close(pfd);
	}

	ret = parasite_fixup_vdso(parasite_ctl, pid, &vmas);
	if (ret) {
		pr_err("Can't fixup vdso VMAs (pid: %d)\n", pid);
		goto err_cure_imgset;
	}

	ret = parasite_collect_aios(parasite_ctl, &vmas); /* FIXME -- merge with above */
	if (ret) {
		pr_err("Failed to check aio rings (pid: %d)\n", pid);
		goto err_cure_imgset;
	}

	ret = parasite_dump_misc_seized(parasite_ctl, &misc);
	if (ret) {
		pr_err("Can't dump misc (pid: %d)\n", pid);
		goto err_cure_imgset;
	}

	item->pid->ns[0].virt = misc.pid;
	pstree_insert_pid(item->pid);
	item->sid = misc.sid;
	item->pgid = misc.pgid;

	pr_info("sid=%d pgid=%d pid=%d\n",
		item->sid, item->pgid, vpid(item));

	if (item->sid == 0) {
		pr_err("A session leader of %d(%d) is outside of its pid namespace\n",
			item->pid->real, vpid(item));
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
	}

	mdc.pre_dump = false;

	ret = parasite_dump_pages_seized(item, &vmas, &mdc, parasite_ctl);
	if (ret)
		goto err_cure;

	ret = parasite_dump_sigacts_seized(parasite_ctl, cr_imgset);
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

	ret = dump_task_core_all(parasite_ctl, item, &pps_buf, cr_imgset);
	if (ret) {
		pr_err("Dump core (pid: %d) failed with %d\n", pid, ret);
		goto err_cure;
	}

	ret = compel_stop_daemon(parasite_ctl);
	if (ret) {
		pr_err("Can't cure (pid: %d) from parasite\n", pid);
		goto err;
	}

	ret = dump_task_threads(parasite_ctl, item);
	if (ret) {
		pr_err("Can't dump threads\n");
		goto err;
	}

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

	close_cr_imgset(&cr_imgset);
	exit_code = 0;
err:
	close_pid_proc();
	free_mappings(&vmas);
	xfree(dfds);
	return exit_code;

err_cure:
	close_cr_imgset(&cr_imgset);
err_cure_imgset:
	compel_cure(parasite_ctl);
	goto err;
}

static int alarm_attempts = 0;

bool alarm_timeouted() {
	return alarm_attempts > 0;
}

static void alarm_handler(int signo)
{

	pr_err("Timeout reached. Try to interrupt: %d\n", alarm_attempts);
	if (alarm_attempts++ < 5) {
		alarm(1);
		/* A curren syscall will be exited with EINTR */
		return;
	}
	pr_err("FATAL: Unable to interrupt the current operation\n");
	BUG();
}

static int setup_alarm_handler()
{
	struct sigaction sa = {
		.sa_handler	= alarm_handler,
		.sa_flags	= 0, /* Don't restart syscalls */
	};

	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGALRM);
	if (sigaction(SIGALRM, &sa, NULL)) {
		pr_perror("Unable to setup SIGALRM handler");
		return -1;
	}

	return 0;
}

static int cr_pre_dump_finish(int ret)
{
	struct pstree_item *item;

	pstree_switch_state(root_item, TASK_ALIVE);

	timing_stop(TIME_FROZEN);

	if (ret < 0)
		goto err;

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
		ret = page_xfer_dump_pages(&xfer, mem_pp, 0);

		xfer.close(&xfer);

		if (ret)
			goto err;

		timing_stop(TIME_MEMWRITE);

		destroy_page_pipe(mem_pp);
		compel_cure_local(ctl);
	}

	free_pstree(root_item);

	if (irmap_predump_run()) {
		ret = -1;
		goto err;
	}

err:
	if (disconnect_from_page_server())
		ret = -1;

	if (bfd_flush_images())
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
	struct pstree_item *item;
	int ret = -1;

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

	if (kerndat_init())
		goto err;

	if (irmap_load_cache())
		goto err;

	if (cpu_init())
		goto err;

	if (vdso_init())
		goto err;

	if (connect_to_page_server())
		goto err;

	if (setup_alarm_handler())
		goto err;

	if (collect_pstree())
		goto err;

	if (collect_pstree_ids_predump())
		goto err;

	if (collect_namespaces(false) < 0)
		goto err;

	for_each_pstree_item(item)
		if (pre_dump_one_task(item))
			goto err;

	ret = cr_dump_shmem();
	if (ret)
		goto err;

	if (irmap_predump_prep())
		goto err;

	ret = 0;
err:
	return cr_pre_dump_finish(ret);
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
	 *  - dump successed but post-dump script returned
	 *    some ret code: same as in previous scenario --
	 *    just clean up everything and continue execution,
	 *    we will return script ret code back to criu caller
	 *    and it's up to a caller what to do with running instance
	 *    of the dumpee -- either kill it, or continue running;
	 *
	 *  - dump successed but -R option passed, pointing that
	 *    we're asked to continue execution of the dumpee. It's
	 *    assumed that a user will use post-dump script to keep
	 *    consistency of the FS and other resources, we simply
	 *    start rollback procedure and cleanup everyhting.
	 */
	if (ret || post_dump_ret || opts.final_state == TASK_ALIVE) {
		network_unlock();
		delete_link_remaps();
		clean_cr_time_mounts();
	}
	pstree_switch_state(root_item,
			    (ret || post_dump_ret) ?
			    TASK_ALIVE : opts.final_state);
	timing_stop(TIME_FROZEN);
	free_pstree(root_item);
	free_file_locks();
	free_link_remaps();
	free_aufs_branches();
	free_userns_maps();

	close_service_fd(CR_PROC_FD_OFF);

	if (ret) {
		pr_err("Dumping FAILED.\n");
	} else {
		write_stats(DUMP_STATS);
		pr_info("Dumping finished successfully\n");
	}
	return post_dump_ret ? : (ret != 0);
}

int cr_dump_tasks(pid_t pid)
{
	InventoryEntry he = INVENTORY_ENTRY__INIT;
	struct pstree_item *item;
	int pre_dump_ret = 0;
	int ret = -1;

	pr_info("========================================\n");
	pr_info("Dumping processes (pid: %d)\n", pid);
	pr_info("========================================\n");

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

	if (kerndat_init())
		goto err;

	if (irmap_load_cache())
		goto err;

	if (cpu_init())
		goto err;

	if (vdso_init())
		goto err;

	if (cgp_init(opts.cgroup_props,
		     opts.cgroup_props ?
		     strlen(opts.cgroup_props) : 0,
		     opts.cgroup_props_file))
		goto err;

	if (parse_cg_info())
		goto err;

	if (prepare_inventory(&he))
		goto err;

	if (opts.cpu_cap & (CPU_CAP_CPU | CPU_CAP_INS)) {
		if (cpu_dump_cpuinfo())
			goto err;
	}

	if (connect_to_page_server())
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

	if (collect_file_locks())
		goto err;

	if (collect_namespaces(true) < 0)
		goto err;

	glob_imgset = cr_glob_imgset_open(O_DUMP);
	if (!glob_imgset)
		goto err;

	if (collect_seccomp_filters() < 0)
		goto err;

	for_each_pstree_item(item) {
		if (dump_one_task(item))
			goto err;
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

	if (root_ns_mask)
		if (dump_namespaces(root_item, root_ns_mask) < 0)
			goto err;

	ret = dump_cgroups();
	if (ret)
		goto err;

	ret = cr_dump_shmem();
	if (ret)
		goto err;

	ret = fix_external_unix_sockets();
	if (ret)
		goto err;

	ret = tty_post_actions();
	if (ret)
		goto err;

	ret = write_img_inventory(&he);
	if (ret)
		goto err;
err:
	return cr_dump_finish(ret);
}
