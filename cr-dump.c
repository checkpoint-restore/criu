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

#include <sys/sendfile.h>
#include <sys/mman.h>

#include <sched.h>
#include <sys/resource.h>

#include "protobuf.h"
#include "protobuf/fdinfo.pb-c.h"
#include "protobuf/fs.pb-c.h"
#include "protobuf/mm.pb-c.h"
#include "protobuf/creds.pb-c.h"
#include "protobuf/core.pb-c.h"
#include "protobuf/file-lock.pb-c.h"
#include "protobuf/rlimit.pb-c.h"
#include "protobuf/siginfo.pb-c.h"

#include "asm/types.h"
#include "list.h"
#include "file-ids.h"
#include "kcmp-ids.h"
#include "compiler.h"
#include "crtools.h"
#include "syscall.h"
#include "ptrace.h"
#include "util.h"
#include "sockets.h"
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
#include "file-lock.h"
#include "page-xfer.h"
#include "kerndat.h"
#include "stats.h"
#include "mem.h"
#include "page-pipe.h"

#include "asm/dump.h"

static char loc_buf[PAGE_SIZE];
static int pidns_proc = -1;

bool privately_dump_vma(struct vma_area *vma)
{
	/*
	 * The special areas are not dumped.
	 */
	if (!(vma->vma.status & VMA_AREA_REGULAR))
		return false;

	/* No dumps for file-shared mappings */
	if (vma->vma.status & VMA_FILE_SHARED)
		return false;

	/* No dumps for SYSV IPC mappings */
	if (vma->vma.status & VMA_AREA_SYSVIPC)
		return false;

	if (vma_area_is(vma, VMA_ANON_SHARED))
		return false;

	if (!vma_area_is(vma, VMA_ANON_PRIVATE) &&
			!vma_area_is(vma, VMA_FILE_PRIVATE)) {
		pr_warn("Unexpected VMA area found\n");
		return false;
	}

	if (vma->vma.end > TASK_SIZE)
		return false;

	return true;
}

void free_mappings(struct vm_area_list *vma_area_list)
{
	struct vma_area *vma_area, *p;

	list_for_each_entry_safe(vma_area, p, &vma_area_list->h, list) {
		if (vma_area->vm_file_fd > 0)
			close(vma_area->vm_file_fd);
		free(vma_area);
	}

	INIT_LIST_HEAD(&vma_area_list->h);
	vma_area_list->nr = 0;
}

int collect_mappings(pid_t pid, struct vm_area_list *vma_area_list)
{
	int ret = -1;

	pr_info("\n");
	pr_info("Collecting mappings (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	ret = parse_smaps(pid, vma_area_list, true);
	if (ret < 0)
		goto err;

	pr_info("Collected, longest ares %lu bytes\n", vma_area_list->longest);
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

	ret = sched_getscheduler(pid);
	if (ret < 0) {
		pr_perror("Can't get sched policy for %d", pid);
		return -1;
	}

	pr_info("%d has %d sched policy\n", pid, ret);
	tc->has_sched_policy = true;
	tc->sched_policy = ret;

	if ((ret == SCHED_RR) || (ret == SCHED_FIFO)) {
		ret = sched_getparam(pid, &sp);
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
	if (errno) {
		pr_perror("Can't get nice for %d", pid);
		return -1;
	}

	pr_info("\tdumping %d nice for %d\n", ret, pid);
	tc->has_sched_nice = true;
	tc->sched_nice = ret;

	return 0;
}

struct cr_fdset *glob_fdset;

static int collect_fds(pid_t pid, struct parasite_drain_fd *dfds)
{
	struct dirent *de;
	DIR *fd_dir;
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

		if (n > PARASITE_MAX_FDS - 1)
			return -ENOMEM;

		dfds->fds[n++] = atoi(de->d_name);
	}

	dfds->nr_fds = n;
	pr_info("Found %d file descriptors\n", n);
	pr_info("----------------------------------------\n");

	closedir(fd_dir);

	return 0;
}

static int dump_task_exe_link(pid_t pid, MmEntry *mm)
{
	struct fd_parms params = FD_PARMS_INIT;
	int fd, ret;

	fd = open_proc(pid, "exe");
	if (fd < 0)
		return -1;

	if (fstat(fd, &params.stat) < 0) {
		pr_perror("Can't fstat exe link");
		return -1;
	}

	mm->exe_file_id = fd_id_generate_special();

	ret = dump_one_reg_file(fd, mm->exe_file_id, &params);
	close(fd);

	return ret;
}

static int dump_task_fs(pid_t pid, struct parasite_dump_misc *misc, struct cr_fdset *fdset)
{
	struct fd_parms p = FD_PARMS_INIT;
	FsEntry fe = FS_ENTRY__INIT;
	int fd, ret;

	fe.has_umask = true;
	fe.umask = misc->umask;

	fd = open_proc(pid, "cwd");
	if (fd < 0)
		return -1;

	if (fstat(fd, &p.stat) < 0) {
		pr_perror("Can't stat cwd");
		return -1;
	}

	fe.cwd_id = fd_id_generate_special();

	ret = dump_one_reg_file(fd, fe.cwd_id, &p);
	if (ret < 0)
		return ret;

	close(fd);

	fd = open_proc(pid, "root");
	if (fd < 0)
		return -1;

	p = FD_PARMS_INIT;
	if (fstat(fd, &p.stat) < 0) {
		pr_perror("Can't stat root");
		return -1;
	}

	fe.root_id = fd_id_generate_special();

	ret = dump_one_reg_file(fd, fe.root_id, &p);
	if (ret < 0)
		return ret;

	close(fd);

	pr_info("Dumping task cwd id %#x root id %#x\n",
			fe.cwd_id, fe.root_id);

	return pb_write_one(fdset_fd(fdset, CR_FD_FS), &fe, PB_FS);
}

static inline u_int64_t encode_rlim(unsigned long val)
{
	return val == RLIM_INFINITY ? -1 : val;
}

static int dump_task_rlims(int pid, struct cr_fdset *fds)
{
	int res, fd;

	fd = fdset_fd(fds, CR_FD_RLIMIT);

	for (res = 0; res < RLIM_NLIMITS; res++) {
		struct rlimit lim;
		RlimitEntry re = RLIMIT_ENTRY__INIT;

		if (prlimit(pid, res, NULL, &lim)) {
			pr_perror("Can't get rlimit %d", res);
			return -1;
		}

		re.cur = encode_rlim(lim.rlim_cur);
		re.max = encode_rlim(lim.rlim_max);

		if (pb_write_one(fd, &re, PB_RLIMIT))
			return -1;
	}

	return 0;
}

static int dump_filemap(pid_t pid, VmaEntry *vma, int file_fd,
		const struct cr_fdset *fdset)
{
	struct fd_parms p = FD_PARMS_INIT;

	if (fstat(file_fd, &p.stat) < 0) {
		pr_perror("Can't stat file for vma");
		return -1;
	}

	if ((vma->prot & PROT_WRITE) && vma_entry_is(vma, VMA_FILE_SHARED))
		p.flags = O_RDWR;
	else
		p.flags = O_RDONLY;
	vma->shmid = fd_id_generate_special();

	return dump_one_reg_file(file_fd, vma->shmid, &p);
}

static int check_sysvipc_map_dump(pid_t pid, VmaEntry *vma)
{
	if (current_ns_mask & CLONE_NEWIPC)
		return 0;

	pr_err("Task %d with SysVIPC shmem map @%"PRIx64" doesn't live in IPC ns\n",
			pid, vma->start);
	return -1;
}

static int dump_task_mappings(pid_t pid, const struct vm_area_list *vma_area_list,
			      const struct cr_fdset *cr_fdset)
{
	struct vma_area *vma_area;
	int ret = -1, fd;

	pr_info("\n");
	pr_info("Dumping mappings (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	fd = fdset_fd(cr_fdset, CR_FD_VMAS);

	list_for_each_entry(vma_area, &vma_area_list->h, list) {
		VmaEntry *vma = &vma_area->vma;

		pr_info_vma(vma_area);

		if (!vma_entry_is(vma, VMA_AREA_REGULAR))
			ret = 0;
		else if (vma_entry_is(vma, VMA_AREA_SYSVIPC))
			ret = check_sysvipc_map_dump(pid, vma);
		else if (vma_entry_is(vma, VMA_ANON_SHARED))
			ret = add_shmem_area(pid, vma);
		else if (vma_entry_is(vma, VMA_FILE_PRIVATE) ||
				vma_entry_is(vma, VMA_FILE_SHARED))
			ret = dump_filemap(pid, vma, vma_area->vm_file_fd, cr_fdset);
		else if (vma_entry_is(vma, VMA_AREA_SOCKET))
			ret = dump_socket_map(vma_area);
		else
			ret = 0;

		if (!ret)
			ret = pb_write_one(fd, vma, PB_VMAS);
		if (ret)
			goto err;
	}

	ret = 0;
	pr_info("----------------------------------------\n");
err:
	return ret;
}

static int dump_task_creds(struct parasite_ctl *ctl, const struct cr_fdset *fds)
{
	int ret;
	struct proc_status_creds cr;
	CredsEntry ce = CREDS_ENTRY__INIT;

	pr_info("\n");
	pr_info("Dumping creds for %d)\n", ctl->pid.real);
	pr_info("----------------------------------------\n");

	ret = parse_pid_status(ctl->pid.real, &cr);
	if (ret < 0)
		return ret;

	ce.uid   = cr.uids[0];
	ce.gid   = cr.gids[0];
	ce.euid  = cr.uids[1];
	ce.egid  = cr.gids[1];
	ce.suid  = cr.uids[2];
	ce.sgid  = cr.gids[2];
	ce.fsuid = cr.uids[3];
	ce.fsgid = cr.gids[3];

	BUILD_BUG_ON(CR_CAP_SIZE != PROC_CAP_SIZE);

	ce.n_cap_inh = CR_CAP_SIZE;
	ce.cap_inh = cr.cap_inh;
	ce.n_cap_prm = CR_CAP_SIZE;
	ce.cap_prm = cr.cap_prm;
	ce.n_cap_eff = CR_CAP_SIZE;
	ce.cap_eff = cr.cap_eff;
	ce.n_cap_bnd = CR_CAP_SIZE;
	ce.cap_bnd = cr.cap_bnd;

	if (parasite_dump_creds(ctl, &ce) < 0)
		return -1;

	return pb_write_one(fdset_fd(fds, CR_FD_CREDS), &ce, PB_CREDS);
}

static int get_task_auxv(pid_t pid, MmEntry *mm, size_t *size)
{
	int fd, ret, i;

	pr_info("Obtaining task auvx ... ");

	fd = open_proc(pid, "auxv");
	if (fd < 0)
		return -1;

	for (i = 0; i < AT_VECTOR_SIZE; i++) {
		ret = read(fd, &mm->mm_saved_auxv[i],
			   sizeof(auxv_t));
		if (ret == 0)
			break;
		else if (ret != sizeof(auxv_t)) {
			ret = -1;
			pr_perror("Error reading %d's auxv[%d]",
				  pid, i);
			goto err;
		}
	}

	*size = i;
	ret = 0;
err:
	close_safe(&fd);
	return ret;
}

static int dump_task_mm(struct parasite_ctl *ctl, const struct proc_pid_stat *stat,
		const struct parasite_dump_misc *misc, const struct cr_fdset *fdset)
{
	MmEntry mme = MM_ENTRY__INIT;
	int ret = -1;
	pid_t pid = ctl->pid.real;

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

	mme.n_mm_saved_auxv = AT_VECTOR_SIZE;
	mme.mm_saved_auxv = xmalloc(pb_repeated_size(&mme, mm_saved_auxv));
	if (!mme.mm_saved_auxv)
		goto out;

	if (get_task_auxv(pid, &mme, &mme.n_mm_saved_auxv))
		goto out;
	pr_info("OK\n");

	if (dump_task_exe_link(pid, &mme))
		goto out;

	ret = pb_write_one(fdset_fd(fdset, CR_FD_MM), &mme, PB_MM);
	xfree(mme.mm_saved_auxv);
out:
	return ret;
}

static int get_task_futex_robust_list(pid_t pid, ThreadCoreEntry *info)
{
	struct robust_list_head *head = NULL;
	size_t len = 0;
	int ret;

	ret = sys_get_robust_list(pid, &head, &len);
	if (ret) {
		pr_err("Failed obtaining futex robust list on %d\n", pid);
		return -1;
	}

	info->futex_rla		= encode_pointer(head);
	info->futex_rla_len	= (u32)len;

	return 0;
}

static int get_task_personality(pid_t pid, u32 *personality)
{
	FILE *file = NULL;
	int ret = -1;

	pr_info("Obtaining personality ... ");

	file = fopen_proc(pid, "personality");
	if (!file)
		goto err;

	if (!fgets(loc_buf, sizeof(loc_buf), file)) {
		pr_perror("Can't read task personality");
		goto err;
	}

	*personality = atoi(loc_buf);
	ret = 0;

err:
	if (file)
		fclose(file);
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
	int pid = item->pid.real;
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

static void core_entry_free(CoreEntry *core)
{
	if (core) {
		arch_free_thread_info(core);
		xfree(core->thread_core);
		xfree(core->tc);
		xfree(core->ids);
		xfree(core);
	}
}

static CoreEntry *core_entry_alloc(int alloc_thread_info,
				   int alloc_tc)
{
	CoreEntry *core;
	TaskCoreEntry *tc;

	core = xmalloc(sizeof(*core));
	if (!core)
		return NULL;
	core_entry__init(core);

	core->mtype = CORE_ENTRY__MARCH;

	if (alloc_thread_info) {
		if (arch_alloc_thread_info(core))
			goto err;
	}

	if (alloc_tc) {
		tc = xzalloc(sizeof(*tc) + TASK_COMM_LEN);
		if (!tc)
			goto err;
		task_core_entry__init(tc);
		tc->comm = (void *)tc + sizeof(*tc);
		core->tc = tc;
	}

	return core;
err:
	core_entry_free(core);
	return NULL;
}

int get_task_ids(struct pstree_item *item)
{
	int ret;

	item->ids = xmalloc(sizeof(*item->ids));
	if (!item->ids)
		goto err;

	task_kobj_ids_entry__init(item->ids);

	if (item->state != TASK_DEAD) {
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

static int dump_task_ids(struct pstree_item *item, const struct cr_fdset *cr_fdset)
{
	return pb_write_one(fdset_fd(cr_fdset, CR_FD_IDS), item->ids, PB_IDS);
}

static int dump_task_core_all(struct parasite_ctl *ctl,
		const struct proc_pid_stat *stat,
		const struct parasite_dump_misc *misc,
		struct vm_area_list *vma_area_list,
		const struct cr_fdset *cr_fdset)
{
	int fd_core = fdset_fd(cr_fdset, CR_FD_CORE);
	CoreEntry *core;
	int ret = -1;
	pid_t pid = ctl->pid.real;

	core = core_entry_alloc(1, 1);
	if (!core)
		return -1;

	pr_info("\n");
	pr_info("Dumping core (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	ret = dump_task_mm(ctl, stat, misc, cr_fdset);
	if (ret)
		goto err_free;

	ret = get_task_regs(pid, core, ctl);
	if (ret)
		goto err_free;

	ret = get_task_futex_robust_list(pid, core->thread_core);
	if (ret)
		goto err_free;

	ret = get_task_personality(pid, &core->tc->personality);
	if (ret)
		goto err_free;

	strncpy((char *)core->tc->comm, stat->comm, TASK_COMM_LEN);
	core->tc->flags = stat->flags;
	BUILD_BUG_ON(sizeof(core->tc->blk_sigset) != sizeof(k_rtsigset_t));
	memcpy(&core->tc->blk_sigset, &misc->blocked, sizeof(k_rtsigset_t));

	core->tc->task_state = TASK_ALIVE;
	core->tc->exit_code = 0;

	ret = dump_sched_info(pid, core->thread_core);
	if (ret)
		goto err_free;

	core_put_tls(core, misc->tls);

	ret = pb_write_one(fd_core, core, PB_CORE);
	if (ret < 0)
		goto err_free;

err_free:
	core_entry_free(core);
	pr_info("----------------------------------------\n");

	return ret;
}

static int parse_threads(const struct pstree_item *item, struct pid **_t, int *_n)
{
	struct dirent *de;
	DIR *dir;
	struct pid *t = NULL;
	int nr = 1;

	dir = opendir_proc(item->pid.real, "task");
	if (!dir)
		return -1;

	while ((de = readdir(dir))) {
		struct pid *tmp;

		/* We expect numbers only here */
		if (de->d_name[0] == '.')
			continue;

		tmp = xrealloc(t, nr * sizeof(struct pid));
		if (!tmp) {
			xfree(t);
			return -1;
		}
		t = tmp;
		t[nr - 1].real = atoi(de->d_name);
		t[nr - 1].virt = -1;
		nr++;
	}

	closedir(dir);

	*_t = t;
	*_n = nr - 1;

	return 0;
}

static int get_threads(struct pstree_item *item)
{
	return parse_threads(item, &item->threads, &item->nr_threads);
}

static int check_threads(const struct pstree_item *item)
{
	struct pid *t;
	int nr, ret;

	ret = parse_threads(item, &t, &nr);
	if (ret)
		return ret;

	ret = ((nr == item->nr_threads) && !memcmp(t, item->threads, nr));
	xfree(t);

	if (!ret) {
		pr_info("Threads set has changed while suspending\n");
		return -1;
	}

	return 0;
}

static int parse_children(pid_t pid, pid_t **_c, int *_n)
{
	FILE *file;
	char *tok;
	pid_t *ch = NULL;
	int nr = 1;
	DIR *dir;
	struct dirent *de;

	dir = opendir_proc(pid, "task");
	if (dir == NULL)
		return -1;

	while ((de = readdir(dir))) {
		if (dir_dots(de))
			continue;

		file = fopen_proc(pid, "task/%s/children", de->d_name);
		if (!file)
			goto err;

		if (!(fgets(loc_buf, sizeof(loc_buf), file)))
			loc_buf[0] = 0;

		fclose(file);

		tok = strtok(loc_buf, " \n");
		while (tok) {
			pid_t *tmp = xrealloc(ch, nr * sizeof(pid_t));
			if (!tmp)
				goto err;
			ch = tmp;
			ch[nr - 1] = atoi(tok);
			nr++;
			tok = strtok(NULL, " \n");
		}

	}

	*_c = ch;
	*_n = nr - 1;

	closedir(dir);
	return 0;
err:
	closedir(dir);
	xfree(ch);
	return -1;
}

static int get_children(struct pstree_item *item)
{
	pid_t *ch;
	int ret, i, nr_children;
	struct pstree_item *c;

	ret = parse_children(item->pid.real, &ch, &nr_children);
	if (ret < 0)
		return ret;

	for (i = 0; i < nr_children; i++) {
		c = alloc_pstree_item();
		if (c == NULL) {
			ret = -1;
			goto free;
		}
		c->pid.real = ch[i];
		c->parent = item;
		list_add_tail(&c->sibling, &item->children);
	}
free:
	xfree(ch);
	return ret;
}

static void unseize_task_and_threads(const struct pstree_item *item, int st)
{
	int i;

	for (i = 0; i < item->nr_threads; i++)
		unseize_task(item->threads[i].real, st); /* item->pid will be here */
}

static void pstree_switch_state(struct pstree_item *root_item, int st)
{
	struct pstree_item *item = root_item;

	pr_info("Unfreezing tasks into %d\n", st);
	for_each_pstree_item(item)
		unseize_task_and_threads(item, st);
}

static pid_t item_ppid(const struct pstree_item *item)
{
	item = item->parent;
	return item ? item->pid.real : -1;
}

static int seize_threads(const struct pstree_item *item)
{
	int i = 0, ret;

	if ((item->state == TASK_DEAD) && (item->nr_threads > 1)) {
		pr_err("Zombies with threads are not supported\n");
		goto err;
	}

	for (i = 0; i < item->nr_threads; i++) {
		pid_t pid = item->threads[i].real;
		if (item->pid.real == pid)
			continue;

		pr_info("\tSeizing %d's %d thread\n",
				item->pid.real, pid);
		ret = seize_task(pid, item_ppid(item), NULL, NULL);
		if (ret < 0)
			goto err;

		if (ret == TASK_DEAD) {
			pr_err("Zombie thread not supported\n");
			goto err;
		}

		if (ret == TASK_STOPPED) {
			pr_err("Stopped threads not supported\n");
			goto err;
		}
	}

	return 0;

err:
	for (i--; i >= 0; i--) {
		if (item->pid.real == item->threads[i].real)
			continue;

		unseize_task(item->threads[i].real, TASK_ALIVE);
	}

	return -1;
}

static int collect_threads(struct pstree_item *item)
{
	int ret;

	ret = get_threads(item);
	if (!ret)
		ret = seize_threads(item);
	if (!ret)
		ret = check_threads(item);

	return ret;
}

static int collect_task(struct pstree_item *item)
{
	int ret;
	pid_t pid = item->pid.real;

	ret = seize_task(pid, item_ppid(item), &item->pgid, &item->sid);
	if (ret < 0)
		goto err;

	pr_info("Seized task %d, state %d\n", pid, ret);
	item->state = ret;

	ret = collect_threads(item);
	if (ret < 0)
		goto err_close;

	ret = get_children(item);
	if (ret < 0)
		goto err_close;

	if ((item->state == TASK_DEAD) && !list_empty(&item->children)) {
		pr_err("Zombie with children?! O_o Run, run, run!\n");
		goto err_close;
	}

	close_pid_proc();

	pr_info("Collected %d in %d state\n", item->pid.real, item->state);
	return 0;

err_close:
	close_pid_proc();
	unseize_task(pid, item->state);
err:
	return -1;
}

static int check_subtree(const struct pstree_item *item)
{
	pid_t *ch;
	int nr, ret, i;
	struct pstree_item *child;

	ret = parse_children(item->pid.real, &ch, &nr);
	if (ret < 0)
		return ret;

	i = 0;
	list_for_each_entry(child, &item->children, sibling) {
		if (child->pid.real != ch[i])
			break;
		i++;
		if (i > nr)
			break;
	}
	xfree(ch);

	if (i != nr) {
		pr_info("Children set has changed while suspending\n");
		return -1;
	}

	return 0;
}

static int collect_subtree(struct pstree_item *item)
{
	struct pstree_item *child;
	pid_t pid = item->pid.real;
	int ret;

	pr_info("Collecting tasks starting from %d\n", pid);
	ret = collect_task(item);
	if (ret)
		return -1;

	list_for_each_entry(child, &item->children, sibling) {
		ret = collect_subtree(child);
		if (ret < 0)
			return -1;
	}

	if (check_subtree(item))
		return -1;

	return 0;
}

static int collect_pstree_ids(void)
{
	struct pstree_item *item;

	for_each_pstree_item(item)
		if (get_task_ids(item))
			return -1;

	return 0;
}

static int collect_pstree(pid_t pid)
{
	int ret, attempts = 5;

	timing_start(TIME_FREEZING);

	while (1) {
		root_item = alloc_pstree_item();
		if (root_item == NULL)
			return -1;

		root_item->pid.real = pid;

		ret = collect_subtree(root_item);
		if (ret == 0) {
			/*
			 * Some tasks could have been reparented to
			 * namespaces' reaper. Check this.
			 */
			if (check_subtree(root_item))
				goto try_again;

			break;
		}

		/*
		 * Old tasks can die and new ones can appear while we
		 * try to seize the swarm. It's much simpler (and reliable)
		 * just to restart the collection from the beginning
		 * rather than trying to chase them.
		 */
try_again:
		if (attempts == 0) {
			pr_err("Can't freeze the tree\n");
			return -1;
		}

		attempts--;
		pr_info("Trying to suspend tasks again\n");

		pstree_switch_state(root_item, TASK_ALIVE);
		free_pstree(root_item);
	}

	timing_stop(TIME_FREEZING);
	timing_start(TIME_FROZEN);

	return 0;
}

static int collect_file_locks(void)
{
	if (parse_file_locks())
		return -1;

	if (opts.handle_file_locks)
		/*
		 * If the handle file locks option(-l) is set,
		 * collect work is over.
		 */
		return 0;

	/*
	 * If the handle file locks option is not set, we need to do
	 * the check, any file locks hold by tasks in our pstree is
	 * not allowed.
	 *
	 * It's hard to do it carefully, there might be some other
	 * issues like tasks beyond pstree would use flocks hold by
	 * dumping tasks, but we can't know it in dumping time.
	 * We need to make sure these flocks only used by dumping tasks.
	 * We might have to do the check that this option would only
	 * be used by container dumping.
	 */
	if (!list_empty(&file_lock_list)) {
		pr_err("Some file locks are hold by dumping tasks!"
			  "You can try --" OPT_FILE_LOCKS " to dump them.\n");
		return -1;
	}

	return 0;

}

static int dump_task_thread(struct parasite_ctl *parasite_ctl, struct pid *tid)
{
	CoreEntry *core;
	int ret = -1, fd_core;
	pid_t pid = tid->real;

	pr_info("\n");
	pr_info("Dumping core for thread (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	core = core_entry_alloc(1, 0);
	if (!core)
		goto err;

	ret = get_task_regs(pid, core, NULL);
	if (ret)
		goto err_free;

	ret = get_task_futex_robust_list(pid, core->thread_core);
	if (ret)
		goto err_free;

	ret = parasite_dump_thread_seized(parasite_ctl, tid, core);
	if (ret) {
		pr_err("Can't dump thread for pid %d\n", pid);
		goto err_free;
	}

	core->thread_core->has_blk_sigset = true;

	ret = dump_sched_info(pid, core->thread_core);
	if (ret)
		goto err_free;

	fd_core = open_image(CR_FD_CORE, O_DUMP, tid->virt);
	if (fd_core < 0)
		goto err_free;

	ret = pb_write_one(fd_core, core, PB_CORE);

	close(fd_core);
err_free:
	core_entry_free(core);
err:
	pr_info("----------------------------------------\n");
	return ret;
}

static int dump_one_zombie(const struct pstree_item *item,
			   const struct proc_pid_stat *pps)
{
	CoreEntry *core;
	int ret = -1, fd_core;

	core = core_entry_alloc(0, 1);
	if (core == NULL)
		goto err;

	core->tc->task_state = TASK_DEAD;
	core->tc->exit_code = pps->exit_code;

	fd_core = open_image(CR_FD_CORE, O_DUMP, item->pid.virt);
	if (fd_core < 0)
		goto err_free;

	ret = pb_write_one(fd_core, core, PB_CORE);
	close(fd_core);
err_free:
	core_entry_free(core);
err:
	return ret;
}

static int dump_signal_queue(pid_t tid, int fd, bool group)
{
	struct ptrace_peeksiginfo_args arg;
	siginfo_t siginfo[32]; /* One page or all non-rt signals */
	int ret, i = 0, j, nr;

	arg.nr = sizeof(siginfo) / sizeof(siginfo_t);
	arg.flags = 0;
	if (group)
		arg.flags |= PTRACE_PEEKSIGINFO_SHARED;

	for (; ; ) {
		arg.off = i;

		ret = ptrace(PTRACE_PEEKSIGINFO, tid, &arg, siginfo);
		if (ret < 0) {
			if (errno == EIO) {
				pr_warn("ptrace doesn't support PTRACE_PEEKSIGINFO\n");
				ret = 0;
			} else
				pr_perror("ptrace");
			break;
		}

		if (ret == 0)
			break;
		nr = ret;

		for (j = 0; j < nr; j++) {
			SiginfoEntry sie = SIGINFO_ENTRY__INIT;

			sie.siginfo.len = sizeof(siginfo_t);
			sie.siginfo.data = (void *) (siginfo + j);

			ret = pb_write_one(fd, &sie, PB_SIGINFO);
			if (ret < 0)
				break;
			i++;
		}
	}

	return ret;
}

static int dump_thread_signals(struct pid *tid)
{
	int fd, ret;

	fd = open_image(CR_FD_PSIGNAL, O_DUMP, tid->virt);
	if (fd < 0)
		return -1;
	ret = dump_signal_queue(tid->real, fd, false);
	close(fd);

	return ret;
}

static struct proc_pid_stat pps_buf;

static int dump_task_threads(struct parasite_ctl *parasite_ctl,
			     const struct pstree_item *item)
{
	int i;

	for (i = 0; i < item->nr_threads; i++) {
		/* Leader is already dumped */
		if (item->pid.real == item->threads[i].real)
			item->threads[i].virt = item->pid.virt;
		else {
			if (dump_task_thread(parasite_ctl, &item->threads[i]))
				return -1;
		}

		if (dump_thread_signals(&item->threads[i]))
			return -1;
	}

	return 0;
}

static int fill_zombies_pids(struct pstree_item *item)
{
	struct pstree_item *child;
	int i, nr;
	pid_t *ch;

	if (parse_children(item->pid.virt, &ch, &nr) < 0)
		return -1;

	list_for_each_entry(child, &item->children, sibling) {
		if (child->pid.virt < 0)
			continue;
		for (i = 0; i < nr; i++) {
			if (ch[i] == child->pid.virt) {
				ch[i] = -1;
				break;
			}
		}
	}

	i = 0;
	list_for_each_entry(child, &item->children, sibling) {
		if (child->pid.virt > 0)
			continue;
		for (; i < nr; i++) {
			if (ch[i] < 0)
				continue;
			child->pid.virt = ch[i];
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
	int oldfd, ret = -1;
	int pidns = current_ns_mask & CLONE_NEWPID;

	if (pidns) {
		oldfd = set_proc_fd(pidns_proc);
		if (oldfd < 0)
			return -1;
	}

	for_each_pstree_item(item) {
		if (item->state != TASK_DEAD)
			continue;

		if (item->pid.virt < 0) {
			if (!pidns)
				item->pid.virt = item->pid.real;
			else if (root_item == item) {
				pr_err("A root task is dead\n");
				goto err;
			} else if (fill_zombies_pids(item->parent))
				goto err;
		}

		pr_info("Obtaining zombie stat ... ");
		if (parse_pid_stat(item->pid.virt, &pps_buf) < 0)
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

static int pre_dump_one_task(struct pstree_item *item, struct list_head *ctls)
{
	pid_t pid = item->pid.real;
	struct vm_area_list vmas;
	struct parasite_ctl *parasite_ctl;
	int ret = -1;
	struct parasite_dump_misc misc;

	pr_info("========================================\n");
	pr_info("Pre-dumping task (pid: %d)\n", pid);
	pr_info("========================================\n");

	if (item->state == TASK_STOPPED) {
		pr_warn("Stopped tasks are not supported\n");
		return 0;
	}

	if (item->state == TASK_DEAD)
		return 0;

	ret = collect_mappings(pid, &vmas);
	if (ret) {
		pr_err("Collect mappings (pid: %d) failed with %d\n", pid, ret);
		goto err;
	}

	ret = -1;
	parasite_ctl = parasite_infect_seized(pid, item, &vmas, NULL);
	if (!parasite_ctl) {
		pr_err("Can't infect (pid: %d) with parasite\n", pid);
		goto err_free;
	}

	ret = parasite_dump_misc_seized(parasite_ctl, &misc);
	if (ret) {
		pr_err("Can't dump misc (pid: %d)\n", pid);
		goto err_cure;
	}

	parasite_ctl->pid.virt = item->pid.virt = misc.pid;

	ret = parasite_dump_pages_seized(parasite_ctl, &vmas, &parasite_ctl->mem_pp);
	if (ret)
		goto err_cure;

	if (parasite_cure_remote(parasite_ctl, item))
		pr_err("Can't cure (pid: %d) from parasite\n", pid);
	list_add_tail(&parasite_ctl->pre_list, ctls);
err_free:
	free_mappings(&vmas);
err:
	return ret;

err_cure:
	if (parasite_cure_seized(parasite_ctl, item))
		pr_err("Can't cure (pid: %d) from parasite\n", pid);
	goto err_free;
}

static int dump_one_task(struct pstree_item *item)
{
	pid_t pid = item->pid.real;
	struct vm_area_list vmas;
	struct parasite_ctl *parasite_ctl;
	int ret = -1;
	struct parasite_dump_misc misc;
	struct cr_fdset *cr_fdset = NULL;
	struct parasite_drain_fd *dfds;

	pr_info("========================================\n");
	pr_info("Dumping task (pid: %d)\n", pid);
	pr_info("========================================\n");

	if (item->state == TASK_STOPPED) {
		pr_err("Stopped tasks are not supported\n");
		return -1;
	}

	if (item->state == TASK_DEAD)
		return 0;

	dfds = xmalloc(sizeof(*dfds));
	if (!dfds)
		goto err_free;

	pr_info("Obtaining task stat ... ");
	ret = parse_pid_stat(pid, &pps_buf);
	if (ret < 0)
		goto err;

	ret = collect_mappings(pid, &vmas);
	if (ret) {
		pr_err("Collect mappings (pid: %d) failed with %d\n", pid, ret);
		goto err;
	}

	ret = collect_fds(pid, dfds);
	if (ret) {
		pr_err("Collect fds (pid: %d) failed with %d\n", pid, ret);
		goto err;
	}

	ret = -1;
	parasite_ctl = parasite_infect_seized(pid, item, &vmas, dfds);
	if (!parasite_ctl) {
		pr_err("Can't infect (pid: %d) with parasite\n", pid);
		goto err;
	}

	if (current_ns_mask & CLONE_NEWPID && root_item == item) {
		pidns_proc = parasite_get_proc_fd_seized(parasite_ctl);
		if (pidns_proc < 0) {
			pr_err("Can't get proc fd (pid: %d)\n", pid);
			goto err_cure_fdset;
		}
	}

	ret = parasite_dump_misc_seized(parasite_ctl, &misc);
	if (ret) {
		pr_err("Can't dump misc (pid: %d)\n", pid);
		goto err_cure_fdset;
	}

	parasite_ctl->pid.virt = item->pid.virt = misc.pid;
	item->sid = misc.sid;
	item->pgid = misc.pgid;

	pr_info("sid=%d pgid=%d pid=%d\n",
		item->sid, item->pgid, item->pid.virt);

	if (item->sid == 0) {
		pr_err("A session leader of %d(%d) is outside of its pid namespace\n",
			item->pid.real, item->pid.virt);
		ret = -1;
		goto err_cure;
	}

	ret = -1;
	cr_fdset = cr_task_fdset_open(item->pid.virt, O_DUMP);
	if (!cr_fdset)
		goto err_cure;

	ret = dump_task_ids(item, cr_fdset);
	if (ret) {
		pr_err("Dump ids (pid: %d) failed with %d\n", pid, ret);
		goto err_cure;
	}

	if (!shared_fdtable(item)) {
		ret = dump_task_files_seized(parasite_ctl, item, dfds);
		if (ret) {
			pr_err("Dump files (pid: %d) failed with %d\n", pid, ret);
			goto err_cure;
		}
	}

	if (opts.handle_file_locks) {
		ret = dump_task_file_locks(parasite_ctl, cr_fdset, dfds);
		if (ret) {
			pr_err("Dump file locks (pid: %d) failed with %d\n",
				pid, ret);
			goto err_cure;
		}
	}

	ret = parasite_dump_pages_seized(parasite_ctl, &vmas, NULL);
	if (ret)
		goto err_cure;

	ret = parasite_dump_sigacts_seized(parasite_ctl, cr_fdset);
	if (ret) {
		pr_err("Can't dump sigactions (pid: %d) with parasite\n", pid);
		goto err_cure;
	}

	ret = parasite_dump_itimers_seized(parasite_ctl, cr_fdset);
	if (ret) {
		pr_err("Can't dump itimers (pid: %d)\n", pid);
		goto err_cure;
	}

	ret = dump_task_core_all(parasite_ctl, &pps_buf, &misc, &vmas, cr_fdset);
	if (ret) {
		pr_err("Dump core (pid: %d) failed with %d\n", pid, ret);
		goto err_cure;
	}

	ret = dump_task_threads(parasite_ctl, item);
	if (ret) {
		pr_err("Can't dump threads\n");
		goto err_cure;
	}

	ret = dump_task_creds(parasite_ctl, cr_fdset);
	if (ret) {
		pr_err("Dump creds (pid: %d) failed with %d\n", pid, ret);
		goto err;
	}

	ret = parasite_cure_seized(parasite_ctl, item);
	if (ret) {
		pr_err("Can't cure (pid: %d) from parasite\n", pid);
		goto err;
	}

	ret = dump_task_mappings(pid, &vmas, cr_fdset);
	if (ret) {
		pr_err("Dump mappings (pid: %d) failed with %d\n", pid, ret);
		goto err;
	}

	ret = dump_task_fs(pid, &misc, cr_fdset);
	if (ret) {
		pr_err("Dump fs (pid: %d) failed with %d\n", pid, ret);
		goto err;
	}

	ret = dump_task_rlims(pid, cr_fdset);
	if (ret) {
		pr_err("Dump %d rlimits failed %d\n", pid, ret);
		goto err;
	}

	ret = dump_signal_queue(pid, fdset_fd(cr_fdset, CR_FD_SIGNAL), true);
	if (ret) {
		pr_err("Can't dump pending signals (pid: %d)\n", pid);
		goto err_cure;
	}

	close_cr_fdset(&cr_fdset);
err:
	close_pid_proc();
err_free:
	free_mappings(&vmas);
	xfree(dfds);
	return ret;

err_cure:
	close_cr_fdset(&cr_fdset);
err_cure_fdset:
	parasite_cure_seized(parasite_ctl, item);
	goto err;
}

int cr_pre_dump_tasks(pid_t pid)
{
	struct pstree_item *item;
	int ret = -1;
	LIST_HEAD(ctls);
	struct parasite_ctl *ctl, *n;

	if (kerndat_init())
		goto err;

	if (connect_to_page_server())
		goto err;

	if (collect_pstree(pid))
		goto err;

	for_each_pstree_item(item)
		if (pre_dump_one_task(item, &ctls))
			goto err;

	ret = 0;
err:
	pstree_switch_state(root_item,
			ret ? TASK_ALIVE : opts.final_state);
	free_pstree(root_item);

	timing_stop(TIME_FROZEN);

	pr_info("Pre-dumping tasks' memory\n");
	list_for_each_entry_safe(ctl, n, &ctls, pre_list) {
		struct page_xfer xfer;

		pr_info("\tPre-dumping %d\n", ctl->pid.virt);
		timing_start(TIME_MEMWRITE);
		ret = open_page_xfer(&xfer, CR_FD_PAGEMAP, ctl->pid.virt);
		if (ret < 0)
			break;

		ret = page_xfer_dump_pages(&xfer, ctl->mem_pp, 0);

		xfer.close(&xfer);
		timing_stop(TIME_MEMWRITE);

		destroy_page_pipe(ctl->mem_pp);
		list_del(&ctl->pre_list);
		parasite_cure_local(ctl);
	}

	if (ret)
		pr_err("Pre-dumping FAILED.\n");
	else {
		write_stats(DUMP_STATS);
		pr_info("Pre-dumping finished successfully\n");
	}

	return ret;
}

int cr_dump_tasks(pid_t pid)
{
	struct pstree_item *item;
	int ret = -1;

	pr_info("========================================\n");
	pr_info("Dumping processes (pid: %d)\n", pid);
	pr_info("========================================\n");

	if (kerndat_init())
		goto err;

	if (cpu_init())
		goto err;

	if (write_img_inventory())
		goto err;

	if (connect_to_page_server())
		goto err;

	if (collect_pstree(pid))
		goto err;

	if (collect_pstree_ids())
		goto err;

	if (network_lock())
		goto err;

	if (collect_file_locks())
		goto err;

	if (collect_mount_info(pid))
		goto err;

	if (mntns_collect_root(root_item->pid.real))
		goto err;

	if (collect_sockets(pid))
		goto err;

	glob_fdset = cr_glob_fdset_open(O_DUMP);
	if (!glob_fdset)
		goto err;

	for_each_pstree_item(item) {
		if (dump_one_task(item))
			goto err;
	}

	if (dump_verify_tty_sids())
		goto err;

	if (dump_zombies())
		goto err;

	if (dump_pstree(root_item))
		goto err;

	if (current_ns_mask)
		if (dump_namespaces(&root_item->pid, current_ns_mask) < 0)
			goto err;

	ret = cr_dump_shmem();
	if (ret)
		goto err;

	ret = fix_external_unix_sockets();
	if (ret)
		goto err;

	ret = tty_verify_active_pairs();
	if (ret)
		goto err;

	fd_id_show_tree();
err:
	close_cr_fdset(&glob_fdset);

	/*
	 * If we've failed to do anything -- unlock all TCP sockets
	 * so that the connections can go on. But if we succeeded --
	 * don't, just close them silently.
	 */
	if (ret)
		network_unlock();
	pstree_switch_state(root_item,
			ret ? TASK_ALIVE : opts.final_state);
	timing_stop(TIME_FROZEN);
	free_pstree(root_item);
	free_file_locks();

	close_safe(&pidns_proc);

	if (ret) {
		kill_inventory();
		pr_err("Dumping FAILED.\n");
	} else {
		write_stats(DUMP_STATS);
		pr_info("Dumping finished successfully\n");
	}

	return ret;
}
