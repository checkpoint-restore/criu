#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <parasite.h>

#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/vfs.h>

#include <sys/sendfile.h>
#include <sys/mman.h>

#include <linux/major.h>

#include "types.h"
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
#include "pipes.h"
#include "fifo.h"
#include "shmem.h"
#include "sk-inet.h"
#include "eventfd.h"
#include "eventpoll.h"
#include "inotify.h"
#include "pstree.h"

#include "protobuf.h"
#include "protobuf/fdinfo.pb-c.h"
#include "protobuf/fs.pb-c.h"
#include "protobuf/mm.pb-c.h"
#include "protobuf/creds.pb-c.h"
#include "protobuf/core.pb-c.h"

#ifndef CONFIG_X86_64
# error No x86-32 support yet
#endif

static char loc_buf[PAGE_SIZE];

void free_mappings(struct list_head *vma_area_list)
{
	struct vma_area *vma_area, *p;

	list_for_each_entry_safe(vma_area, p, vma_area_list, list) {
		if (vma_area->vm_file_fd > 0)
			close(vma_area->vm_file_fd);
		free(vma_area);
	}

	INIT_LIST_HEAD(vma_area_list);
}

static int collect_mappings(pid_t pid, struct list_head *vma_area_list)
{
	int ret = -1;

	pr_info("\n");
	pr_info("Collecting mappings (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	ret = parse_smaps(pid, vma_area_list, true);
	if (ret < 0)
		goto err;

	pr_info_vma_list(vma_area_list);

	pr_info("----------------------------------------\n");
	ret = 0;

err:
	return ret;
}

struct cr_fdset *glob_fdset;

static int collect_fds(pid_t pid, int *fd, int *nr_fd)
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
		if (!strcmp(de->d_name, "."))
			continue;
		if (!strcmp(de->d_name, ".."))
			continue;

		if (n > *nr_fd - 1)
			return -ENOMEM;
		fd[n++] = atoi(de->d_name);
	}

	*nr_fd = n;
	pr_info("Found %d file descriptors\n", n);
	pr_info("----------------------------------------\n");

	closedir(fd_dir);

	return 0;
}

u32 make_gen_id(const struct fd_parms *p)
{
	return MAKE_FD_GENID(p->stat.st_dev, p->stat.st_ino, p->pos);
}

int do_dump_gen_file(struct fd_parms *p, int lfd,
		const struct fdtype_ops *ops, const struct cr_fdset *cr_fdset)
{
	FdinfoEntry e = FDINFO_ENTRY__INIT;
	int ret = -1;

	e.type	= ops->type;
	e.id	= ops->make_gen_id(p);
	e.fd	= p->fd;
	e.flags = p->fd_flags;

	ret = fd_id_generate(p->pid, &e);
	if (ret == 1) /* new ID generated */
		ret = ops->dump(lfd, e.id, p);

	if (ret < 0)
		return -1;

	pr_info("fdinfo: type: 0x%2x flags: 0x%4x pos: 0x%8lx fd: %d\n",
		ops->type, p->flags, p->pos, p->fd);

	return pb_write(fdset_fd(cr_fdset, CR_FD_FDINFO), &e, fdinfo_entry);
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

static int fill_fd_params(pid_t pid, int fd, int lfd, char fd_flags, struct fd_parms *p)
{
	struct f_owner_ex owner_ex;
	u32 v[2];

	if (fstat(lfd, &p->stat) < 0) {
		pr_perror("Can't stat fd %d\n", lfd);
		return -1;
	}

	p->fd		= fd;
	p->pos		= lseek(lfd, 0, SEEK_CUR);
	p->flags	= fcntl(lfd, F_GETFL);
	p->pid		= pid;
	p->fd_flags	= fd_flags;

	fown_entry__init(&p->fown);

	pr_info("%d fdinfo %d: pos: 0x%16lx flags: %16o/%#x\n",
		pid, fd, p->pos, p->flags, (int)fd_flags);

	p->fown.signum = fcntl(lfd, F_GETSIG, 0);
	if (p->fown.signum < 0) {
		pr_perror("Can't get owner signum on %d\n", lfd);
		return -1;
	}

	if (fcntl(lfd, F_GETOWN_EX, (long)&owner_ex)) {
		pr_perror("Can't get owners on %d\n", lfd);
		return -1;
	}

	/*
	 * Simple case -- nothing is changed.
	 */
	if (owner_ex.pid == 0)
		return 0;

	if (fcntl(lfd, F_GETOWNER_UIDS, (long)&v)) {
		pr_perror("Can't get owner uids on %d\n", lfd);
		return -1;
	}

	p->fown.uid	= v[0];
	p->fown.euid	= v[1];
	p->fown.pid_type= owner_ex.type;
	p->fown.pid	= owner_ex.pid;

	return 0;
}

static int dump_unsupp_fd(const struct fd_parms *p)
{
	pr_err("Can't dump file %d of that type [%#x]\n",
			p->fd, p->stat.st_mode);
	return -1;
}

static int dump_chrdev(struct fd_parms *p, int lfd, const struct cr_fdset *set)
{
	int maj = major(p->stat.st_rdev);

	switch (maj) {
	case MEM_MAJOR:
		return dump_reg_file(p, lfd, set);
	case TTY_MAJOR:
	case UNIX98_PTY_SLAVE_MAJOR:
		if (p->fd < 3) {
			pr_info("... Skipping tty ... %d\n", p->fd);
			return 0;
		}
	}

	return dump_unsupp_fd(p);
}

#ifndef PIPEFS_MAGIC
#define PIPEFS_MAGIC	0x50495045
#endif

static int dump_one_file(pid_t pid, int fd, int lfd, char fd_flags,
		       const struct cr_fdset *cr_fdset)
{
	struct fd_parms p;
	struct statfs statfs;

	if (fill_fd_params(pid, fd, lfd, fd_flags, &p) < 0) {
		pr_perror("Can't get stat on %d", fd);
		return -1;
	}

	if (S_ISSOCK(p.stat.st_mode))
		return dump_socket(&p, lfd, cr_fdset);

	if (S_ISCHR(p.stat.st_mode))
		return dump_chrdev(&p, lfd, cr_fdset);

	if (fstatfs(lfd, &statfs)) {
		pr_perror("Can't obtain statfs on fd %d\n", fd);
		return -1;
	}

	if (is_anon_inode(&statfs)) {
		if (is_eventfd_link(lfd))
			return dump_eventfd(&p, lfd, cr_fdset);
		else if (is_eventpoll_link(lfd))
			return dump_eventpoll(&p, lfd, cr_fdset);
		else if (is_inotify_link(lfd))
			return dump_inotify(&p, lfd, cr_fdset);
		else
			return dump_unsupp_fd(&p);
	}

	if (S_ISREG(p.stat.st_mode) || S_ISDIR(p.stat.st_mode))
		return dump_reg_file(&p, lfd, cr_fdset);

	if (S_ISFIFO(p.stat.st_mode)) {
		if (statfs.f_type == PIPEFS_MAGIC)
			return dump_pipe(&p, lfd, cr_fdset);
		else
			return dump_fifo(&p, lfd, cr_fdset);
	}

	return dump_unsupp_fd(&p);
}

static int dump_task_files_seized(struct parasite_ctl *ctl, const struct cr_fdset *cr_fdset,
				  int *fds, int nr_fds)
{
	int *lfds;
	char *flags;
	int i, ret = -1;

	pr_info("\n");
	pr_info("Dumping opened files (pid: %d)\n", ctl->pid);
	pr_info("----------------------------------------\n");

	lfds = xmalloc(PARASITE_MAX_FDS * sizeof(int));
	if (!lfds)
		goto err;

	flags = xmalloc(PARASITE_MAX_FDS * sizeof(char));
	if (!flags)
		goto err1;

	ret = parasite_drain_fds_seized(ctl, fds, lfds, nr_fds, flags);
	if (ret)
		goto err2;

	for (i = 0; i < nr_fds; i++) {
		ret = dump_one_file(ctl->pid, fds[i], lfds[i], flags[i], cr_fdset);
		close(lfds[i]);
		if (ret)
			goto err2;
	}

	pr_info("----------------------------------------\n");
err2:
	xfree(flags);
err1:
	xfree(lfds);
err:
	return ret;
}

static int dump_task_fs(pid_t pid, struct cr_fdset *fdset)
{
	struct fd_parms p = FD_PARMS_INIT;
	FsEntry fe = FS_ENTRY__INIT;
	int fd, ret;

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

	return pb_write(fdset_fd(fdset, CR_FD_FS), &fe, fs_entry);
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

static int dump_task_mappings(pid_t pid, const struct list_head *vma_area_list,
			      const struct cr_fdset *cr_fdset)
{
	struct vma_area *vma_area;
	int ret = -1, fd;

	pr_info("\n");
	pr_info("Dumping mappings (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	fd = fdset_fd(cr_fdset, CR_FD_VMAS);

	list_for_each_entry(vma_area, vma_area_list, list) {
		VmaEntry *vma = &vma_area->vma;

		pr_info_vma(vma_area);

		if (!vma_entry_is(vma, VMA_AREA_REGULAR) ||
				vma_entry_is(vma, VMA_AREA_SYSVIPC))
			ret = 0;
		else if (vma_entry_is(vma, VMA_ANON_SHARED))
			ret = add_shmem_area(pid, vma);
		else if (vma_entry_is(vma, VMA_FILE_PRIVATE) ||
				vma_entry_is(vma, VMA_FILE_SHARED))
			ret = dump_filemap(pid, vma, vma_area->vm_file_fd, cr_fdset);
		else
			ret = 0;

		if (!ret)
			ret = pb_write(fd, vma, vma_entry);
		if (ret)
			goto err;
	}

	ret = 0;
	pr_info("----------------------------------------\n");
err:
	return ret;
}

static int dump_task_creds(pid_t pid, const struct parasite_dump_misc *misc,
			   const struct cr_fdset *fds)
{
	int ret;
	struct proc_status_creds cr;
	CredsEntry ce = CREDS_ENTRY__INIT;

	pr_info("\n");
	pr_info("Dumping creds for %d)\n", pid);
	pr_info("----------------------------------------\n");

	ret = parse_pid_status(pid, &cr);
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

	ce.secbits = misc->secbits;

	return pb_write(fdset_fd(fds, CR_FD_CREDS), &ce, creds_entry);
}

#define assign_reg(dst, src, e)		dst->e = (__typeof__(dst->e))src.e
#define assign_array(dst, src, e)	memcpy(dst->e, &src.e, sizeof(src.e))

static int get_task_auxv(pid_t pid, MmEntry *mm)
{
	int fd, ret, i;

	pr_info("Obtainting task auvx ... ");

	fd = open_proc(pid, "auxv");
	if (fd < 0)
		return -1;

	for (i = 0; i < AT_VECTOR_SIZE; i++) {
		ret = read(fd, &mm->mm_saved_auxv[i],
			   sizeof(mm->mm_saved_auxv[0]));
		if (ret == 0)
			break;
		else if (ret != sizeof(mm->mm_saved_auxv[0])) {
			ret = -1;
			pr_perror("Error readind %d's auxv[%d]",
				  pid, i);
			goto err;
		}
	}

	ret = 0;
err:
	close_safe(&fd);
	return ret;
}

static int dump_task_mm(pid_t pid, const struct proc_pid_stat *stat,
		const struct parasite_dump_misc *misc, const struct cr_fdset *fdset)
{
	MmEntry mme = MM_ENTRY__INIT;
	int ret = -1;

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

	if (get_task_auxv(pid, &mme))
		goto out;
	pr_info("OK\n");

	if (dump_task_exe_link(pid, &mme))
		goto out;

	ret = pb_write(fdset_fd(fdset, CR_FD_MM), &mme, mm_entry);
	xfree(mme.mm_saved_auxv);
out:
	return ret;
}

static int get_task_personality(pid_t pid, u32 *personality)
{
	FILE *file = NULL;
	int ret = -1;

	pr_info("Obtainting personality ... ");

	file = fopen_proc(pid, "personality");
	if (!file)
		goto err;

	if (!fgets(loc_buf, sizeof(loc_buf), file)) {
		perror("Can't read task personality");
		goto err;
	}

	*personality = atoi(loc_buf);
	ret = 0;

err:
	if (file)
		fclose(file);
	return ret;
}

static int get_task_regs(pid_t pid, CoreEntry *core, const struct parasite_ctl *ctl)
{
	user_fpregs_struct_t fpregs	= {-1};
	user_regs_struct_t regs		= {-1};

	int ret = -1;

	pr_info("Dumping GP/FPU registers ... ");

	if (ctl)
		regs = ctl->regs_orig;
	else {
		if (ptrace(PTRACE_GETREGS, pid, NULL, &regs)) {
			pr_err("Can't obtain GP registers for %d\n", pid);
			goto err;
		}
	}

	if (ptrace(PTRACE_GETFPREGS, pid, NULL, &fpregs)) {
		pr_err("Can't obtain FPU registers for %d\n", pid);
		goto err;
	}

	/* Did we come from a system call? */
	if ((int)regs.orig_ax >= 0) {
		/* Restart the system call */
		switch ((long)(int)regs.ax) {
		case -ERESTARTNOHAND:
		case -ERESTARTSYS:
		case -ERESTARTNOINTR:
			regs.ax = regs.orig_ax;
			regs.ip -= 2;
			break;
		case -ERESTART_RESTARTBLOCK:
			regs.ax = __NR_restart_syscall;
			regs.ip -= 2;
			break;
		}
	}

	assign_reg(core->thread_info->gpregs, regs, r15);
	assign_reg(core->thread_info->gpregs, regs, r14);
	assign_reg(core->thread_info->gpregs, regs, r13);
	assign_reg(core->thread_info->gpregs, regs, r12);
	assign_reg(core->thread_info->gpregs, regs, bp);
	assign_reg(core->thread_info->gpregs, regs, bx);
	assign_reg(core->thread_info->gpregs, regs, r11);
	assign_reg(core->thread_info->gpregs, regs, r10);
	assign_reg(core->thread_info->gpregs, regs, r9);
	assign_reg(core->thread_info->gpregs, regs, r8);
	assign_reg(core->thread_info->gpregs, regs, ax);
	assign_reg(core->thread_info->gpregs, regs, cx);
	assign_reg(core->thread_info->gpregs, regs, dx);
	assign_reg(core->thread_info->gpregs, regs, si);
	assign_reg(core->thread_info->gpregs, regs, di);
	assign_reg(core->thread_info->gpregs, regs, orig_ax);
	assign_reg(core->thread_info->gpregs, regs, ip);
	assign_reg(core->thread_info->gpregs, regs, cs);
	assign_reg(core->thread_info->gpregs, regs, flags);
	assign_reg(core->thread_info->gpregs, regs, sp);
	assign_reg(core->thread_info->gpregs, regs, ss);
	assign_reg(core->thread_info->gpregs, regs, fs_base);
	assign_reg(core->thread_info->gpregs, regs, gs_base);
	assign_reg(core->thread_info->gpregs, regs, ds);
	assign_reg(core->thread_info->gpregs, regs, es);
	assign_reg(core->thread_info->gpregs, regs, fs);
	assign_reg(core->thread_info->gpregs, regs, gs);

	assign_reg(core->thread_info->fpregs, fpregs, cwd);
	assign_reg(core->thread_info->fpregs, fpregs, swd);
	assign_reg(core->thread_info->fpregs, fpregs, twd);
	assign_reg(core->thread_info->fpregs, fpregs, fop);
	assign_reg(core->thread_info->fpregs, fpregs, rip);
	assign_reg(core->thread_info->fpregs, fpregs, rdp);
	assign_reg(core->thread_info->fpregs, fpregs, mxcsr);
	assign_reg(core->thread_info->fpregs, fpregs, mxcsr_mask);

	/* Make sure we have enough space */
	BUG_ON(core->thread_info->fpregs->n_st_space != ARRAY_SIZE(fpregs.st_space));
	BUG_ON(core->thread_info->fpregs->n_xmm_space != ARRAY_SIZE(fpregs.xmm_space));
	BUG_ON(core->thread_info->fpregs->n_padding != ARRAY_SIZE(fpregs.padding));

	assign_array(core->thread_info->fpregs, fpregs,	st_space);
	assign_array(core->thread_info->fpregs, fpregs,	xmm_space);
	assign_array(core->thread_info->fpregs, fpregs,	padding);

	ret = 0;

err:
	return ret;
}

static DECLARE_KCMP_TREE(vm_tree, KCMP_VM);
static DECLARE_KCMP_TREE(fs_tree, KCMP_FS);
static DECLARE_KCMP_TREE(files_tree, KCMP_FILES);
static DECLARE_KCMP_TREE(sighand_tree, KCMP_SIGHAND);

static int dump_task_kobj_ids(pid_t pid, CoreEntry *core)
{
	int new;
	struct kid_elem elem;

	elem.pid = pid;
	elem.idx = 0; /* really 0 for all */
	elem.genid = 0; /* FIXME optimize */

	new = 0;
	core->ids->vm_id = kid_generate_gen(&vm_tree, &elem, &new);
	if (!core->ids->vm_id || !new) {
		pr_err("Can't make VM id for %d\n", pid);
		return -1;
	}

	new = 0;
	core->ids->fs_id = kid_generate_gen(&fs_tree, &elem, &new);
	if (!core->ids->fs_id || !new) {
		pr_err("Can't make FS id for %d\n", pid);
		return -1;
	}

	new = 0;
	core->ids->files_id = kid_generate_gen(&files_tree, &elem, &new);
	if (!core->ids->files_id || !new) {
		pr_err("Can't make FILES id for %d\n", pid);
		return -1;
	}

	new = 0;
	core->ids->sighand_id = kid_generate_gen(&sighand_tree, &elem, &new);
	if (!core->ids->sighand_id || !new) {
		pr_err("Can't make IO id for %d\n", pid);
		return -1;
	}

	return 0;
}

static void core_entry_free(CoreEntry *core)
{
	if (core) {
		if (core->thread_info) {
			if (core->thread_info->fpregs) {
				xfree(core->thread_info->fpregs->st_space);
				xfree(core->thread_info->fpregs->xmm_space);
				xfree(core->thread_info->fpregs->padding);
			}
			xfree(core->thread_info->gpregs);
			xfree(core->thread_info->fpregs);
		}
		xfree(core->thread_info);
		xfree(core->tc);
		xfree(core->ids);
	}
}

static CoreEntry *core_entry_alloc(int alloc_thread_info,
				   int alloc_tc,
				   int alloc_ids)
{
	CoreEntry *core;
	ThreadInfoX86 *thread_info;
	UserX86RegsEntry *gpregs;
	UserX86FpregsEntry *fpregs;
	TaskCoreEntry *tc;
	TaskKobjIdsEntry *ids;

	core = xmalloc(sizeof(*core));
	if (!core)
		return NULL;
	core_entry__init(core);

	core->mtype = CORE_ENTRY__MARCH__X86_64;

	if (alloc_thread_info) {
		thread_info = xmalloc(sizeof(*thread_info));
		if (!thread_info)
			goto err;
		thread_info_x86__init(thread_info);
		core->thread_info = thread_info;

		gpregs = xmalloc(sizeof(*gpregs));
		if (!gpregs)
			goto err;
		user_x86_regs_entry__init(gpregs);
		thread_info->gpregs = gpregs;

		fpregs = xmalloc(sizeof(*fpregs));
		if (!fpregs)
			goto err;
		user_x86_fpregs_entry__init(fpregs);
		thread_info->fpregs = fpregs;

		/* These are numbers from kernel */
		fpregs->n_st_space	= 32;
		fpregs->n_xmm_space	= 64;
		fpregs->n_padding	= 24;

		fpregs->st_space	= xzalloc(pb_repeated_size(fpregs, st_space));
		fpregs->xmm_space	= xzalloc(pb_repeated_size(fpregs, xmm_space));
		fpregs->padding		= xzalloc(pb_repeated_size(fpregs, padding));

		if (!fpregs->st_space || !fpregs->xmm_space || !fpregs->padding)
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

	if (alloc_ids) {
		ids = xmalloc(sizeof(*ids));
		if (!ids)
			goto err;
		task_kobj_ids_entry__init(ids);
		core->ids = ids;
	}

	return core;
err:
	core_entry_free(core);
	return NULL;
}

static int dump_task_core_all(pid_t pid, const struct proc_pid_stat *stat,
		const struct parasite_dump_misc *misc, const struct parasite_ctl *ctl,
		const struct cr_fdset *cr_fdset)
{
	int fd_core = fdset_fd(cr_fdset, CR_FD_CORE);
	CoreEntry *core;
	int ret = -1;

	core = core_entry_alloc(1, 1, 1);
	if (!core)
		return -1;

	pr_info("\n");
	pr_info("Dumping core (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	ret = dump_task_kobj_ids(pid, core);
	if (ret)
		goto err_free;

	ret = dump_task_mm(pid, stat, misc, cr_fdset);
	if (ret)
		goto err_free;

	ret = get_task_regs(pid, core, ctl);
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

	ret = pb_write(fd_core, core, core_entry);
	if (ret < 0) {
		pr_info("ERROR\n");
		goto err_free;
	} else
		pr_info("OK\n");

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

static int parse_children(const struct pstree_item *item, u32 **_c, int *_n)
{
	FILE *file;
	char *tok;
	u32 *ch = NULL;
	int nr = 1, i;

	for (i = 0; i < item->nr_threads; i++) {
		file = fopen_proc(item->pid.real, "task/%d/children",
						item->threads[i].real);
		if (!file)
			goto err;

		if (!(fgets(loc_buf, sizeof(loc_buf), file)))
			loc_buf[0] = 0;

		fclose(file);

		tok = strtok(loc_buf, " \n");
		while (tok) {
			u32 *tmp = xrealloc(ch, nr * sizeof(u32));
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

	return 0;

err:
	xfree(ch);
	return -1;
}

static int get_children(struct pstree_item *item)
{
	u32 *ch;
	int ret, i, nr_children;
	struct pstree_item *c;

	ret = parse_children(item, &ch, &nr_children);
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
		list_add_tail(&c->list, &item->children);
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
	u32 *ch;
	int nr, ret, i;
	struct pstree_item *child;

	ret = parse_children(item, &ch, &nr);
	if (ret < 0)
		return ret;

	i = 0;
	list_for_each_entry(child, &item->children, list) {
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

	list_for_each_entry(child, &item->children, list) {
		ret = collect_subtree(child);
		if (ret < 0)
			return -1;
	}

	if (check_subtree(item))
		return -1;

	return 0;
}

static int collect_pstree(pid_t pid, const struct cr_options *opts)
{
	int ret, attempts = 5;

	while (1) {
		root_item = alloc_pstree_item();
		if (root_item == NULL)
			return -1;

		root_item->pid.real = pid;
		INIT_LIST_HEAD(&root_item->list);

		ret = collect_subtree(root_item);
		if (ret == 0) {
			/*
			 * Some tasks could have been reparented to
			 * namespaces' reaper. Check this.
			 */
			if (opts->namespaces_flags & CLONE_NEWPID)
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
		if (attempts == 0)
			break;

		attempts--;
		pr_info("Trying to suspend tasks again\n");

		pstree_switch_state(root_item, TASK_ALIVE);
		free_pstree(root_item);
	}

	return ret;
}

static int dump_task_thread(struct parasite_ctl *parasite_ctl, struct pid *tid)
{
	CoreEntry *core;
	int ret = -1, fd_core;
	unsigned int *taddr;
	pid_t pid = tid->real;

	pr_info("\n");
	pr_info("Dumping core for thread (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	core = core_entry_alloc(1, 0, 0);
	if (!core)
		goto err;

	ret = get_task_regs(pid, core, NULL);
	if (ret)
		goto err_free;

	ret = parasite_dump_thread_seized(parasite_ctl, pid, &taddr, &tid->virt);
	if (ret) {
		pr_err("Can't dump tid address for pid %d", pid);
		goto err_free;
	}

	pr_info("%d: tid_address=%p\n", pid, taddr);
	core->thread_info->clear_tid_addr = (u64) taddr;

	pr_info("OK\n");

	fd_core = open_image(CR_FD_CORE, O_DUMP, tid->virt);
	if (fd_core < 0)
		goto err_free;

	ret = pb_write(fd_core, core, core_entry);

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

	core = core_entry_alloc(0, 1, 0);
	if (core == NULL)
		goto err;

	core->tc->task_state = TASK_DEAD;
	core->tc->exit_code = pps->exit_code;

	fd_core = open_image(CR_FD_CORE, O_DUMP, item->pid);
	if (fd_core < 0)
		goto err_free;

	ret = pb_write(fd_core, core, core_entry);
	close(fd_core);
err_free:
	core_entry_free(core);
err:
	return ret;
}

static struct proc_pid_stat pps_buf;

static int dump_task_threads(struct parasite_ctl *parasite_ctl,
			     const struct pstree_item *item)
{
	int i;

	for (i = 0; i < item->nr_threads; i++) {
		/* Leader is already dumped */
		if (item->pid.real == item->threads[i].real) {
			item->threads[i].virt = item->pid.virt;
			continue;
		}

		if (dump_task_thread(parasite_ctl, &item->threads[i]))
			return -1;
	}

	return 0;
}

static int dump_one_task(struct pstree_item *item)
{
	pid_t pid = item->pid.real;
	LIST_HEAD(vma_area_list);
	struct parasite_ctl *parasite_ctl;
	int ret = -1;
	struct parasite_dump_misc misc;
	struct cr_fdset *cr_fdset = NULL;

	int nr_fds = PARASITE_MAX_FDS;
	int *fds = NULL;

	pr_info("========================================\n");
	pr_info("Dumping task (pid: %d)\n", pid);
	pr_info("========================================\n");

	fds = xmalloc(nr_fds * sizeof(int));
	if (!fds)
		goto err_free;

	if (item->state == TASK_STOPPED) {
		pr_err("Stopped tasks are not supported\n");
		goto err_free;
	}

	pr_info("Obtainting task stat ... ");
	ret = parse_pid_stat(pid, &pps_buf);
	if (ret < 0)
		goto err;

	if (item->state == TASK_DEAD) {
		/* FIXME don't support zombie in pid name space*/
		if (root_item->pid.virt == 1) {
			pr_err("Can't dump a zombie %d in PIDNS", item->pid.real);
			ret = -1;
			goto err;
		}
		item->pid.virt = item->pid.real;

		BUG_ON(!list_empty(&item->children));
		return dump_one_zombie(item, &pps_buf);
	}

	ret = collect_mappings(pid, &vma_area_list);
	if (ret) {
		pr_err("Collect mappings (pid: %d) failed with %d\n", pid, ret);
		goto err;
	}

	ret = collect_fds(pid, fds, &nr_fds);
	if (ret) {
		pr_err("Collect fds (pid: %d) failed with %d\n", pid, ret);
		goto err;
	}

	parasite_ctl = parasite_infect_seized(pid, &vma_area_list);
	if (!parasite_ctl) {
		ret = -1;
		pr_err("Can't infect (pid: %d) with parasite\n", pid);
		goto err;
	}

	ret = parasite_dump_misc_seized(parasite_ctl, &misc);
	if (ret) {
		pr_err("Can't dump misc (pid: %d)\n", pid);
		goto err_cure_fdset;
	}

	item->pid.virt = misc.pid;
	item->sid = misc.sid;
	item->pgid = misc.pgid;

	ret = -1;
	cr_fdset = cr_task_fdset_open(item->pid.virt, O_DUMP);
	if (!cr_fdset)
		goto err_cure;

	ret = dump_task_files_seized(parasite_ctl, cr_fdset, fds, nr_fds);
	if (ret) {
		pr_err("Dump files (pid: %d) failed with %d\n", pid, ret);
		goto err_cure;
	}

	ret = parasite_dump_pages_seized(parasite_ctl, &vma_area_list, cr_fdset);
	if (ret) {
		pr_err("Can't dump pages (pid: %d) with parasite\n", pid);
		goto err_cure;
	}

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

	ret = dump_task_core_all(pid, &pps_buf, &misc, parasite_ctl, cr_fdset);
	if (ret) {
		pr_err("Dump core (pid: %d) failed with %d\n", pid, ret);
		goto err_cure;
	}

	ret = dump_task_threads(parasite_ctl, item);
	if (ret) {
		pr_err("Can't dump threads\n");
		goto err_cure;
	}

	ret = parasite_cure_seized(parasite_ctl);
	if (ret) {
		pr_err("Can't cure (pid: %d) from parasite\n", pid);
		goto err;
	}

	ret = dump_task_mappings(pid, &vma_area_list, cr_fdset);
	if (ret) {
		pr_err("Dump mappings (pid: %d) failed with %d\n", pid, ret);
		goto err;
	}

	ret = dump_task_creds(pid, &misc, cr_fdset);
	if (ret) {
		pr_err("Dump creds (pid: %d) failed with %d\n", pid, ret);
		goto err;
	}

	ret = dump_task_fs(pid, cr_fdset);
	if (ret) {
		pr_err("Dump fs (pid: %d) failed with %d\n", pid, ret);
		goto err;
	}

	close_cr_fdset(&cr_fdset);
err:
	close_pid_proc();
err_free:
	free_mappings(&vma_area_list);
	xfree(fds);
	return ret;

err_cure:
	close_cr_fdset(&cr_fdset);
err_cure_fdset:
	parasite_cure_seized(parasite_ctl);
	goto err;
}

int cr_dump_tasks(pid_t pid, const struct cr_options *opts)
{
	struct pstree_item *item;
	int ret = -1;

	pr_info("========================================\n");
	pr_info("Dumping processes (pid: %d)\n", pid);
	pr_info("========================================\n");

	if (write_img_inventory())
		goto err;

	if (collect_pstree(pid, opts))
		goto err;

	/*
	 * Ignore collection errors by now since we may not want
	 * to dump the missed sockets. But later, when we will start
	 * dumping containers, we'll better fail here, rather than
	 * in the dump stage
	 */

	collect_sockets();

	glob_fdset = cr_glob_fdset_open(O_DUMP);
	if (!glob_fdset)
		goto err;

	if (init_shmem_dump())
		goto err;

	for_each_pstree_item(item) {
		if (dump_one_task(item))
			goto err;
	}

	if (dump_pstree(root_item))
		goto err;

	if (opts->namespaces_flags)
		if (dump_namespaces(&root_item->pid, opts->namespaces_flags) < 0)
			goto err;

	ret = cr_dump_shmem();
	if (ret)
		goto err;

	ret = fix_external_unix_sockets();
	if (ret)
		goto err;

	fd_id_show_tree();
err:
	fini_shmem_dump();
	close_cr_fdset(&glob_fdset);

	/*
	 * If we've failed to do anything -- unlock all TCP sockets
	 * so that the connections can go on. But if we succeeded --
	 * don't, just close them silently.
	 */
	if (ret)
		tcp_unlock_all();
	pstree_switch_state(root_item,
			ret ? TASK_ALIVE : opts->final_state);
	free_pstree(root_item);

	return ret;
}
