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
#include "pipes.h"
#include "shmem.h"
#include "sk-inet.h"
#include "eventfd.h"
#include "eventpoll.h"
#include "inotify.h"

#ifndef CONFIG_X86_64
# error No x86-32 support yet
#endif

static char big_buffer[PATH_MAX];
static char loc_buf[PAGE_SIZE];

void free_pstree(struct list_head *pstree_list)
{
	struct pstree_item *item, *p;

	list_for_each_entry_safe(item, p, pstree_list, list) {
		xfree(item->children);
		xfree(item->threads);
		xfree(item);
	}

	INIT_LIST_HEAD(pstree_list);
}

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

/*
 * Ghost files are those not visible from the FS. Dumping them is
 * nasty and the only way we have -- just carry its contents with
 * us. Any brave soul to implement link unlinked file back?
 */
struct ghost_file {
	u32	dev;
	u32	ino;
	u32	id;
	struct list_head list;
};

static u32 ghost_file_ids = 1;
static LIST_HEAD(ghost_files);
/*
 * This constant is selected without any calculations. Just do not
 * want to pick up too big files with us in the image.
 */
#define MAX_GHOST_FILE_SIZE	(1 * 1024 * 1024)

static int dump_ghost_file(int _fd, u32 id, const struct stat *st)
{
	int img, fd;
	struct ghost_file_entry gfe;
	char lpath[32];

	pr_info("Dumping ghost file contents (id %#x)\n", id);

	img = open_image(CR_FD_GHOST_FILE, O_DUMP, id);
	if (img < 0)
		return -1;

	/*
	 * Reopen file locally since it may have no read
	 * permissions when drained
	 */
	snprintf(lpath, sizeof(lpath), "/proc/self/fd/%d", _fd);
	fd = open(lpath, O_RDONLY);
	if (fd < 0) {
		pr_perror("Can't open ghost original file");
		return -1;
	}

	gfe.uid = st->st_uid;
	gfe.gid = st->st_gid;
	gfe.mode = st->st_mode;

	if (write_img(img, &gfe))
		return -1;

	if (copy_file(fd, img, st->st_size))
		return -1;

	close(fd);
	close(img);
	return 0;
}

static int dump_ghost_remap(char *path, const struct stat *st, int lfd, u32 id)
{
	struct ghost_file *gf;
	struct remap_file_path_entry rpe;

	pr_info("Dumping ghost file for fd %d id %#x\n", lfd, id);

	if (st->st_size > MAX_GHOST_FILE_SIZE) {
		pr_err("Can't dump ghost file %s of %lu size\n",
				path, st->st_size);
		return -1;
	}

	list_for_each_entry(gf, &ghost_files, list)
		if ((gf->dev == st->st_dev) && (gf->ino == st->st_ino))
			goto dump_entry;

	gf = xmalloc(sizeof(*gf));
	if (gf == NULL)
		return -1;

	gf->dev = st->st_dev;
	gf->ino = st->st_ino;
	gf->id = ghost_file_ids++;
	list_add_tail(&gf->list, &ghost_files);

	if (dump_ghost_file(lfd, gf->id, st))
		return -1;

dump_entry:
	rpe.orig_id = id;
	rpe.remap_id = gf->id | REMAP_GHOST;

	return write_img(fdset_fd(glob_fdset, CR_FD_REMAP_FPATH), &rpe);
}

static int check_path_remap(char *path, const struct stat *ost, int lfd, u32 id)
{
	int ret;
	struct stat pst;

	if (ost->st_nlink == 0)
		/*
		 * Unpleasant, but easy case. File is completely invisible
		 * from the FS. Just dump its contents and that's it. But
		 * be careful whether anybody still has any of its hardlinks
		 * also open.
		 */
		return dump_ghost_remap(path, ost, lfd, id);

	ret = stat(path, &pst);
	if (ret < 0) {
		/*
		 * FIXME linked file, but path is not accessible (unless any
		 * other error occurred). We can create a temporary link to it
		 * uning linkat with AT_EMPTY_PATH flag and remap it to this
		 * name.
		 */
		pr_perror("Can't stat path");
		return -1;
	}

	if ((pst.st_ino != ost->st_ino) || (pst.st_dev != ost->st_dev)) {
		/*
		 * FIXME linked file, but the name we see it by is reused
		 * by somebody else.
		 */
		pr_err("Unaccessible path opened %u:%u, need %u:%u\n",
				(int)pst.st_dev, (int)pst.st_ino,
				(int)ost->st_dev, (int)ost->st_ino);
		return -1;
	}

	/*
	 * File is linked and visible by the name it is opened by
	 * this task. Go ahead and dump it.
	 */
	return 0;
}

static int dump_one_reg_file(int lfd, u32 id, const struct fd_parms *p)
{
	char fd_str[128];
	int len, rfd;
	struct reg_file_entry rfe;

	snprintf(fd_str, sizeof(fd_str), "/proc/self/fd/%d", lfd);
	len = readlink(fd_str, big_buffer, sizeof(big_buffer) - 1);
	if (len < 0) {
		pr_perror("Can't readlink %s", fd_str);
		return len;
	}

	big_buffer[len] = '\0';
	pr_info("Dumping path for %d fd via self %d [%s]\n",
			p->fd, lfd, big_buffer);

	if (check_path_remap(big_buffer, &p->stat, lfd, id))
		return -1;

	rfe.len = len;
	rfe.flags = p->flags;
	rfe.pos = p->pos;
	rfe.id = id;
	rfe.fown = p->fown;

	rfd = fdset_fd(glob_fdset, CR_FD_REG_FILES);

	if (write_img(rfd, &rfe))
		return -1;
	if (write_img_buf(rfd, big_buffer, len))
		return -1;

	return 0;
}

u32 make_gen_id(const struct fd_parms *p)
{
	return MAKE_FD_GENID(p->stat.st_dev, p->stat.st_ino, p->pos);
}

int do_dump_gen_file(struct fd_parms *p, int lfd,
		const struct fdtype_ops *ops, const struct cr_fdset *cr_fdset)
{
	struct fdinfo_entry e;
	int ret = -1;

	e.type	= ops->type;
	e.id	= p->id = ops->make_gen_id(p);
	e.fd	= p->fd;
	e.flags = p->fd_flags;

	ret = fd_id_generate(p->pid, &e);
	if (ret == 1) /* new ID generated */
		ret = ops->dump(lfd, e.id, p);

	if (ret < 0)
		goto err;

	pr_info("fdinfo: type: 0x%2x flags: 0x%4x pos: 0x%8lx fd: %d\n",
		ops->type, p->flags, p->pos, p->fd);

	if (write_img(fdset_fd(cr_fdset, CR_FD_FDINFO), &e))
		goto err;

	ret = 0;
err:
	return ret;
}

static const struct fdtype_ops regfile_ops = {
	.type		= FDINFO_REG,
	.make_gen_id	= make_gen_id,
	.dump		= dump_one_reg_file,
};

static int dump_reg_file(struct fd_parms *p, int lfd,
			     const struct cr_fdset *cr_fdset)
{
	return do_dump_gen_file(p, lfd, &regfile_ops, cr_fdset);
}

static int dump_task_exe_link(pid_t pid, struct mm_entry *mm)
{
	struct fd_parms params;
	int fd, ret;

	fd = open_proc(pid, "exe");
	if (fd < 0)
		return -1;

	if (fstat(fd, &params.stat) < 0) {
		pr_perror("Can't fstat exe link");
		return -1;
	}

	params.flags = 0;
	params.pos = 0;
	params.fown = (fown_t){ };
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
	p->id		= FD_ID_INVALID;
	p->fd_flags	= fd_flags;
	p->fown		= (fown_t){ };

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

	if (S_ISREG(p.stat.st_mode) ||
            S_ISDIR(p.stat.st_mode))
		return dump_reg_file(&p, lfd, cr_fdset);

	if (S_ISFIFO(p.stat.st_mode) && (statfs.f_type == PIPEFS_MAGIC))
		return dump_pipe(&p, lfd, cr_fdset);

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
	struct fd_parms p;
	struct fs_entry fe;
	int fd, ret;

	fd = open_proc(pid, "cwd");
	if (fd < 0)
		return -1;

	if (fstat(fd, &p.stat) < 0) {
		pr_perror("Can't stat cwd");
		return -1;
	}

	p.flags = 0;
	p.pos = 0;
	p.fown = (fown_t){ };
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

	p.flags = 0;
	p.pos = 0;
	fe.root_id = fd_id_generate_special();

	ret = dump_one_reg_file(fd, fe.root_id, &p);
	if (ret < 0)
		return ret;

	close(fd);

	pr_info("Dumping task cwd id %#x root id %#x\n",
			fe.cwd_id, fe.root_id);

	return write_img(fdset_fd(fdset, CR_FD_FS), &fe);
}

static int dump_filemap(pid_t pid, struct vma_entry *vma, int file_fd,
		const struct cr_fdset *fdset)
{
	struct fd_parms p;

	if (fstat(file_fd, &p.stat) < 0) {
		pr_perror("Can't stat file for vma");
		return -1;
	}

	p.pos = 0;
	p.fown = (fown_t){ };
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
		struct vma_entry *vma = &vma_area->vma;

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
			ret = write_img(fd, vma);
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
	int ret, i;
	struct proc_status_creds cr;
	struct creds_entry ce;

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

	for (i = 0; i < CR_CAP_SIZE; i++) {
		ce.cap_inh[i] = cr.cap_inh[i];
		ce.cap_prm[i] = cr.cap_prm[i];
		ce.cap_eff[i] = cr.cap_eff[i];
		ce.cap_bnd[i] = cr.cap_bnd[i];
	}

	ce.secbits = misc->secbits;

	ret = write_img(fdset_fd(fds, CR_FD_CREDS), &ce);
	if (ret < 0)
		return ret;

	return 0;
}

#define assign_reg(dst, src, e)		dst.e = (__typeof__(dst.e))src.e
#define assign_array(dst, src, e)	memcpy(&dst.e, &src.e, sizeof(dst.e))

static int get_task_auxv(pid_t pid, struct mm_entry *mm)
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
	struct mm_entry mme;

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

	if (get_task_auxv(pid, &mme))
		return -1;
	pr_info("OK\n");

	if (dump_task_exe_link(pid, &mme))
		return -1;

	return write_img(fdset_fd(fdset, CR_FD_MM), &mme);
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

static int get_task_regs(pid_t pid, struct core_entry *core, const struct parasite_ctl *ctl)
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

	assign_reg(core->arch.gpregs, regs, r15);
	assign_reg(core->arch.gpregs, regs, r14);
	assign_reg(core->arch.gpregs, regs, r13);
	assign_reg(core->arch.gpregs, regs, r12);
	assign_reg(core->arch.gpregs, regs, bp);
	assign_reg(core->arch.gpregs, regs, bx);
	assign_reg(core->arch.gpregs, regs, r11);
	assign_reg(core->arch.gpregs, regs, r10);
	assign_reg(core->arch.gpregs, regs, r9);
	assign_reg(core->arch.gpregs, regs, r8);
	assign_reg(core->arch.gpregs, regs, ax);
	assign_reg(core->arch.gpregs, regs, cx);
	assign_reg(core->arch.gpregs, regs, dx);
	assign_reg(core->arch.gpregs, regs, si);
	assign_reg(core->arch.gpregs, regs, di);
	assign_reg(core->arch.gpregs, regs, orig_ax);
	assign_reg(core->arch.gpregs, regs, ip);
	assign_reg(core->arch.gpregs, regs, cs);
	assign_reg(core->arch.gpregs, regs, flags);
	assign_reg(core->arch.gpregs, regs, sp);
	assign_reg(core->arch.gpregs, regs, ss);
	assign_reg(core->arch.gpregs, regs, fs_base);
	assign_reg(core->arch.gpregs, regs, gs_base);
	assign_reg(core->arch.gpregs, regs, ds);
	assign_reg(core->arch.gpregs, regs, es);
	assign_reg(core->arch.gpregs, regs, fs);
	assign_reg(core->arch.gpregs, regs, gs);

	assign_reg(core->arch.fpregs, fpregs, cwd);
	assign_reg(core->arch.fpregs, fpregs, swd);
	assign_reg(core->arch.fpregs, fpregs, twd);
	assign_reg(core->arch.fpregs, fpregs, fop);
	assign_reg(core->arch.fpregs, fpregs, rip);
	assign_reg(core->arch.fpregs, fpregs, rdp);
	assign_reg(core->arch.fpregs, fpregs, mxcsr);
	assign_reg(core->arch.fpregs, fpregs, mxcsr_mask);

	assign_array(core->arch.fpregs, fpregs,	st_space);
	assign_array(core->arch.fpregs, fpregs,	xmm_space);
	assign_array(core->arch.fpregs, fpregs,	padding);

	ret = 0;

err:
	return ret;
}

static int dump_task_core(struct core_entry *core, int fd_core)
{
	pr_info("Dumping header ... ");

	core->header.version	= HEADER_VERSION;
	core->header.arch	= HEADER_ARCH_X86_64;
	core->header.flags	= 0;

	return write_img(fd_core, core);
}

static DECLARE_KCMP_TREE(vm_tree, KCMP_VM);
static DECLARE_KCMP_TREE(fs_tree, KCMP_FS);
static DECLARE_KCMP_TREE(files_tree, KCMP_FILES);
static DECLARE_KCMP_TREE(sighand_tree, KCMP_SIGHAND);

static int dump_task_kobj_ids(pid_t pid, struct core_entry *core)
{
	int new;
	struct kid_elem elem;

	elem.pid = pid;
	elem.idx = 0; /* really 0 for all */
	elem.genid = 0; /* FIXME optimize */

	new = 0;
	core->ids.vm_id = kid_generate_gen(&vm_tree, &elem, &new);
	if (!core->ids.vm_id || !new) {
		pr_err("Can't make VM id for %d\n", pid);
		return -1;
	}

	new = 0;
	core->ids.fs_id = kid_generate_gen(&fs_tree, &elem, &new);
	if (!core->ids.fs_id || !new) {
		pr_err("Can't make FS id for %d\n", pid);
		return -1;
	}

	new = 0;
	core->ids.files_id = kid_generate_gen(&files_tree, &elem, &new);
	if (!core->ids.files_id || !new) {
		pr_err("Can't make FILES id for %d\n", pid);
		return -1;
	}

	new = 0;
	core->ids.sighand_id = kid_generate_gen(&sighand_tree, &elem, &new);
	if (!core->ids.sighand_id || !new) {
		pr_err("Can't make IO id for %d\n", pid);
		return -1;
	}

	return 0;
}

static int dump_task_core_all(pid_t pid, const struct proc_pid_stat *stat,
		const struct parasite_dump_misc *misc, const struct parasite_ctl *ctl,
		const struct cr_fdset *cr_fdset)
{
	struct core_entry *core;
	int ret = -1;

	pr_info("\n");
	pr_info("Dumping core (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	core = xzalloc(sizeof(*core));
	if (!core)
		goto err;

	ret = dump_task_kobj_ids(pid, core);
	if (ret)
		goto err_free;

	ret = dump_task_mm(pid, stat, misc, cr_fdset);
	if (ret)
		goto err_free;

	ret = get_task_regs(pid, core, ctl);
	if (ret)
		goto err_free;

	ret = get_task_personality(pid, &core->tc.personality);
	if (ret)
		goto err_free;

	strncpy((char *)core->tc.comm, stat->comm, TASK_COMM_LEN);
	core->tc.flags = stat->flags;
	BUILD_BUG_ON(sizeof(core->tc.blk_sigset) != sizeof(k_rtsigset_t));
	memcpy(&core->tc.blk_sigset, &misc->blocked, sizeof(k_rtsigset_t));

	core->tc.task_state = TASK_ALIVE;
	core->tc.exit_code = 0;

	ret = dump_task_core(core, fdset_fd(cr_fdset, CR_FD_CORE));
	if (ret)
		goto err_free;
	pr_info("OK\n");

err_free:
	free(core);
err:
	pr_info("----------------------------------------\n");

	return ret;
}

static int parse_threads(const struct pstree_item *item, u32 **_t, int *_n)
{
	struct dirent *de;
	DIR *dir;
	u32 *t = NULL;
	int nr = 1;

	dir = opendir_proc(item->pid, "task");
	if (!dir)
		return -1;

	while ((de = readdir(dir))) {
		u32 *tmp;

		/* We expect numbers only here */
		if (de->d_name[0] == '.')
			continue;

		tmp = xrealloc(t, nr * sizeof(u32));
		if (!tmp) {
			xfree(t);
			return -1;
		}
		t = tmp;
		t[nr - 1] = atoi(de->d_name);
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
	u32 *t;
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

		file = fopen_proc(item->pid, "task/%d/children", item->threads[i]);
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
	return parse_children(item, &item->children, &item->nr_children);
}

static void unseize_task_and_threads(const struct pstree_item *item, int st)
{
	int i;

	for (i = 0; i < item->nr_threads; i++)
		unseize_task(item->threads[i], st); /* item->pid will be here */
}

static void pstree_switch_state(const struct list_head *list, int st)
{
	struct pstree_item *item;

	pr_info("Unfreezing tasks into %d\n", st);
	list_for_each_entry(item, list, list)
		unseize_task_and_threads(item, st);
}

static pid_t item_ppid(const struct pstree_item *item)
{
	item = item->parent;
	return item ? item->pid : -1;
}

static int seize_threads(const struct pstree_item *item)
{
	int i = 0, ret;

	if ((item->state == TASK_DEAD) && (item->nr_threads > 1)) {
		pr_err("Zombies with threads are not supported\n");
		goto err;
	}

	for (i = 0; i < item->nr_threads; i++) {
		if (item->pid == item->threads[i])
			continue;

		pr_info("\tSeizing %d's %d thread\n", item->pid, item->threads[i]);
		ret = seize_task(item->threads[i], item_ppid(item), NULL, NULL);
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
		if (item->pid == item->threads[i])
			continue;

		unseize_task(item->threads[i], TASK_ALIVE);
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

/*
 * Few words about sid and pgid handling.
 *
 * An axiom: session can only be changed on self, group -- on self or
 * on one of self children.
 *
 * Conclusions:
 * 1. both should better be saved in pstree.img so we can restore sid
 *    at the time we fork kids and pgid is just for harmony;
 * 2. if we seized the parent these IDs* shouldn't change and it's safe
 *    to read and check them right at the seizing time.
 * 
 * Easings:
 * 1. with the existing setsid we can only reset sid to task's pid.
 *    Thus, if task escaped from its ancestors with sid we will not be
 *    able to easily restore this construction. Thus for now this is
 *    treated as "unsupported" (FIXME);
 *
 * 2. when task whose pid is equal to pgid/sid (i.e. leader) exits we
 *    lose the ability to restore the grp/session easily with the 
 *    existing interfaces, thus we also treat this as temporarily
 *    unsupported (FIXME #2).
 */

static int check_xids(struct list_head *list)
{
	struct pstree_item *p, *tmp;

	list_for_each_entry(p, list, list) {
		if (p->parent == NULL)
			continue;

		/* Easing #1 and #2 for sids */
		if ((p->sid != p->pid) && (p->sid != p->parent->sid)) {
			pr_err("SID mismatch on %d (%d/%d)\n",
					p->pid, p->sid, p->parent->sid);
			return -1;
		}

		/* Easing #2 for pgids */
		list_for_each_entry(tmp, list, list)
			if (tmp->pid == p->pgid)
				break;

		if (&tmp->list == list) {
			pr_err("PGIG mismatch on %d (%d)\n",
					p->pid, p->pgid);
			return -1;
		}
	}
	return 0;
}

static struct pstree_item *collect_task(pid_t pid, struct pstree_item *parent,
		struct list_head *list)
{
	int ret;
	struct pstree_item *item;

	item = xzalloc(sizeof(*item));
	if (!item)
		goto err;

	item->pid = pid;
	item->parent = parent;

	ret = seize_task(pid, item_ppid(item), &item->pgid, &item->sid);
	if (ret < 0)
		goto err_free;

	pr_info("Seized task %d, state %d\n", pid, ret);
	item->state = ret;

	ret = collect_threads(item);
	if (ret < 0)
		goto err_close;

	ret = get_children(item);
	if (ret < 0)
		goto err_close;

	if ((item->state == TASK_DEAD) && (item->nr_children > 0)) {
		pr_err("Zombie with children?! O_o Run, run, run!\n");
		goto err_close;
	}

	close_pid_proc();
	list_add_tail(&item->list, list);
	pr_info("Collected %d in %d state\n", item->pid, item->state);
	return item;

err_close:
	close_pid_proc();
	unseize_task(pid, item->state);
err_free:
	xfree(item->children);
	xfree(item->threads);
	xfree(item);
err:
	return NULL;
}

static int check_subtree(const struct pstree_item *item)
{
	u32 *ch;
	int nr, ret;

	ret = parse_children(item, &ch, &nr);
	if (ret < 0)
		return ret;

	ret = ((nr == item->nr_children) && !memcmp(ch, item->children, nr));
	xfree(ch);

	if (!ret) {
		pr_info("Children set has changed while suspending\n");
		return -1;
	}

	return 0;
}

static int collect_subtree(pid_t pid, struct pstree_item *parent,
		struct list_head *pstree_list, int leader_only)
{
	struct pstree_item *item;
	int i;

	pr_info("Collecting tasks starting from %d\n", pid);
	item = collect_task(pid, parent, pstree_list);
	if (item == NULL)
		return -1;

	if (leader_only)
		return 0;

	for (i = 0; i < item->nr_children; i++)
		if (collect_subtree(item->children[i], item, pstree_list, 0) < 0)
			return -1;

	if (check_subtree(item))
		return -1;

	return 0;
}

static int dump_pstree(pid_t pid, const struct list_head *pstree_list);

static int collect_dump_pstree(pid_t pid, struct list_head *pstree_list,
			  const struct cr_options *opts)
{
	int ret, attempts = 5;

	while (1) {
		struct pstree_item *item;

		ret = collect_subtree(pid, NULL, pstree_list, opts->leader_only);
		if (ret == 0) {
			/*
			 * Some tasks could have been reparented to
			 * namespaces' reaper. Check this.
			 */
			if (opts->namespaces_flags & CLONE_NEWPID) {
				item = list_first_entry(pstree_list,
						struct pstree_item, list);
				BUG_ON(item->pid != 1);

				if (check_subtree(item))
					goto try_again;
			}

			break;
		}

		if (list_empty(pstree_list))
			/*
			 * No items at all -- no need in re-scanning it again
			 */
			break;

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

		while (!list_empty(pstree_list)) {
			item = list_first_entry(pstree_list,
					struct pstree_item, list);
			list_del(&item->list);

			unseize_task_and_threads(item, TASK_ALIVE);

			xfree(item->children);
			xfree(item->threads);
			xfree(item);
		}
	}

	if (!ret)
		ret = check_xids(pstree_list);

	if (ret)
		return ret;

	return dump_pstree(pid, pstree_list);
}

static int dump_pstree(pid_t pid, const struct list_head *pstree_list)
{
	const struct pstree_item *item;
	struct pstree_entry e;
	int ret = -1;
	int pstree_fd;

	pr_info("\n");
	pr_info("Dumping pstree (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	pstree_fd = open_image(CR_FD_PSTREE, O_DUMP);
	if (pstree_fd < 0)
		return -1;

	list_for_each_entry(item, pstree_list, list) {

		pr_info("Process: %d (%d children)\n",
			item->pid, item->nr_children);

		e.pid		= item->pid;
		e.pgid		= item->pgid;
		e.sid		= item->sid;
		e.nr_children	= item->nr_children;
		e.nr_threads	= item->nr_threads;

		if (write_img(pstree_fd, &e))
			goto err;

		if (write_img_buf(pstree_fd, item->children,
					item->nr_children * sizeof(u32)))
			goto err;

		if (write_img_buf(pstree_fd, item->threads,
					item->nr_threads * sizeof(u32)))
			goto err;
	}
	ret = 0;

err:
	pr_info("----------------------------------------\n");
	close(pstree_fd);
	return ret;
}

static int dump_task_thread(struct parasite_ctl *parasite_ctl, pid_t pid)
{
	struct core_entry *core;
	int ret = -1, fd_core;
	unsigned int *taddr;

	pr_info("\n");
	pr_info("Dumping core for thread (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	core = xzalloc(sizeof(*core));
	if (!core)
		goto err;

	ret = get_task_regs(pid, core, NULL);
	if (ret)
		goto err_free;

	ret = parasite_dump_tid_addr_seized(parasite_ctl, pid, &taddr);
	if (ret) {
		pr_err("Can't dump tid address for pid %d", pid);
		goto err_free;
	}

	pr_info("%d: tid_address=%p\n", pid, taddr);
	core->clear_tid_address = (u64) taddr;

	pr_info("OK\n");

	core->tc.task_state = TASK_ALIVE;
	core->tc.exit_code = 0;

	fd_core = open_image(CR_FD_CORE, O_DUMP, pid);
	if (fd_core < 0)
		goto err_free;

	ret = dump_task_core(core, fd_core);

	close(fd_core);
err_free:
	free(core);
err:
	pr_info("----------------------------------------\n");
	return ret;
}

static int dump_one_zombie(const struct pstree_item *item,
			   const struct proc_pid_stat *pps)
{
	struct core_entry *core;
	int ret = -1, fd_core;

	core = xzalloc(sizeof(*core));
	if (core == NULL)
		goto err;

	core->tc.task_state = TASK_DEAD;
	core->tc.exit_code = pps->exit_code;

	fd_core = open_image(CR_FD_CORE, O_DUMP, item->pid);
	if (fd_core < 0)
		goto err_free;

	ret = dump_task_core(core, fd_core);
	close(fd_core);
err_free:
	xfree(core);
err:
	return ret;
}

static struct proc_pid_stat pps_buf;

static int dump_task_threads(struct parasite_ctl *parasite_ctl,
			     const struct pstree_item *item)
{
	int i;

	if (item->nr_threads == 1)
		return 0;

	for (i = 0; i < item->nr_threads; i++) {
		/* Leader is already dumped */
		if (item->pid == item->threads[i])
			continue;

		if (dump_task_thread(parasite_ctl, item->threads[i]))
			return -1;
	}

	return 0;
}

static int dump_one_task(const struct pstree_item *item)
{
	pid_t pid = item->pid;
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

	if (item->state == TASK_DEAD)
		return dump_one_zombie(item, &pps_buf);

	ret = -1;
	cr_fdset = cr_task_fdset_open(item->pid, O_DUMP);
	if (!cr_fdset)
		goto err;

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

	ret = parasite_dump_misc_seized(parasite_ctl, &misc);
	if (ret) {
		pr_err("Can't dump misc (pid: %d)\n", pid);
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

err:
	close_cr_fdset(&cr_fdset);
	close_pid_proc();
err_free:
	free_mappings(&vma_area_list);
	xfree(fds);
	return ret;

err_cure:
	parasite_cure_seized(parasite_ctl);
	goto err;
}

int cr_dump_tasks(pid_t pid, const struct cr_options *opts)
{
	LIST_HEAD(pstree_list);
	struct pstree_item *item;
	int ret = -1;

	pr_info("========================================\n");
	pr_info("Dumping process %s(pid: %d)\n", !opts->leader_only ? "group " : "", pid);
	pr_info("========================================\n");

	if (collect_dump_pstree(pid, &pstree_list, opts))
		goto err;

	if (opts->namespaces_flags) {
		if (dump_namespaces(pid, opts->namespaces_flags) < 0)
			goto err;
	}

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

	if (init_pipes_dump())
		goto err;

	list_for_each_entry(item, &pstree_list, list) {
		if (dump_one_task(item))
			goto err;

		if (opts->leader_only)
			break;
	}

	ret = cr_dump_shmem();
	if (ret)
		goto err;

	ret = fix_external_unix_sockets();
	if (ret)
		goto err;

	fd_id_show_tree();
err:
	fini_shmem_dump();
	fini_pipes_dump();
	close_cr_fdset(&glob_fdset);

	/*
	 * If we've failed to do anything -- unlock all TCP sockets
	 * so that the connections can go on. But if we succeeded --
	 * don't, just close them silently.
	 */
	if (ret)
		tcp_unlock_all();
	pstree_switch_state(&pstree_list, 
			ret ? TASK_ALIVE : opts->final_state);
	free_pstree(&pstree_list);

	return ret;
}
