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

#include "compiler.h"
#include "crtools.h"
#include "syscall.h"
#include "ptrace.h"
#include "util.h"
#include "sockets.h"
#include "namespaces.h"
#include "image.h"
#include "proc_parse.h"
#include "parasite-syscall.h"

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

	ret = parse_maps(pid, vma_area_list, true);
	if (ret)
		goto err;

	pr_info_vma_list(vma_area_list);

	pr_info("----------------------------------------\n");

err:
	return ret;
}

struct fd_parms {
	unsigned long	fd_name;
	unsigned long	pos;
	unsigned int	flags;
	char		*id;
};

static int dump_one_reg_file(int type, struct fd_parms *p, int lfd,
			     struct cr_fdset *cr_fdset,
			     bool do_close_lfd)
{
	struct fdinfo_entry e;
	char fd_str[128];
	int len;
	int ret = -1;

	snprintf(fd_str, sizeof(fd_str), "/proc/self/fd/%d", lfd);
	len = readlink(fd_str, big_buffer, sizeof(big_buffer) - 1);
	if (len < 0) {
		pr_perror("Can't readlink %s", fd_str);
		goto err;
	}

	big_buffer[len] = '\0';
	pr_info("Dumping path for %lx fd via self %d [%s]\n",
		p->fd_name, lfd, big_buffer);

	if (do_close_lfd)
		close(lfd);

	e.type	= type;
	e.len	= len;
	e.flags = p->flags;
	e.pos	= p->pos;
	e.addr	= p->fd_name;
	if (p->id)
		memcpy(e.id, p->id, FD_ID_SIZE);
	else
		memzero(e.id, FD_ID_SIZE);

	pr_info("fdinfo: type: %2x len: %2x flags: %4x pos: %8lx addr: %16lx\n",
		type, len, p->flags, p->pos, p->fd_name);

	if (write_img(cr_fdset->fds[CR_FD_FDINFO], &e))
		goto err;
	if (write_img_buf(cr_fdset->fds[CR_FD_FDINFO], big_buffer, e.len))
		goto err;

	ret = 0;
err:
	return ret;
}

static int dump_task_special_files(pid_t pid, struct cr_fdset *cr_fdset)
{
	struct fd_parms params;
	int fd, ret;

	/* Dump /proc/pid/cwd */
	params = (struct fd_parms){ .fd_name = FDINFO_CWD, };
	fd = open_proc(pid, "cwd");
	if (fd < 0)
		return -1;
	ret = dump_one_reg_file(FDINFO_FD, &params, fd, cr_fdset, 1);
	if (ret)
		return ret;

	/* Dump /proc/pid/exe */
	params = (struct fd_parms){ .fd_name = FDINFO_EXE, };
	fd = open_proc(pid, "exe");
	if (fd < 0)
		return -1;
	ret = dump_one_reg_file(FDINFO_FD, &params, fd, cr_fdset, 1);

	return ret;
}

static int dump_pipe_and_data(int lfd, struct pipe_entry *e,
			      struct cr_fdset *cr_fdset)
{
	int fd_pipes;
	int steal_pipe[2];
	int pipe_size;
	int has_bytes;
	int ret = -1;

	fd_pipes = cr_fdset->fds[CR_FD_PIPES];

	pr_info("Dumping data from pipe %x\n", e->pipeid);
	if (pipe(steal_pipe) < 0) {
		pr_perror("Can't create pipe for stealing data");
		goto err;
	}

	pipe_size = fcntl(lfd, F_GETPIPE_SZ);
	if (pipe_size < 0) {
		pr_err("Can't obtain piped data size\n");
		goto err;
	}

	has_bytes = tee(lfd, steal_pipe[1], pipe_size, SPLICE_F_NONBLOCK);
	if (has_bytes < 0) {
		if (errno != EAGAIN) {
			pr_perror("Can't pick pipe data");
			goto err_close;
		} else
			has_bytes = 0;
	}

	e->bytes = has_bytes;
	if (write_img(fd_pipes, e))
		goto err_close;

	if (has_bytes) {
		ret = splice(steal_pipe[0], NULL, fd_pipes,
			     NULL, has_bytes, 0);
		if (ret < 0) {
			pr_perror("Can't push pipe data");
			goto err_close;
		}
	}

	ret = 0;

err_close:
	close(steal_pipe[0]);
	close(steal_pipe[1]);

err:
	return ret;
}

static int dump_one_pipe(struct fd_parms *p, unsigned int id, int lfd,
		struct cr_fdset *cr_fdset)
{
	struct pipe_entry e;
	int ret = -1;

	pr_info("Dumping pipe %ld/%x flags %x\n", p->fd_name, id, p->flags);

	e.fd		= p->fd_name;
	e.pipeid	= id;
	e.flags		= p->flags;

	if (p->flags & O_WRONLY) {
		e.bytes = 0;
		ret = write_img(cr_fdset->fds[CR_FD_PIPES], &e);
	} else
		ret = dump_pipe_and_data(lfd, &e, cr_fdset);

err:
	if (!ret)
		pr_info("Dumped pipe: fd: %8x pipeid: %8x flags: %8x bytes: %8x\n",
			e.fd, e.pipeid, e.flags, e.bytes);
	else
		pr_err("Dumping pipe %ld/%x flags %x\n", p->fd_name, id, p->flags);

	return ret;
}

static int dump_one_fd(pid_t pid, int pid_fd_dir, int lfd,
		       struct fd_parms *p, struct cr_fdset *cr_fdset)
{
	struct statfs stfs_buf;
	struct stat st_buf;
	int err = -1;

	if (lfd < 0) {
		err = try_dump_socket(pid, p->fd_name, cr_fdset);
		if (err != 1)
			return err;

		pr_perror("Failed to open %d/%ld", pid_fd_dir, p->fd_name);
		return -1;
	}

	if (fstat(lfd, &st_buf) < 0) {
		pr_perror("Can't get stat on %ld", p->fd_name);
		goto out_close;
	}

	if (S_ISCHR(st_buf.st_mode) &&
	    (major(st_buf.st_rdev) == TTY_MAJOR ||
	     major(st_buf.st_rdev) == UNIX98_PTY_SLAVE_MAJOR)) {
		/* skip only standard destriptors */
		if (p->fd_name < 3) {
			err = 0;
			pr_info("... Skipping tty ... %d/%ld\n",
				pid_fd_dir, p->fd_name);
			goto out_close;
		}
		goto err;
	}

	if (S_ISREG(st_buf.st_mode) ||
	    S_ISDIR(st_buf.st_mode) ||
	    (S_ISCHR(st_buf.st_mode) && major(st_buf.st_rdev) == MEM_MAJOR))
		return dump_one_reg_file(FDINFO_FD, p, lfd, cr_fdset, 1);

	if (S_ISFIFO(st_buf.st_mode)) {
		if (fstatfs(lfd, &stfs_buf) < 0) {
			pr_perror("Can't fstatfs on %ld", p->fd_name);
			return -1;
		}

		if (stfs_buf.f_type == PIPEFS_MAGIC)
			return dump_one_pipe(p, st_buf.st_ino, lfd, cr_fdset);
	}

err:
	pr_err("Can't dump file %ld of that type [%x]\n", p->fd_name, st_buf.st_mode);

out_close:
	close_safe(&lfd);
	return err;
}

static int read_fd_params(pid_t pid, char *fd, struct fd_parms *p)
{
	FILE *file;
	int ret;

	file = fopen_proc(pid, "fdinfo/%s", fd);
	if (!file)
		return -1;

	p->fd_name = atoi(fd);
	ret = fscanf(file, "pos:\t%li\nflags:\t%o\nid:\t%s\n", &p->pos, &p->flags, p->id);
	fclose(file);

	if (ret != 3) {
		pr_err("Bad format of fdinfo file (%d items, want 3)\n", ret);
		return -1;
	}

	pr_info("%d fdinfo %s: pos: %16lx flags: %16o id %s\n",
		pid, fd, p->pos, p->flags, p->id);

	return 0;
}

static int dump_task_files(pid_t pid, struct cr_fdset *cr_fdset)
{
	struct dirent *de;
	unsigned long pos;
	unsigned int flags;
	DIR *fd_dir;

	pr_info("\n");
	pr_info("Dumping opened files (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	/*
	 * Dump special files at the beginning. We might need
	 * to re-read them in restorer, so better to make it
	 * fast.
	 */
	if (dump_task_special_files(pid, cr_fdset)) {
		pr_err("Can't dump special files\n");
		return -1;
	}

	fd_dir = opendir_proc(pid, "fd");
	if (!fd_dir)
		return -1;

	while ((de = readdir(fd_dir))) {
		char id[FD_ID_SIZE];
		struct fd_parms p = { .id = id };
		int lfd;

		if (de->d_name[0] == '.')
			continue;
		if (read_fd_params(pid, de->d_name, &p))
			return -1;

		lfd = openat(dirfd(fd_dir), de->d_name, O_RDONLY);
		if (dump_one_fd(pid, dirfd(fd_dir), lfd, &p, cr_fdset))
			return -1;
	}

	pr_info("----------------------------------------\n");

	closedir(fd_dir);
	return 0;
}

static int dump_task_mappings(pid_t pid, struct list_head *vma_area_list, struct cr_fdset *cr_fdset)
{
	struct vma_area *vma_area;
	int ret = -1;

	pr_info("\n");
	pr_info("Dumping mappings (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	list_for_each_entry(vma_area, vma_area_list, list) {

		struct vma_entry *vma = &vma_area->vma;

		if (!vma_entry_is(vma, VMA_AREA_REGULAR))
			continue;

		pr_info_vma(vma_area);

		if (vma->flags & (MAP_SHARED | MAP_PRIVATE)) {

			if (vma_entry_is(vma, VMA_ANON_SHARED)) {
				struct shmem_entry e;

				e.start	= vma->start;
				e.end	= vma->end;
				e.shmid	= vma_area->shmid;

				pr_info("shmem: s: %16lx e: %16lx shmid: %16lx\n",
					e.start, e.end, e.shmid);

				if (write_img(cr_fdset->fds[CR_FD_SHMEM], &e))
					goto err;
			} else if (vma_entry_is(vma, VMA_FILE_PRIVATE) ||
				   vma_entry_is(vma, VMA_FILE_SHARED)) {
				struct fd_parms p = {
					.fd_name = vma->start,
					.pos = 0,
					.id = NULL,
				};

				if (vma->prot & PROT_WRITE &&
				    vma_entry_is(vma, VMA_FILE_SHARED))
					p.flags = O_RDWR;
				else
					p.flags = O_RDONLY;

				ret = dump_one_reg_file(FDINFO_MAP, &p, vma_area->vm_file_fd, cr_fdset, 0);
				if (ret)
					goto err;
			}
		} else {
			pr_panic("Unknown VMA (pid: %d)\n", pid);
			goto err;
		}
	}

	ret = 0;

	pr_info("----------------------------------------\n");

err:
	return ret;
}

static int dump_task_creds(pid_t pid,
		struct parasite_dump_misc *misc, struct cr_fdset *fds)
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

	ret = write_img(fds->fds[CR_FD_CREDS], &ce);
	if (ret < 0)
		return ret;

	return 0;
}

#define assign_reg(dst, src, e)		dst.e = (__typeof__(dst.e))src.e
#define assign_array(dst, src, e)	memcpy(&dst.e, &src.e, sizeof(dst.e))

static int get_task_auxv(pid_t pid, struct core_entry *core)
{
	int fd = open_proc(pid, "auxv");
	int ret, i;

	if (fd < 0)
		return -1;

	for (i = 0; i < AT_VECTOR_SIZE; i++) {
		ret = read(fd, &core->tc.mm_saved_auxv[i],
			   sizeof(core->tc.mm_saved_auxv[0]));
		if (ret == 0)
			break;
		else if (ret != sizeof(core->tc.mm_saved_auxv[0])) {
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

static int get_task_personality(pid_t pid, u32 *personality)
{
	FILE *file = NULL;
	int ret = -1;

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

static int get_task_regs(pid_t pid, struct core_entry *core, struct parasite_ctl *ctl)
{
	user_fpregs_struct_t fpregs	= {-1};
	user_regs_struct_t regs		= {-1};
	int ret = -1;

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

	assign_reg(core->arch.gpregs, regs,		r15);
	assign_reg(core->arch.gpregs, regs,		r14);
	assign_reg(core->arch.gpregs, regs,		r13);
	assign_reg(core->arch.gpregs, regs,		r12);
	assign_reg(core->arch.gpregs, regs,		bp);
	assign_reg(core->arch.gpregs, regs,		bx);
	assign_reg(core->arch.gpregs, regs,		r11);
	assign_reg(core->arch.gpregs, regs,		r10);
	assign_reg(core->arch.gpregs, regs,		r9);
	assign_reg(core->arch.gpregs, regs,		r8);
	assign_reg(core->arch.gpregs, regs,		ax);
	assign_reg(core->arch.gpregs, regs,		cx);
	assign_reg(core->arch.gpregs, regs,		dx);
	assign_reg(core->arch.gpregs, regs,		si);
	assign_reg(core->arch.gpregs, regs,		di);
	assign_reg(core->arch.gpregs, regs,		orig_ax);
	assign_reg(core->arch.gpregs, regs,		ip);
	assign_reg(core->arch.gpregs, regs,		cs);
	assign_reg(core->arch.gpregs, regs,		flags);
	assign_reg(core->arch.gpregs, regs,		sp);
	assign_reg(core->arch.gpregs, regs,		ss);
	assign_reg(core->arch.gpregs, regs,		fs_base);
	assign_reg(core->arch.gpregs, regs,		gs_base);
	assign_reg(core->arch.gpregs, regs,		ds);
	assign_reg(core->arch.gpregs, regs,		es);
	assign_reg(core->arch.gpregs, regs,		fs);
	assign_reg(core->arch.gpregs, regs,		gs);

	assign_reg(core->arch.fpregs, fpregs,		cwd);
	assign_reg(core->arch.fpregs, fpregs,		swd);
	assign_reg(core->arch.fpregs, fpregs,		twd);
	assign_reg(core->arch.fpregs, fpregs,		fop);
	assign_reg(core->arch.fpregs, fpregs,		rip);
	assign_reg(core->arch.fpregs, fpregs,		rdp);
	assign_reg(core->arch.fpregs, fpregs,		mxcsr);
	assign_reg(core->arch.fpregs, fpregs,		mxcsr_mask);

	assign_array(core->arch.fpregs, fpregs,	st_space);
	assign_array(core->arch.fpregs, fpregs,	xmm_space);
	assign_array(core->arch.fpregs, fpregs,	padding);

	ret = 0;

err:
	return ret;
}

static int dump_task_core(struct core_entry *core, struct cr_fdset *fdset)
{
	int fd_core = fdset->fds[CR_FD_CORE];
	int ret;

	lseek(fd_core, MAGIC_OFFSET, SEEK_SET);

	pr_info("Dumping header ... ");

	core->header.version	= HEADER_VERSION;
	core->header.arch	= HEADER_ARCH_X86_64;
	core->header.flags	= 0;

	ret = write_img(fd_core, core);

	free(core);
	return ret;
}

static int dump_task_core_all(pid_t pid, struct proc_pid_stat *stat,
		struct parasite_dump_misc *misc, struct parasite_ctl *ctl,
		struct cr_fdset *cr_fdset)
{
	struct core_entry *core		= xzalloc(sizeof(*core));
	int ret				= -1;
	unsigned long brk;

	pr_info("\n");
	pr_info("Dumping core (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	if (!core)
		goto err;

	pr_info("Dumping GP/FPU registers ... ");
	ret = get_task_regs(pid, core, ctl);
	if (ret)
		goto err_free;
	pr_info("OK\n");

	pr_info("Obtainting personality ... ");
	ret = get_task_personality(pid, &core->tc.personality);
	if (ret)
		goto err_free;
	pr_info("OK\n");

	strncpy((char *)core->tc.comm, stat->comm, TASK_COMM_LEN);
	core->tc.flags = stat->flags;
	core->tc.mm_start_code = stat->start_code;
	core->tc.mm_end_code = stat->end_code;
	core->tc.mm_start_data = stat->start_data;
	core->tc.mm_end_data = stat->end_data;
	core->tc.mm_start_stack = stat->start_stack;
	core->tc.mm_start_brk = stat->start_brk;

	core->tc.mm_arg_start = stat->arg_start;
	core->tc.mm_arg_end = stat->arg_end;
	core->tc.mm_env_start = stat->env_start;
	core->tc.mm_env_end = stat->env_end;

	core->tc.mm_brk = misc->brk;

	BUILD_BUG_ON(sizeof(core->tc.blk_sigset) != sizeof(k_rtsigset_t));
	memcpy(&core->tc.blk_sigset, &misc->blocked, sizeof(k_rtsigset_t));

	pr_info("Obtainting task auvx ... ");
	ret = get_task_auxv(pid, core);
	if (ret)
		goto err_free;
	pr_info("OK\n");

	core->tc.task_state = TASK_ALIVE;
	core->tc.exit_code = 0;

	return dump_task_core(core, cr_fdset);

err_free:
	free(core);
err:
	pr_info("----------------------------------------\n");

	return ret;
}

static int parse_threads(struct pstree_item *item, pid_t pid)
{
	struct dirent *de;
	DIR *dir;
	u32 *t = NULL;
	int nr = 1;

	dir = opendir_proc(pid, "task");
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

	item->threads = t;
	item->nr_threads = nr - 1;

	return 0;
}

static int parse_children(struct pstree_item *item, pid_t pid)
{
	FILE *file;
	char *tok;
	u32 *ch = NULL;
	int nr = 1, i;

	for (i = 0; i < item->nr_threads; i++) {

		file = fopen_proc(pid, "task/%d/children", item->threads[i]);
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

	item->children = ch;
	item->nr_children = nr - 1;

	return 0;

err:
	xfree(ch);
	return -1;
}

static void unseize_task_and_threads(struct pstree_item *item, enum cr_task_state st)
{
	int i;

	for (i = 0; i < item->nr_threads; i++)
		unseize_task(item->threads[i], st); /* item->pid will be here */
}

static void pstree_switch_state(struct list_head *list, struct cr_options *opts)
{
	struct pstree_item *item;

	list_for_each_entry(item, list, list) {
		unseize_task_and_threads(item, opts->final_state);
		if (opts->leader_only)
			break;
	}
}

static int seize_threads(struct pstree_item *item)
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
		ret = seize_task(item->threads[i]);
		if (ret < 0)
			goto err;

		if (ret == TASK_SHOULD_BE_DEAD) {
			pr_err("Potentially zombie thread not supported\n");
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

		unseize_task(item->threads[i], CR_TASK_STOP /* FIXME */);
	}

	return -1;
}

static struct pstree_item *collect_task(pid_t pid, struct list_head *list)
{
	int ret;
	struct pstree_item *item;

	item = xzalloc(sizeof(*item));
	if (!item)
		goto err;

	ret = seize_task(pid);
	if (ret < 0)
		goto err_free;

	pr_info("Seized task %d, state %d\n", pid, ret);
	item->pid = pid;
	item->state = ret;

	if (item->state == TASK_SHOULD_BE_DEAD) {
		struct proc_pid_stat_small ps;

		ret = parse_pid_stat_small(pid, &ps);
		if (ret < 0)
			goto err_close;

		if (ps.state != 'Z') {
			pr_err("Unseizeable non-zombie %d found, state %c\n",
					item->pid, ps.state);
			goto err_close;
		}

		item->state = TASK_DEAD;
	}

	ret = parse_threads(item, pid);
	if (ret < 0)
		goto err_close;

	ret = seize_threads(item);
	if (ret < 0)
		goto err_close;

	ret = parse_children(item, pid);
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
err_free:
	xfree(item->children);
	xfree(item->threads);
	xfree(item);
err:
	return NULL;
}

static int collect_pstree(pid_t pid, struct list_head *pstree_list, int leader_only)
{
	struct pstree_item *item;
	int i;

	pr_info("Collecting tasks starting from %d\n", pid);
	item = collect_task(pid, pstree_list);
	if (item == NULL)
		return -1;

	if (leader_only)
		return 0;

	for (i = 0; i < item->nr_children; i++)
		if (collect_pstree(item->children[i], pstree_list, 0) < 0)
			return -1;

	return 0;
}

static int dump_pstree(pid_t pid, struct list_head *pstree_list, struct cr_fdset *cr_fdset)
{
	struct pstree_item *item;
	struct pstree_entry e;
	unsigned long i;
	int ret = -1;

	pr_info("\n");
	pr_info("Dumping pstree (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	list_for_each_entry(item, pstree_list, list) {

		pr_info("Process: %d (%d children)\n",
			item->pid, item->nr_children);

		e.pid		= item->pid;
		e.nr_children	= item->nr_children;
		e.nr_threads	= item->nr_threads;

		if (write_img(cr_fdset->fds[CR_FD_PSTREE], &e))
			goto err;

		pr_info("Children:");
		for (i = 0; i < item->nr_children; i++) {
			pr_info(" %d", item->children[i]);
			if (write_img(cr_fdset->fds[CR_FD_PSTREE],
						&item->children[i]))
				goto err;
		}
		pr_info("\n");

		pr_info("Threads:\n");
		for (i = 0; i < item->nr_threads; i++) {
			pr_info(" %d", item->threads[i]);
			if (write_img(cr_fdset->fds[CR_FD_PSTREE],
						&item->threads[i]))
				goto err;
		}
		pr_info("\n");
	}
	ret = 0;

err:
	pr_info("----------------------------------------\n");
	return ret;
}

static struct vma_area *find_vma_by_addr(struct list_head *vma_area_list, unsigned long addr)
{
	struct vma_area *vma_area;

	list_for_each_entry(vma_area, vma_area_list, list) {
		if (in_vma_area(vma_area, addr))
			return vma_area;
	}

	return NULL;
}

/* kernel expects a special format in core file */
static int finalize_core(pid_t pid, struct list_head *vma_area_list, struct cr_fdset *cr_fdset)
{
	int fd_core;
	unsigned long num;
	struct vma_area *vma_area;
	struct vma_entry ve;
	ssize_t bytes;

	pr_info("\n");
	pr_info("Finalizing core (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	fd_core		= cr_fdset->fds[CR_FD_CORE];

	lseek(fd_core,		GET_FILE_OFF_AFTER(struct core_entry), SEEK_SET);

	num = 0;
	pr_info("Appending VMAs ... ");

	/* All VMAs first */

	list_for_each_entry(vma_area, vma_area_list, list) {
		bytes = write(fd_core, &vma_area->vma, sizeof(vma_area->vma));
		if (bytes != sizeof(vma_area->vma)) {
			pr_perror("\nUnable to write vma entry (%li written)", num);
			goto err;
		}
		num++;
	}

	/* Ending marker */
	memzero_p(&ve);
	if (write_img(fd_core, &ve))
		goto err;

	pr_info("OK (%li written)\n", num);

	pr_info("----------------------------------------\n");
	return 0;

err:
	pr_perror("Error catched");
	return -1;
}

static int dump_task_thread(struct parasite_ctl *parasite_ctl,
				pid_t pid, struct cr_fdset *cr_fdset)
{
	struct core_entry *core		= xzalloc(sizeof(*core));
	int ret				= -1;
	unsigned int *taddr;

	pr_info("\n");
	pr_info("Dumping core for thread (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	if (!core)
		goto err;

	pr_info("Dumping GP/FPU registers ... ");
	ret = get_task_regs(pid, core, NULL);
	if (ret)
		goto err_free;

	ret = parasite_dump_tid_addr_seized(parasite_ctl, pid, &taddr);
	if (ret) {
		pr_err("Can't dump tid address for pid %d", pid);
		goto err;
	}

	pr_info("%d: tid_address=%p\n", pid, taddr);
	core->clear_tid_address = (u64) taddr;

	pr_info("OK\n");

	core->tc.task_state = TASK_ALIVE;
	core->tc.exit_code = 0;

	return dump_task_core(core, cr_fdset);

err_free:
	free(core);
err:
	pr_info("----------------------------------------\n");

	return ret;
}

static int dump_one_zombie(struct pstree_item *item, struct proc_pid_stat *pps,
		struct cr_fdset *cr_fdset)
{
	struct core_entry *core;

	cr_fdset = cr_dump_fdset_open(item->pid, CR_FD_DESC_CORE, cr_fdset);
	if (cr_fdset == NULL)
		return -1;

	core = xzalloc(sizeof(*core));
	if (core == NULL)
		return -1;

	core->tc.task_state = TASK_DEAD;
	core->tc.exit_code = pps->exit_code;

	return dump_task_core(core, cr_fdset);
}

static struct proc_pid_stat pps_buf;

static int dump_task_threads(struct parasite_ctl *parasite_ctl,
					struct pstree_item *item)
{
	int i;
	struct cr_fdset *cr_fdset_thread = NULL;

	if (item->nr_threads == 1)
		return 0;

	for (i = 0; i < item->nr_threads; i++) {
		/* Leader is already dumped */
		if (item->pid == item->threads[i])
			continue;

		cr_fdset_thread = cr_dump_fdset_open(item->threads[i], CR_FD_DESC_CORE, NULL);
		if (!cr_fdset_thread)
			goto err;

		if (dump_task_thread(parasite_ctl,
					item->threads[i], cr_fdset_thread))
			goto err;

		close_cr_fdset(&cr_fdset_thread);
	}

	return 0;

err:
	close_cr_fdset(&cr_fdset_thread);
	return -1;
}

static int dump_one_task(struct pstree_item *item, struct cr_fdset *cr_fdset)
{
	pid_t pid = item->pid;
	LIST_HEAD(vma_area_list);
	struct parasite_ctl *parasite_ctl;
	int ret = -1;
	struct parasite_dump_misc misc;

	pr_info("========================================\n");
	pr_info("Dumping task (pid: %d)\n", pid);
	pr_info("========================================\n");

	if (item->state == TASK_STOPPED) {
		pr_err("Stopped tasks are not supported\n");
		goto err_free;
	}

	pr_info("Obtainting task stat ... ");
	ret = parse_pid_stat(pid, &pps_buf);
	if (ret < 0)
		goto err;

	if (item->state == TASK_DEAD)
		return dump_one_zombie(item, &pps_buf, cr_fdset);

	ret = -1;
	if (!cr_dump_fdset_open(item->pid, CR_FD_DESC_TASK, cr_fdset))
		goto err;

	ret = collect_mappings(pid, &vma_area_list);
	if (ret) {
		pr_err("Collect mappings (pid: %d) failed with %d\n", pid, ret);
		goto err;
	}

	parasite_ctl = parasite_infect_seized(pid, &vma_area_list);
	if (!parasite_ctl) {
		pr_err("Can't infect (pid: %d) with parasite\n", pid);
		goto err;
	}

	ret = parasite_dump_pages_seized(parasite_ctl, &vma_area_list, cr_fdset);
	if (ret) {
		pr_err("Can't dump pages (pid: %d) with parasite\n", pid);
		goto err;
	}

	ret = parasite_dump_sigacts_seized(parasite_ctl, cr_fdset);
	if (ret) {
		pr_err("Can't dump sigactions (pid: %d) with parasite\n", pid);
		goto err;
	}

	ret = parasite_dump_itimers_seized(parasite_ctl, cr_fdset);
	if (ret) {
		pr_err("Can't dump itimers (pid: %d)\n", pid);
		goto err;
	}

	ret = parasite_dump_misc_seized(parasite_ctl, &misc);
	if (ret) {
		pr_err("Can't dump misc (pid: %d)\n", pid);
		goto err;
	}

	ret = dump_task_core_all(pid, &pps_buf, &misc, parasite_ctl, cr_fdset);
	if (ret) {
		pr_err("Dump core (pid: %d) failed with %d\n", pid, ret);
		goto err;
	}

	ret = dump_task_threads(parasite_ctl, item);
	if (ret) {
		pr_err("Can't dump threads\n");
		goto err;
	}

	ret = parasite_cure_seized(parasite_ctl);
	if (ret) {
		pr_err("Can't cure (pid: %d) from parasite\n", pid);
		goto err;
	}

	ret = dump_task_files(pid, cr_fdset);
	if (ret) {
		pr_err("Dump files (pid: %d) failed with %d\n", pid, ret);
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

	ret = finalize_core(pid, &vma_area_list, cr_fdset);
	if (ret) {
		pr_err("Finalizing core (pid: %d) failed with %d\n", pid, ret);
		goto err;
	}

	free_mappings(&vma_area_list);

err:
	close_pid_proc();
err_free:
	free_mappings(&vma_area_list);
	return ret;
}

int cr_dump_tasks(pid_t pid, struct cr_options *opts)
{
	LIST_HEAD(pstree_list);
	struct cr_fdset *cr_fdset = NULL;
	struct pstree_item *item;
	int i, ret = -1;

	pr_info("========================================\n");
	if (!opts->leader_only)
		pr_info("Dumping process group (pid: %d)\n", pid);
	else
		pr_info("Dumping process (pid: %d)\n", pid);
	pr_info("========================================\n");

	if (collect_pstree(pid, &pstree_list, opts->leader_only))
		goto err;

	if (opts->namespaces_flags) {
		ret = dump_namespaces(pid, opts->namespaces_flags);
		if (ret < 0)
			goto err;
	}

	/*
	 * Ignore collection errors by now since we may not want
	 * to dump the missed sockets. But later, when we will start
	 * dumping containers, we'll better fail here, rather than
	 * in the dump stage
	 */

	collect_sockets();

	list_for_each_entry(item, &pstree_list, list) {
		cr_fdset = cr_dump_fdset_open(item->pid, CR_FD_DESC_NONE, NULL);
		if (!cr_fdset)
			goto err;

		if (item->pid == pid) {
			if (!cr_dump_fdset_open(item->pid, CR_FD_DESC_USE(CR_FD_PSTREE), cr_fdset))
				goto err;
			if (dump_pstree(pid, &pstree_list, cr_fdset))
				goto err;
		}

		if (dump_one_task(item, cr_fdset))
			goto err;

		close_cr_fdset(&cr_fdset);

		if (opts->leader_only)
			break;
	}
	ret = 0;

err:
	pstree_switch_state(&pstree_list, opts);
	free_pstree(&pstree_list);
	close_cr_fdset(&cr_fdset);

	return ret;
}
