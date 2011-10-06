#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>

#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/vfs.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/prctl.h>

#include <sys/sendfile.h>

#include "types.h"
#include "list.h"

#include "compiler.h"
#include "crtools.h"
#include "syscall.h"
#include "util.h"

#include "image.h"

#include "parasite.h"
#include "parasite-syscall.h"
#include "parasite-blob.h"

#ifndef CONFIG_X86_64
# error No x86-32 support yet
#endif

static LIST_HEAD(vma_area_list);
static LIST_HEAD(pstree_list);

static char big_buffer[PATH_MAX];
static struct parasite_ctl *parasite_ctl;

static char loc_buf[PAGE_SIZE];

static void free_pstree(void)
{
	struct pstree_item *item, *p;

	list_for_each_entry_safe(item, p, &pstree_list, list) {
		xfree(item->children);
		xfree(item);
	}

	INIT_LIST_HEAD(&pstree_list);
}

static void free_mappings(void)
{
	struct vma_area *vma_area, *p;

	list_for_each_entry_safe(vma_area, p, &vma_area_list, list) {
		if (vma_area->vm_file_fd > 0)
			close(vma_area->vm_file_fd);
		free(vma_area);
	}

	INIT_LIST_HEAD(&vma_area_list);
}

static int collect_mappings(pid_t pid)
{
	struct vma_area *vma_area;
	int ret = -1;

	pr_info("\n");
	pr_info("Collecting mappings (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	ret = parse_maps(pid, &vma_area_list);
	if (ret)
		goto err;

	pr_info_vma_list(&vma_area_list);

	pr_info("----------------------------------------\n");

err:
	return ret;

err_bogus_mapping:
	pr_err("Bogus mapping %lx-%lx\n",
	       vma_area->vma.start,
	       vma_area->vma.end);
	goto err;
}

static int dump_one_reg_file(int type, unsigned long fd_name, int lfd,
			     bool do_close, unsigned long pos, unsigned int flags,
			     struct cr_fdset *cr_fdset)
{
	struct fdinfo_entry e;
	char fd_str[128];
	int len;
	int ret = -1;

	snprintf(fd_str, sizeof(fd_str), "/proc/self/fd/%d", lfd);
	len = readlink(fd_str, big_buffer, sizeof(big_buffer) - 1);
	if (len < 0) {
		pr_perror("Can't readlink %s\n", fd_str);
		goto err;
	}

	big_buffer[len] = '\0';
	pr_info("Dumping path for %lx fd via self %d [%s]\n",
		fd_name, lfd, big_buffer);

	if (do_close)
		close(lfd);

	e.type	= type;
	e.len	= len;
	e.flags = flags;
	e.pos	= pos;
	e.addr	= fd_name;

	pr_info("fdinfo: type: %2x len: %2x flags: %4x pos: %8x addr: %16lx\n",
		type, len, flags, pos, fd_name);

	write_ptr_safe(cr_fdset->desc[CR_FD_FDINFO].fd, &e, err);
	write_safe(cr_fdset->desc[CR_FD_FDINFO].fd, big_buffer, e.len, err);

	ret = 0;
err:
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

	fd_pipes = cr_fdset->desc[CR_FD_PIPES].fd;

	pr_info("Dumping data from pipe %x\n", e->pipeid);
	if (pipe(steal_pipe) < 0) {
		pr_perror("Can't create pipe for stealing data\n");
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
			pr_perror("Can't pick pipe data\n");
			goto err_close;
		} else
			has_bytes = 0;
	}

	e->bytes = has_bytes;
	write_ptr_safe(fd_pipes, e, err_close);

	if (has_bytes) {
		ret = splice(steal_pipe[0], NULL, fd_pipes,
			     NULL, has_bytes, 0);
		if (ret < 0) {
			pr_perror("Can't push pipe data\n");
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

static int dump_one_pipe(int fd, int lfd, unsigned int id, unsigned int flags,
			 struct cr_fdset *cr_fdset)
{
	struct pipe_entry e;
	int ret = -1;

	pr_info("Dumping pipe %d/%x flags %x\n", fd, id, flags);

	e.fd		= fd;
	e.pipeid	= id;
	e.flags		= flags;

	if (flags & O_WRONLY) {
		e.bytes = 0;
		write_ptr_safe(cr_fdset->desc[CR_FD_PIPES].fd, &e, err);
		ret = 0;
	} else
		ret = dump_pipe_and_data(lfd, &e, cr_fdset);

err:
	if (!ret)
		pr_info("Dumped pipe: fd: %8lx pipeid: %8lx flags: %8lx bytes: %8lx\n",
			e.fd, e.pipeid, e.flags, e.bytes);
	else
		pr_err("Dumping pipe %d/%x flags %x\n", fd, id, flags);

	return ret;
}

static bool should_ignore_fd(char *pid_fd_dir, int dir, char *fd_name)
{
	if (!strcmp(fd_name, "0")) {
		pr_info("... Skipping stdin ...\n");
		return true;
	} else if (!strcmp(fd_name, "1")) {
		pr_info("... Skipping stdout ...\n");
		return true;
	} else if (!strcmp(fd_name, "2")) {
		pr_info("... Skipping stderr ...\n");
		return true;
	} else {
		char ttybuf[32];

		if (readlinkat(dir, fd_name, ttybuf, sizeof(ttybuf)) > 0) {
			if (!strncmp(ttybuf, "/dev/tty", 8)) {
				pr_info("... Skipping tty ...\n");
				return true;
			}
		} else {
			pr_perror("Failed to readlink %s/%d %s\n", pid_fd_dir, dir, fd_name);
			return false;
		}
	}

	return false;
}

static int dump_one_fd(char *pid_fd_dir, int dir, char *fd_name, unsigned long pos,
		       unsigned int flags, struct cr_fdset *cr_fdset)
{
	struct statfs stfs_buf;
	struct stat st_buf;
	int fd;

	if (should_ignore_fd(pid_fd_dir, dir, fd_name))
		return 0;

	fd = openat(dir, fd_name, O_RDONLY);
	if (fd < 0) {
		pr_perror("Failed to openat %s/%d %s\n", pid_fd_dir, dir, fd_name);
		return -1;
	}

	if (fstat(fd, &st_buf) < 0) {
		pr_perror("Can't get stat on %s\n", fd_name);
		return -1;
	}

	if (S_ISREG(st_buf.st_mode))
		return dump_one_reg_file(FDINFO_FD, atol(fd_name),
					 fd, 1, pos, flags, cr_fdset);

	if (S_ISFIFO(st_buf.st_mode)) {
		if (fstatfs(fd, &stfs_buf) < 0) {
			pr_perror("Can't fstatfs on %s\n", fd_name);
			return -1;
		}

		if (stfs_buf.f_type == PIPEFS_MAGIC)
			return dump_one_pipe(atol(fd_name), fd,
					     st_buf.st_ino, flags, cr_fdset);
	}

	pr_err("Can't dump file %s of that type [%x]\n", fd_name, st_buf.st_mode);
	return 1;
}

static int read_fd_params(pid_t pid, char *fd, unsigned long *pos, unsigned int *flags)
{
	char fd_str[128];
	int ifd;

	snprintf(fd_str, sizeof(fd_str), "/proc/%d/fdinfo/%s", pid, fd);

	ifd = open(fd_str, O_RDONLY);
	if (ifd < 0) {
		pr_perror("Can't open %s\n", fd_str);
		return -1;
	}

	read(ifd, big_buffer, sizeof(big_buffer));
	close(ifd);

	sscanf(big_buffer, "pos:\t%li\nflags:\t%o\n", pos, flags);

	pr_info("%s: pos: %16lx flags: %16lx\n", fd_str, *pos, *flags);

	return 0;
}

static int dump_task_files(pid_t pid, struct cr_fdset *cr_fdset)
{
	char pid_fd_dir[64];
	struct dirent *de;
	unsigned long pos;
	unsigned int flags;
	DIR *fd_dir;

	pr_info("\n");
	pr_info("Dumping opened files (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	snprintf(pid_fd_dir, sizeof(pid_fd_dir), "/proc/%d/fd", pid);
	fd_dir = opendir(pid_fd_dir);
	if (!fd_dir) {
		pr_perror("Can't open %s\n", pid_fd_dir);
		return -1;
	}

	while ((de = readdir(fd_dir))) {
		if (de->d_name[0] == '.')
			continue;
		if (read_fd_params(pid, de->d_name, &pos, &flags))
			return -1;
		if (dump_one_fd(pid_fd_dir, dirfd(fd_dir), de->d_name, pos, flags, cr_fdset))
			return -1;
	}

	pr_info("----------------------------------------\n");

	closedir(fd_dir);
	return 0;
}

static int dump_task_mappings(pid_t pid, struct cr_fdset *cr_fdset)
{
	struct vma_area *vma_area;
	int ret = -1;

	pr_info("\n");
	pr_info("Dumping mappings (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	list_for_each_entry(vma_area, &vma_area_list, list) {

		struct vma_entry *vma = &vma_area->vma;

		if (!(vma->status & VMA_AREA_REGULAR))
			continue;

		pr_info_vma(vma_area);

		switch (vma->flags) {
		case MAP_SHARED:
		case MAP_PRIVATE:

			if ((vma->status & VMA_ANON_SHARED)) {
				struct shmem_entry e;

				e.start	= vma->start;
				e.end	= vma->end;
				e.shmid	= vma_area->shmid;

				pr_info("shmem: s: %16lx e: %16lx shmid: %16lx\n",
					e.start, e.end, e.shmid);

				write_ptr_safe(cr_fdset->desc[CR_FD_SHMEM].fd, &e, err);
			} else if ((vma->status & VMA_FILE_PRIVATE) ||
				   (vma->status & VMA_FILE_SHARED)) {

				unsigned int flags;

				if (vma->prot & PROT_WRITE && (vma->status & VMA_FILE_SHARED))
					flags = O_RDWR;
				else
					flags = O_RDONLY;

				ret = dump_one_reg_file(FDINFO_MAP,
							vma->start,
							vma_area->vm_file_fd,
							0, 0, flags,
							cr_fdset);
				if (ret)
					goto err;
			}
			break;
		default:
			pr_panic("Unknown VMA (pid: %d)\n", pid);
			goto err;
			break;
		}
	}

	ret = 0;

	pr_info("----------------------------------------\n");

err:
	return ret;
}

#define assign_reg(dst, src, e)		dst.e = (__typeof__(dst.e))src.e
#define assign_array(dst, src, e)	memcpy(&dst.e, &src.e, sizeof(dst.e))

static int get_task_comm(pid_t pid, u8 *comm)
{
	FILE *file = NULL;
	char *tok1, *tok2;
	int ret = -1;

	snprintf(loc_buf, sizeof(loc_buf), "/proc/%d/stat", pid);
	file = fopen(loc_buf, "r");
	if (!file) {
		pr_perror("Can't open %s", loc_buf);
		goto err;
	}

	if (!fgets(loc_buf, sizeof(loc_buf), file)) {
		perror("Can't read task stat");
		goto err;
	}

	tok1 = strtok(loc_buf, "(");
	tok2 = strtok(NULL, ")");
	if ((long)tok1 & (long)tok2) {
		strncpy((char *)comm, tok2, TASK_COMM_LEN);
		ret = 0;
	} else {
		printf("Unable to parse task stat\n");
		ret = -1;
	}

err:
	if (file)
		fclose(file);
	return ret;
}

static int get_task_personality(pid_t pid, u32 *personality)
{
	FILE *file = NULL;
	int ret = -1;

	snprintf(loc_buf, sizeof(loc_buf), "/proc/%d/personality", pid);
	file = fopen(loc_buf, "r");
	if (!file) {
		perror("Can't open task personality");
		goto err;
	}

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

static int dump_task_tls(pid_t pid, struct desc_struct *tls_array, int size)
{
	FILE *file = NULL;
	int ret = -1;

	if (size != GDT_ENTRY_TLS_ENTRIES) {
		pr_err("Wrong TLS storage size: %d\n", size);
		goto err;
	}

	snprintf(loc_buf, sizeof(loc_buf), "/proc/%d/tls", pid);
	file = fopen(loc_buf, "r");
	if (!file) {
		perror("Can't open task tls");
		goto err;
	}

	ret = 0;
	while (fgets(loc_buf, sizeof(loc_buf), file)) {
		u32 a, b;
		if (sscanf(loc_buf, "%x %x", &a, &b) != 2) {
			pr_err("Can't parse tls entry: %s\n");
			ret = -1;
			goto err;
		}
		if (ret >= GDT_ENTRY_TLS_ENTRIES) {
			pr_err("Too many entries in tls\n");
			ret = -1;
			goto err;
		}
		tls_array[ret].a = a;
		tls_array[ret].b = b;

		ret++;
	}

	if (ret != GDT_ENTRY_TLS_ENTRIES) {
		pr_err("tls returened %i entries instead of %i\n",
			 ret, GDT_ENTRY_TLS_ENTRIES);
		ret = -1;
		goto err;
	}

	ret = 0;

err:
	if (file)
		fclose(file);
	return ret;
}

static int dump_task_core_seized(pid_t pid, struct cr_fdset *cr_fdset)
{
	struct core_entry *core		= xzalloc(sizeof(*core));
	user_fpregs_struct_t fpregs	= {-1};
	user_regs_struct_t regs		= {-1};
	int fd_core			= cr_fdset->desc[CR_FD_CORE].fd;
	int ret				= -1;

	pr_info("\n");
	pr_info("Dumping core (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	if (!core)
		goto err;

	lseek(fd_core, MAGIC_OFFSET, SEEK_SET);

	jerr(ptrace(PTRACE_GETREGS,	pid, NULL, &regs), err_free);
	jerr(ptrace(PTRACE_GETFPREGS,	pid, NULL, &fpregs), err_free);

	pr_info("Dumping GP/FPU registers ... ");

	assign_reg(core->gpregs, regs,		r15);
	assign_reg(core->gpregs, regs,		r14);
	assign_reg(core->gpregs, regs,		r13);
	assign_reg(core->gpregs, regs,		r12);
	assign_reg(core->gpregs, regs,		bp);
	assign_reg(core->gpregs, regs,		bx);
	assign_reg(core->gpregs, regs,		r11);
	assign_reg(core->gpregs, regs,		r10);
	assign_reg(core->gpregs, regs,		r9);
	assign_reg(core->gpregs, regs,		r8);
	assign_reg(core->gpregs, regs,		ax);
	assign_reg(core->gpregs, regs,		cx);
	assign_reg(core->gpregs, regs,		dx);
	assign_reg(core->gpregs, regs,		si);
	assign_reg(core->gpregs, regs,		di);
	assign_reg(core->gpregs, regs,		orig_ax);
	assign_reg(core->gpregs, regs,		ip);
	assign_reg(core->gpregs, regs,		cs);
	assign_reg(core->gpregs, regs,		flags);
	assign_reg(core->gpregs, regs,		sp);
	assign_reg(core->gpregs, regs,		ss);
	assign_reg(core->gpregs, regs,		fs_base);
	assign_reg(core->gpregs, regs,		gs_base);
	assign_reg(core->gpregs, regs,		ds);
	assign_reg(core->gpregs, regs,		es);
	assign_reg(core->gpregs, regs,		fs);
	assign_reg(core->gpregs, regs,		gs);

	assign_reg(core->fpregs, fpregs,	cwd);
	assign_reg(core->fpregs, fpregs,	swd);
	assign_reg(core->fpregs, fpregs,	twd);
	assign_reg(core->fpregs, fpregs,	fop);
	assign_reg(core->fpregs, fpregs,	rip);
	assign_reg(core->fpregs, fpregs,	rdp);
	assign_reg(core->fpregs, fpregs,	mxcsr);
	assign_reg(core->fpregs, fpregs,	mxcsr_mask);

	assign_array(core->fpregs, fpregs,	st_space);
	assign_array(core->fpregs, fpregs,	xmm_space);
	assign_array(core->fpregs, fpregs,	padding);

	pr_info("OK\n");

	pr_info("Obtainting TLS ... ");
	ret = dump_task_tls(pid, core->tls_array, ARRAY_SIZE(core->tls_array));
	if (ret)
		goto err_free;
	pr_info("OK\n");

	pr_info("Obtainting personality ... ");
	ret = get_task_personality(pid, &core->personality);
	if (ret)
		goto err_free;
	pr_info("OK\n");

	pr_info("Obtainting task command ... ");
	ret = get_task_comm(pid, core->comm);
	if (ret)
		goto err_free;
	pr_info("OK\n");

	pr_info("Dumping header ... ");
	core->hdr.version	= HEADER_VERSION;
	core->hdr.arch		= HEADER_ARCH_X86_64;
	core->hdr.flags		= 0;

	write_ptr_safe(fd_core, core, err_free);

	pr_info("OK\n");
	ret = 0;

err_free:
	free(core);
err:
	pr_info("----------------------------------------\n");

	return ret;
}

static struct pstree_item *find_children(pid_t pid)
{
	struct pstree_item *item = NULL;
	u32 *children = NULL;
	u32 nr_allocated = 0;
	u32 nr_children = 0;
	bool found = false;
	FILE *file;
	char *tok;

	pr_debug("pid: %d\n", pid);

	snprintf(loc_buf, sizeof(loc_buf), "/proc/%d/status", pid);
	file = fopen(loc_buf, "r");
	if (!file) {
		perror("Can't open task status");
		goto err;
	}

	while ((fgets(loc_buf, sizeof(loc_buf), file))) {
		if (strncmp(loc_buf, "Children:", 9)) {
			continue;
		} else {
			found = true;
			break;
		}
	}

	fclose(file), file = NULL;
	if (!found) {
		pr_err("Children marker is not found\n");
		goto err;
	}

	item = xzalloc(sizeof(*item));
	if (!item)
		goto err;

	tok = strtok(&loc_buf[10], " \n");
	while (tok) {
		u32 child_pid = atoi(tok);

		pr_debug("child_pid: %d\n", child_pid);

		if (nr_allocated <= nr_children) {
			nr_allocated += 64;
			if (xrealloc_safe((void **)&children, nr_allocated)) {
				xfree(children);
				xfree(item);
				item = NULL;
				goto err;
			}
		}

		children[nr_children++] = child_pid;
		tok = strtok(NULL, " \n");
	}

	item->pid		= pid;
	item->nr_children	= nr_children;
	item->children		= children;

err:
	return item;
}

static int collect_pstree(pid_t pid)
{
	struct pstree_item *item;
	unsigned long i;
	int ret = -1;

	item = find_children(pid);
	if (!item)
		goto err;

	list_add_tail(&item->list, &pstree_list);

	for (i = 0; i < item->nr_children; i++) {
		ret = collect_pstree(item->children[i]);
		if (ret)
			goto err;
	}
	ret = 0;

err:
	return ret;
}

static int dump_pstree(pid_t pid, struct cr_fdset *cr_fdset)
{
	struct pstree_item *item;
	struct pstree_entry e;
	unsigned long i;
	int ret = -1;

	pr_info("\n");
	pr_info("Dumping pstree (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	list_for_each_entry(item, &pstree_list, list) {

		pr_info("Process: %d (%d children)\n",
			item->pid, item->nr_children);

		e.pid		= item->pid;
		e.nr_children	= item->nr_children;

		write_ptr_safe(cr_fdset->desc[CR_FD_PSTREE].fd, &e, err);

		pr_info("Children:");
		for (i = 0; i < item->nr_children; i++) {
			pr_info(" %d", item->children[i]);
			write_ptr_safe(cr_fdset->desc[CR_FD_PSTREE].fd,
				       &item->children[i], err);
		}
		pr_info("\n");
	}
	ret = 0;

err:
	pr_info("----------------------------------------\n");
	return ret;
}

static struct vma_area *find_vma_by_addr(unsigned long addr)
{
	struct vma_area *vma_area;

	list_for_each_entry(vma_area, &vma_area_list, list) {
		if (in_vma_area(vma_area, addr))
			return vma_area;
	}

	return NULL;
}

/* kernel expects a special format in core file */
static int finalize_core(pid_t pid, struct cr_fdset *cr_fdset)
{
	int fd_pages, fd_pages_shmem, fd_core;
	unsigned long num, num_anon;
	struct vma_area *vma_area;
	struct vma_entry ve;
	int ret = -1;
	u64 va;

	pr_info("\n");
	pr_info("Finalizing core (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	fd_core		= cr_fdset->desc[CR_FD_CORE].fd;
	fd_pages	= cr_fdset->desc[CR_FD_PAGES].fd;
	fd_pages_shmem	= cr_fdset->desc[CR_FD_PAGES_SHMEM].fd;

	pr_debug("dsc: fd_core %d fd_pages %d fd_pages_shmem %d\n",
		 fd_core, fd_pages, fd_pages_shmem);

	lseek(fd_core,		GET_FILE_OFF_AFTER(struct core_entry), SEEK_SET);
	lseek(fd_pages,		MAGIC_OFFSET, SEEK_SET);
	lseek(fd_pages_shmem,	MAGIC_OFFSET, SEEK_SET);

	num = 0;
	pr_info("Appending VMAs ... ");

	/* All VMAs first */

	list_for_each_entry(vma_area, &vma_area_list, list) {
		ret = write(fd_core, &vma_area->vma, sizeof(vma_area->vma));
		if (ret != sizeof(vma_area->vma)) {
			pr_perror("\nUnable to write vma entry (%li written)\n", num);
			goto err;
		}
		num++;
	}

	/* Ending marker */
	memset(&ve, 0, sizeof(ve));
	write_ptr_safe(fd_core, &ve, err);

	pr_info("OK (%li written)\n", num);

	num = 0;
	num_anon = 0;

	pr_info("Appending pages ... ");
	while (1) {
		ret = read(fd_pages, &va, sizeof(va));
		if (!ret)
			break;
		if (ret != sizeof(va)) {
			pr_perror("\nUnable to read VA of page (%li written)\n", num);
			goto err;
		}

		/* Ending marker */
		if (va == 0) {
			write_ptr_safe(fd_core,		&zero_page_entry, err);
			write_ptr_safe(fd_pages_shmem,	&zero_page_entry, err);
			break;
		}

		vma_area = find_vma_by_addr((unsigned long)va);
		if (!vma_area) {
			pr_panic("\nA page with address %lx is unknown\n", va);
			goto err;
		}

		/*
		 * Just in case if someone broke parasite page
		 * dumper code.
		 */
		if (!vma_area_has(vma_area, VMA_AREA_REGULAR)) {
			pr_panic("\nA page with address %lx has a wrong status\n", va);
			goto err;
		}

		if (vma_area_has(vma_area, VMA_ANON_PRIVATE) ||
		    vma_area_has(vma_area, VMA_FILE_PRIVATE)) {
			ret  = write(fd_core, &va, sizeof(va));
			ret += sendfile(fd_core, fd_pages, NULL, PAGE_SIZE);
			if (ret != sizeof(va) + PAGE_SIZE) {
				pr_perror("\nUnable to write VMA_FILE_PRIVATE|VMA_ANON_PRIVATE "
					  "page (%li, %li written)\n",
					  num, num_anon);
				goto err;
			}
			num++;
		} else if (vma_area_has(vma_area, VMA_ANON_SHARED)) {
			ret  = write(fd_pages_shmem, &va, sizeof(va));
			ret += sendfile(fd_pages_shmem, fd_pages, NULL, PAGE_SIZE);
			if (ret != sizeof(va) + PAGE_SIZE) {
				pr_perror("\nUnable to write VMA_ANON_SHARED "
					  "page (%li, %li written)\n",
					  num, num_anon);
				goto err;
			}
			num_anon++;
		} else {
			/* skip the page */
			lseek(fd_pages, PAGE_SIZE, SEEK_CUR);
		}
	}
	ret = 0;

	pr_info("OK (%li written)\n", num + num_anon);

err:
	pr_info("----------------------------------------\n");
	return ret;

err_strno:
	pr_perror("Error catched\n");
	goto err;
}

static int dump_one_task(pid_t pid, struct cr_fdset *cr_fdset)
{
	int ret = 0;

	pr_info("========================================\n");
	pr_info("Dumping task (pid: %d)\n", pid);
	pr_info("========================================\n");

	ret = collect_mappings(pid);
	if (ret) {
		pr_err("Collect mappings (pid: %d) failed with %d\n", pid, ret);
		goto err;
	}

	ret = seize_task(pid);
	if (ret) {
		pr_err("Failed to seize task (pid: %d) with %d\n",
		       pid, ret);
		goto err;
	}

	ret = dump_task_core_seized(pid, cr_fdset);
	if (ret) {
		pr_err("Dump core (pid: %d) failed with %d\n", pid, ret);
		goto err;
	}

	parasite_ctl = parasite_infect_seized(pid, NULL, &vma_area_list);
	if (!parasite_ctl) {
		pr_err("Can't infect (pid: %d) with parasite\n", pid);
		goto err;
	}

	ret = parasite_dump_pages_seized(parasite_ctl, &vma_area_list,
					 cr_fdset, CR_FD_PAGES);
	if (ret) {
		pr_err("Can't dump pages (pid: %d) with parasite\n", pid);
		goto err;
	}

	ret = parasite_cure_seized(&parasite_ctl, &vma_area_list);
	if (ret) {
		pr_err("Can't cure (pid: %d) from parasite\n", pid);
		goto err;
	}

	ret = unseize_task(pid);
	if (ret) {
		pr_err("Can't unsieze (pid: %d) task\n", pid);
		goto err;
	}

	ret = dump_task_files(pid, cr_fdset);
	if (ret) {
		pr_err("Dump files (pid: %d) failed with %d\n", pid, ret);
		goto err;
	}

	ret = dump_task_mappings(pid, cr_fdset);
	if (ret) {
		pr_err("Dump mappings (pid: %d) failed with %d\n", pid, ret);
		goto err;
	}

	ret = finalize_core(pid, cr_fdset);
	if (ret) {
		pr_err("Finalizing core (pid: %d) failed with %d\n", pid, ret);
		goto err;
	}

err:
	free_mappings();
	return ret;
}

int cr_dump_tasks(pid_t pid, struct cr_options *opts)
{
	struct cr_fdset *cr_fdset = NULL;
	struct pstree_item *item;
	int ret = -1;

	pr_info("========================================\n");
	if (!opts->leader_only)
		pr_info("Dumping process group (pid: %d)\n", pid);
	else
		pr_info("Dumping process (pid: %d)\n", pid);
	pr_info("========================================\n");

	if (collect_pstree(pid))
		goto err;

	list_for_each_entry(item, &pstree_list, list) {
		stop_task(item->pid);
		if (opts->leader_only)
			break;
	}

	/* Dump the process tree first */
	cr_fdset = alloc_cr_fdset(pid);
	if (!cr_fdset)
		goto err;

	if (prep_cr_fdset_for_dump(cr_fdset, CR_FD_DESC_USE(CR_FD_PSTREE)))
		goto err;
	if (dump_pstree(pid, cr_fdset))
		goto err;

	close_cr_fdset(cr_fdset);
	free_cr_fdset(&cr_fdset);

	/* Now all other data */
	list_for_each_entry(item, &pstree_list, list) {

		cr_fdset = alloc_cr_fdset(item->pid);
		if (!cr_fdset)
			goto err;
		if (prep_cr_fdset_for_dump(cr_fdset, CR_FD_DESC_NOPSTREE))
			goto err;

		if (dump_one_task(item->pid, cr_fdset))
			goto err;

		close_cr_fdset(cr_fdset);
		free_cr_fdset(&cr_fdset);

		if (opts->leader_only)
			break;
	}
	ret = 0;

err:
	if (!opts->final_state != CR_TASK_LEAVE_STOPPED) {
		list_for_each_entry(item, &pstree_list, list) {
			continue_task(item->pid);
			if (opts->leader_only)
				break;
		}
	}

	free_pstree();
	close_cr_fdset(cr_fdset);
	free_cr_fdset(&cr_fdset);
	return ret;
}
