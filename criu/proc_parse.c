#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <string.h>
#include <ctype.h>
#include <linux/fs.h>
#include <sys/sysmacros.h>

#include "types.h"
#include "common/list.h"
#include "util.h"
#include "mount.h"
#include "filesystems.h"
#include "mman.h"
#include "cpu.h"
#include "file-lock.h"
#include "pstree.h"
#include "fsnotify.h"
#include "posix-timer.h"
#include "kerndat.h"
#include "vdso.h"
#include "vma.h"
#include "bfd.h"
#include "proc_parse.h"
#include "fdinfo.h"
#include "parasite.h"
#include "cr_options.h"
#include "sysfs_parse.h"
#include "seccomp.h"
#include "string.h"
#include "namespaces.h"
#include "files-reg.h"
#include "cgroup.h"
#include "cgroup-props.h"
#include "timerfd.h"
#include "path.h"

#include "protobuf.h"
#include "images/fdinfo.pb-c.h"
#include "images/mnt.pb-c.h"

#include <stdlib.h>

#ifndef SIGEV_SIGNAL
#define SIGEV_SIGNAL    0       /* notify via signal */
#endif
#ifndef SIGEV_NONE
#define SIGEV_NONE      1       /* other notification: meaningless */
#endif
#ifndef SIGEV_THREAD
#define SIGEV_THREAD    2       /* deliver via thread creation */
#endif
#ifndef SIGEV_THREAD_ID
#define SIGEV_THREAD_ID 4       /* deliver to thread */
#endif

struct buffer {
	char buf[PAGE_SIZE];
	char end; /* '\0' */
};

static struct buffer __buf;
static char *buf = __buf.buf;

#define BUF_SIZE sizeof(__buf.buf)

/*
 * This is how AIO ring buffers look like in proc
 */

#define AIO_FNAME	"/[aio]"

/* check the @line starts with "%lx-%lx" format */
static bool is_vma_range_fmt(char *line)
{
#define ____is_vma_addr_char(__c)		\
	(((__c) <= '9' && (__c) >= '0') ||	\
	((__c) <= 'f' && (__c) >= 'a'))

	while (*line && ____is_vma_addr_char(*line))
		line++;

	if (*line++ != '-')
		return false;

	while (*line && ____is_vma_addr_char(*line))
		line++;

	if (*line++ != ' ')
		return false;

	return true;
#undef ____is_vma_addr_char
}

static int parse_vmflags(char *buf, struct vma_area *vma_area)
{
	char *tok;

	if (!buf[0])
		return 0;

	tok = strtok(buf, " \n");
	if (!tok)
		return 0;

#define _vmflag_match(_t, _s) (_t[0] == _s[0] && _t[1] == _s[1])

	do {
		/* mmap() block */
		if (_vmflag_match(tok, "gd"))
			vma_area->e->flags |= MAP_GROWSDOWN;
		else if (_vmflag_match(tok, "lo"))
			vma_area->e->flags |= MAP_LOCKED;
		else if (_vmflag_match(tok, "nr"))
			vma_area->e->flags |= MAP_NORESERVE;
		else if (_vmflag_match(tok, "ht"))
			vma_area->e->flags |= MAP_HUGETLB;

		/* madvise() block */
		if (_vmflag_match(tok, "sr"))
			vma_area->e->madv |= (1ul << MADV_SEQUENTIAL);
		else if (_vmflag_match(tok, "rr"))
			vma_area->e->madv |= (1ul << MADV_RANDOM);
		else if (_vmflag_match(tok, "dc"))
			vma_area->e->madv |= (1ul << MADV_DONTFORK);
		else if (_vmflag_match(tok, "dd"))
			vma_area->e->madv |= (1ul << MADV_DONTDUMP);
		else if (_vmflag_match(tok, "mg"))
			vma_area->e->madv |= (1ul << MADV_MERGEABLE);
		else if (_vmflag_match(tok, "hg"))
			vma_area->e->madv |= (1ul << MADV_HUGEPAGE);
		else if (_vmflag_match(tok, "nh"))
			vma_area->e->madv |= (1ul << MADV_NOHUGEPAGE);

		/* vmsplice doesn't work for VM_IO and VM_PFNMAP mappings. */
		if (_vmflag_match(tok, "io") || _vmflag_match(tok, "pf")) {
			/*
			 * VVAR area mapped by the kernel as
			 * VM_IO | VM_PFNMAP| VM_DONTEXPAND | VM_DONTDUMP
			 */
			if (!vma_area_is(vma_area, VMA_AREA_VVAR))
				vma_area->e->status |= VMA_UNSUPP;
		}

		/*
		 * Anything else is just ignored.
		 */
	} while ((tok = strtok(NULL, " \n")));

#undef _vmflag_match

	if (vma_area->e->madv)
		vma_area->e->has_madv = true;

	return 0;
}

static inline int is_anon_shmem_map(dev_t dev)
{
	return kdat.shmem_dev == dev;
}

struct vma_file_info {
	int dev_maj;
	int dev_min;
	unsigned long ino;
	struct vma_area *vma;
};

static inline int vfi_equal(struct vma_file_info *a, struct vma_file_info *b)
{
	return ((a->ino ^ b->ino) |
			(a->dev_maj ^ b->dev_maj) |
			(a->dev_min ^ b->dev_min)) == 0;
}

static int vma_get_mapfile_flags(struct vma_area *vma, DIR *mfd, char *path)
{
	struct stat stat;

	if (fstatat(dirfd(mfd), path, &stat, AT_SYMLINK_NOFOLLOW) < 0) {
		if (errno == ENOENT) {
			/* Just mapping w/o map_files link */
			return 0;
		}
		pr_perror("Failed fstatat on map %"PRIx64"", vma->e->start);
		return -1;
	}

	switch(stat.st_mode & 0600) {
		case 0200:
			vma->e->fdflags = O_WRONLY;
			break;
		case 0400:
			vma->e->fdflags = O_RDONLY;
			break;
		case 0600:
			vma->e->fdflags = O_RDWR;
			break;
	}
	vma->e->has_fdflags = true;
	return 0;
}

static int vma_stat(struct vma_area *vma, int fd)
{
	vma->vmst = xmalloc(sizeof(struct stat));
	if (!vma->vmst)
		return -1;

	/*
	 * For AUFS support, we need to check if the symbolic link
	 * points to a branch.  If it does, we cannot fstat() its file
	 * descriptor because it would return a different dev/ino than
	 * the real file.  If fixup_aufs_vma_fd() returns positive,
	 * it means that it has stat()'ed using the full pathname.
	 * Zero return means that the symbolic link does not point to
	 * a branch and we can do fstat() below.
	 */
	if (opts.aufs) {
		int ret;

		ret = fixup_aufs_vma_fd(vma, fd);
		if (ret < 0)
			return -1;
		if (ret > 0)
			return 0;
	}

	if (fstat(fd, vma->vmst) < 0) {
		pr_perror("Failed fstat on map %"PRIx64"", vma->e->start);
		return -1;
	}

	return 0;
}

static int vma_get_mapfile_user(const char *fname, struct vma_area *vma,
			   struct vma_file_info *vfi, int *vm_file_fd,
			   const char *path)
{
	int fd;
	dev_t vfi_dev;

	/*
	 * Kernel prohibits reading map_files for users. The
	 * best we can do here is fill stat using the information
	 * from smaps file and ... hope for the better :\
	 *
	 * Here we'll miss AIO-s and sockets :(
	 */

	if (fname[0] == '\0') {
		/*
		 * Another bad thing is that kernel first checks
		 * for permission access to ANY map_files link,
		 * then checks for its existence. So we have to
		 * check for file path being empty to "emulate"
		 * the ENOENT case.
		 */

		if (vfi->dev_maj != 0 || vfi->dev_min != 0 || vfi->ino != 0) {
			pr_err("Strange file mapped at %lx [%s]:%d.%d.%ld\n",
			       (unsigned long)vma->e->start, fname,
			       vfi->dev_maj, vfi->dev_min, vfi->ino);
			return -1;
		}

		return 0;
	} else if (fname[0] != '/') {
		/*
		 * This should be some kind of
		 * special mapping like [heap], [vdso]
		 * and such, the caller should take care
		 * of the @fname and vma status.
		 */
		return 0;
	}

	vfi_dev = makedev(vfi->dev_maj, vfi->dev_min);
	if (is_anon_shmem_map(vfi_dev)) {
		if (!(vma->e->flags & MAP_SHARED))
			return -1;

		vma->e->flags  |= MAP_ANONYMOUS;
		vma->e->status |= VMA_ANON_SHARED;
		vma->e->shmid = vfi->ino;

		if (!strncmp(fname, "/SYSV", 5))
			vma->e->status |= VMA_AREA_SYSVIPC;

		return 0;
	}

	pr_info("Failed to open map_files/%s, try to go via [%s] path\n", path, fname);
	fd = open(fname, O_RDONLY);
	if (fd < 0) {
		pr_perror("Can't open mapped [%s]", fname);
		return -1;
	}

	if (vma_stat(vma, fd)) {
		close(fd);
		return -1;
	}

	if (vma->vmst->st_dev != vfi_dev ||
			vma->vmst->st_ino != vfi->ino) {
		pr_err("Failed to resolve mapping %lx filename\n",
		       (unsigned long)vma->e->start);
		close(fd);
		return -1;
	}

	*vm_file_fd = fd;
	return 0;
}

static int vma_get_mapfile(const char *fname, struct vma_area *vma, DIR *mfd,
			   struct vma_file_info *vfi,
			   struct vma_file_info *prev_vfi,
			   int *vm_file_fd)
{
	char path[32];
	int flags;

	/* Figure out if it's file mapping */
	snprintf(path, sizeof(path), "%"PRIx64"-%"PRIx64, vma->e->start, vma->e->end);

	if (vma_get_mapfile_flags(vma, mfd, path))
		return -1;

	if (prev_vfi->vma && vfi_equal(vfi, prev_vfi)) {
		struct vma_area *prev = prev_vfi->vma;

		/*
		 * If vfi is equal (!) and negative @vm_file_fd --
		 * we have nothing to borrow for sure.
		 */
		if (*vm_file_fd < 0)
			return 0;

		pr_debug("vma %"PRIx64" borrows vfi from previous %"PRIx64"\n",
				vma->e->start, prev->e->start);
		if (prev->e->status & VMA_AREA_SOCKET)
			vma->e->status |= VMA_AREA_SOCKET | VMA_AREA_REGULAR;

		/*
		 * FIXME -- in theory there can be vmas that have
		 * dev:ino match, but live in different mount
		 * namespaces. However, we only borrow files for
		 * subsequent vmas. These are _very_ likely to
		 * have files from the same namespaces.
		 */
		vma->file_borrowed = true;

		return 0;
	}
	close_safe(vm_file_fd);

	/*
	 * Note that we "open" it in dumper process space
	 * so later we might refer to it via /proc/self/fd/vm_file_fd
	 * if needed.
	 */
	flags = O_PATH;
	if (vfi->dev_maj == 0)
		/*
		 * Opening with O_PATH omits calling kernel ->open
		 * method, thus for some special files their type
		 * detection might be broken. Thus we open those with
		 * the O_RDONLY to potentially get ENXIO and check
		 * it below.
		 */
		flags = O_RDONLY;

	*vm_file_fd = openat(dirfd(mfd), path, flags);
	if (*vm_file_fd < 0) {
		if (errno == ENOENT)
			/* Just mapping w/o map_files link */
			return 0;

		if (errno == ENXIO) {
			struct stat buf;

			if (fstatat(dirfd(mfd), path, &buf, 0))
				return -1;

			if (S_ISSOCK(buf.st_mode)) {
				pr_info("Found socket mapping @%"PRIx64"\n", vma->e->start);
				vma->vm_socket_id = buf.st_ino;
				vma->e->status |= VMA_AREA_SOCKET | VMA_AREA_REGULAR;
				return 0;
			}

			if ((buf.st_mode & S_IFMT) == 0 && !strncmp(fname, AIO_FNAME, sizeof(AIO_FNAME) - 1)) {
				/* AIO ring, let's try */
				close_safe(vm_file_fd);
				vma->e->status = VMA_AREA_AIORING;
				return 0;
			}

			pr_err("Unknown shit %o (%s)\n", buf.st_mode, fname);
			return -1;
		}

		if (errno == EPERM && !opts.aufs)
			return vma_get_mapfile_user(fname, vma, vfi, vm_file_fd, path);

		pr_perror("Can't open map_files");
		return -1;
	}

	return vma_stat(vma, *vm_file_fd);
}

int parse_self_maps_lite(struct vm_area_list *vms)
{
	FILE *maps;
	struct vma_area *prev = NULL;

	vm_area_list_init(vms);

	maps = fopen_proc(PROC_SELF, "maps");
	if (maps == NULL)
		return -1;

	while (fgets(buf, BUF_SIZE, maps) != NULL) {
		struct vma_area *vma;
		char *end;
		unsigned long s, e;

		s = strtoul(buf, &end, 16);
		e = strtoul(end + 1, NULL, 16);

		if (prev && prev->e->end == s)
			/*
			 * This list is needed for one thing only -- to
			 * get the idea of what parts of current address
			 * space are busy. So merge them altogether.
			 */
			prev->e->end = e;
		else {
			vma = alloc_vma_area();
			if (!vma) {
				fclose(maps);
				return -1;
			}

			vma->e->start = s;
			vma->e->end = e;
			list_add_tail(&vma->list, &vms->h);
			vms->nr++;
			prev = vma;
		}

		pr_debug("Parsed %"PRIx64"-%"PRIx64" vma\n", prev->e->start, prev->e->end);
	}

	fclose(maps);
	return 0;
}

#ifdef CONFIG_VDSO
static inline int handle_vdso_vma(struct vma_area *vma)
{
	vma->e->status |= VMA_AREA_REGULAR;
	if ((vma->e->prot & VDSO_PROT) == VDSO_PROT)
		vma->e->status |= VMA_AREA_VDSO;
	return 0;
}

static inline int handle_vvar_vma(struct vma_area *vma)
{
	vma->e->status |= VMA_AREA_REGULAR;
	if ((vma->e->prot & VVAR_PROT) == VVAR_PROT)
		vma->e->status |= VMA_AREA_VVAR;
	return 0;
}
#else
static inline int handle_vdso_vma(struct vma_area *vma)
{
	pr_warn_once("Found vDSO area without support\n");
	return -1;
}

static inline int handle_vvar_vma(struct vma_area *vma)
{
	pr_warn_once("Found VVAR area without support\n");
	return -1;
}
#endif

static int handle_vma(pid_t pid, struct vma_area *vma_area,
			const char *file_path, DIR *map_files_dir,
			struct vma_file_info *vfi,
			struct vma_file_info *prev_vfi,
			int *vm_file_fd)
{
	if (vma_get_mapfile(file_path, vma_area, map_files_dir,
					vfi, prev_vfi, vm_file_fd))
		goto err_bogus_mapfile;

	if (vma_area->e->status != 0)
		return 0;

	if (!strcmp(file_path, "[vsyscall]") ||
		   !strcmp(file_path, "[vectors]")) {
		vma_area->e->status |= VMA_AREA_VSYSCALL;
	} else if (!strcmp(file_path, "[vdso]")) {
		if (handle_vdso_vma(vma_area))
			goto err;
	} else if (!strcmp(file_path, "[vvar]")) {
		if (handle_vvar_vma(vma_area))
			goto err;
	} else if (!strcmp(file_path, "[heap]")) {
		vma_area->e->status |= VMA_AREA_REGULAR | VMA_AREA_HEAP;
	} else {
		vma_area->e->status = VMA_AREA_REGULAR;
	}

	/*
	 * Some mapping hints for restore, we save this on
	 * disk and restore might need to analyze it.
	 */
	if (vma_area->file_borrowed) {
		struct vma_area *prev = prev_vfi->vma;

		/*
		 * Pick-up flags that might be set in the branch below.
		 * Status is copied as-is as it should be zero here,
		 * and have full match with the previous.
		 */
		vma_area->e->flags |= (prev->e->flags & MAP_ANONYMOUS);
		vma_area->e->status = prev->e->status;
		vma_area->e->shmid = prev->e->shmid;
		vma_area->vmst = prev->vmst;
		vma_area->mnt_id = prev->mnt_id;
	} else if (*vm_file_fd >= 0) {
		struct stat *st_buf = vma_area->vmst;

		if (S_ISREG(st_buf->st_mode))
			/* regular file mapping -- supported */;
		else if (S_ISCHR(st_buf->st_mode) && (st_buf->st_rdev == DEVZERO))
			/* devzero mapping -- also makes sense */;
		else {
			pr_err("Can't handle non-regular mapping on %d's map %"PRIx64"\n", pid, vma_area->e->start);
			goto err;
		}

		/*
		 * /dev/zero stands for anon-shared mapping
		 * otherwise it's some file mapping.
		 */
		if (is_anon_shmem_map(st_buf->st_dev)) {
			if (!(vma_area->e->flags & MAP_SHARED))
				goto err_bogus_mapping;
			vma_area->e->flags  |= MAP_ANONYMOUS;
			vma_area->e->status |= VMA_ANON_SHARED;
			vma_area->e->shmid = st_buf->st_ino;

			if (!strncmp(file_path, "/SYSV", 5)) {
				pr_info("path: %s\n", file_path);
				vma_area->e->status |= VMA_AREA_SYSVIPC;
			}
		} else {
			if (vma_area->e->flags & MAP_PRIVATE)
				vma_area->e->status |= VMA_FILE_PRIVATE;
			else
				vma_area->e->status |= VMA_FILE_SHARED;
		}

		/*
		 * We cannot use the mnt_id value provided by the kernel
		 * for vm_file_fd if it is an AUFS file (the value is
		 * wrong).  In such a case, fixup_aufs_vma_fd() has set
		 * mnt_id to -1 to mimic pre-3.15 kernels that didn't
		 * have mnt_id.
		 */
		if (vma_area->mnt_id != -1 &&
		    get_fd_mntid(*vm_file_fd, &vma_area->mnt_id))
			return -1;
	} else {
		/*
		 * No file but mapping -- anonymous one.
		 */
		if (vma_area->e->flags & MAP_SHARED) {
			vma_area->e->status |= VMA_ANON_SHARED;
			vma_area->e->shmid = vfi->ino;
		} else {
			vma_area->e->status |= VMA_ANON_PRIVATE;
		}
		vma_area->e->flags  |= MAP_ANONYMOUS;
	}

	return 0;
err:
	return -1;
err_bogus_mapping:
	pr_err("Bogus mapping 0x%"PRIx64"-0x%"PRIx64" (flags: %#x vm_file_fd: %d)\n",
	       vma_area->e->start, vma_area->e->end,
	       vma_area->e->flags, *vm_file_fd);
	goto err;

err_bogus_mapfile:
	pr_perror("Can't open %d's mapfile link %"PRIx64, pid, vma_area->e->start);
	goto err;
}

static int vma_list_add(struct vma_area *vma_area,
			struct vm_area_list *vma_area_list,
			unsigned long *prev_end,
			struct vma_file_info *vfi, struct vma_file_info *prev_vfi)
{
	if (vma_area->e->status & VMA_UNSUPP) {
		pr_err("Unsupported mapping found %016"PRIx64"-%016"PRIx64"\n",
					vma_area->e->start, vma_area->e->end);
		return -1;
	}

	/* Add a guard page only if here is enough space for it */
	if ((vma_area->e->flags & MAP_GROWSDOWN) &&
	    *prev_end < vma_area->e->start)
		vma_area->e->start -= PAGE_SIZE; /* Guard page */
	*prev_end = vma_area->e->end;

	list_add_tail(&vma_area->list, &vma_area_list->h);
	vma_area_list->nr++;
	if (vma_area_is_private(vma_area, kdat.task_size)) {
		unsigned long pages;

		pages = vma_area_len(vma_area) / PAGE_SIZE;
		vma_area_list->priv_size += pages;
		vma_area_list->priv_longest = max(vma_area_list->priv_longest, pages);
	} else if (vma_area_is(vma_area, VMA_ANON_SHARED)) {
		unsigned long pages;

		pages = vma_area_len(vma_area) / PAGE_SIZE;
		vma_area_list->shared_longest =
			max(vma_area_list->shared_longest, pages);
	}

	*prev_vfi = *vfi;
	prev_vfi->vma = vma_area;

	return 0;
}

int parse_smaps(pid_t pid, struct vm_area_list *vma_area_list,
					dump_filemap_t dump_filemap)
{
	struct vma_area *vma_area = NULL;
	unsigned long start, end, pgoff, prev_end = 0;
	char r, w, x, s;
	int ret = -1, vm_file_fd = -1;
	struct vma_file_info vfi;
	struct vma_file_info prev_vfi = {};

	DIR *map_files_dir = NULL;
	struct bfd f;

	vma_area_list->nr = 0;
	vma_area_list->nr_aios = 0;
	vma_area_list->priv_longest = 0;
	vma_area_list->priv_size = 0;
	vma_area_list->shared_longest = 0;
	INIT_LIST_HEAD(&vma_area_list->h);

	f.fd = open_proc(pid, "smaps");
	if (f.fd < 0)
		goto err_n;

	if (bfdopenr(&f))
		goto err_n;

	map_files_dir = opendir_proc(pid, "map_files");
	if (!map_files_dir) /* old kernel? */
		goto err;

	while (1) {
		int num, path_off;
		bool eof;
		char *str;

		str = breadline(&f);
		if (IS_ERR(str))
			goto err;
		eof = (str == NULL);

		if (!eof && !is_vma_range_fmt(str)) {
			if (!strncmp(str, "Nonlinear", 9)) {
				BUG_ON(!vma_area);
				pr_err("Nonlinear mapping found %016"PRIx64"-%016"PRIx64"\n",
				       vma_area->e->start, vma_area->e->end);
				/*
				 * VMA is already on list and will be
				 * freed later as list get destroyed.
				 */
				vma_area = NULL;
				goto err;
			} else if (!strncmp(str, "VmFlags: ", 9)) {
				BUG_ON(!vma_area);
				if (parse_vmflags(&str[9], vma_area))
					goto err;
				continue;
			} else
				continue;
		}

		if (vma_area && vma_list_add(vma_area, vma_area_list,
						&prev_end, &vfi, &prev_vfi))
			goto err;

		if (eof)
			break;

		vma_area = alloc_vma_area();
		if (!vma_area)
			goto err;

		num = sscanf(str, "%lx-%lx %c%c%c%c %lx %x:%x %lu %n",
			     &start, &end, &r, &w, &x, &s, &pgoff,
			     &vfi.dev_maj, &vfi.dev_min, &vfi.ino, &path_off);
		if (num < 10) {
			pr_err("Can't parse: %s\n", str);
			goto err;
		}

		vma_area->e->start	= start;
		vma_area->e->end	= end;
		vma_area->e->pgoff	= pgoff;
		vma_area->e->prot	= PROT_NONE;

		if (r == 'r')
			vma_area->e->prot |= PROT_READ;
		if (w == 'w')
			vma_area->e->prot |= PROT_WRITE;
		if (x == 'x')
			vma_area->e->prot |= PROT_EXEC;

		if (s == 's')
			vma_area->e->flags = MAP_SHARED;
		else if (s == 'p')
			vma_area->e->flags = MAP_PRIVATE;
		else {
			pr_err("Unexpected VMA met (%c)\n", s);
			goto err;
		}

		if (handle_vma(pid, vma_area, str + path_off, map_files_dir,
				&vfi, &prev_vfi, &vm_file_fd))
			goto err;

		if (vma_entry_is(vma_area->e, VMA_FILE_PRIVATE) ||
				vma_entry_is(vma_area->e, VMA_FILE_SHARED)) {
			if (dump_filemap && dump_filemap(vma_area, vm_file_fd))
				goto err;
		} else if (vma_entry_is(vma_area->e, VMA_AREA_AIORING))
			vma_area_list->nr_aios++;
	}

	vma_area = NULL;
	ret = 0;

err:
	bclose(&f);
err_n:
	close_safe(&vm_file_fd);
	if (map_files_dir)
		closedir(map_files_dir);

	xfree(vma_area);
	return ret;

}

int parse_pid_stat(pid_t pid, struct proc_pid_stat *s)
{
	char *tok, *p;
	int fd;
	int n;

	fd = open_proc(pid, "stat");
	if (fd < 0)
		return -1;

	n = read(fd, buf, BUF_SIZE);
	close(fd);
	if (n < 1) {
		pr_err("stat for %d is corrupted\n", pid);
		return -1;
	}

	memset(s, 0, sizeof(*s));

	tok = strchr(buf, ' ');
	if (!tok)
		goto err;
	*tok++ = '\0';
	if (*tok != '(')
		goto err;

	s->pid = atoi(buf);

	p = strrchr(tok + 1, ')');
	if (!p)
		goto err;
	*tok = '\0';
	*p = '\0';

	strlcpy(s->comm, tok + 1, sizeof(s->comm));

	n = sscanf(p + 1,
	       " %c %d %d %d %d %d %u %lu %lu %lu %lu "
	       "%lu %lu %ld %ld %ld %ld %d %d %llu %lu %ld %lu %lu %lu %lu "
	       "%lu %lu %lu %lu %lu %lu %lu %lu %lu %d %d %u %u %llu %lu %ld "
	       "%lu %lu %lu %lu %lu %lu %lu %d",
		&s->state,
		&s->ppid,
		&s->pgid,
		&s->sid,
		&s->tty_nr,
		&s->tty_pgrp,
		&s->flags,
		&s->min_flt,
		&s->cmin_flt,
		&s->maj_flt,
		&s->cmaj_flt,
		&s->utime,
		&s->stime,
		&s->cutime,
		&s->cstime,
		&s->priority,
		&s->nice,
		&s->num_threads,
		&s->zero0,
		&s->start_time,
		&s->vsize,
		&s->mm_rss,
		&s->rsslim,
		&s->start_code,
		&s->end_code,
		&s->start_stack,
		&s->esp,
		&s->eip,
		&s->sig_pending,
		&s->sig_blocked,
		&s->sig_ignored,
		&s->sig_handled,
		&s->wchan,
		&s->zero1,
		&s->zero2,
		&s->exit_signal,
		&s->task_cpu,
		&s->rt_priority,
		&s->policy,
		&s->delayacct_blkio_ticks,
		&s->gtime,
		&s->cgtime,
		&s->start_data,
		&s->end_data,
		&s->start_brk,
		&s->arg_start,
		&s->arg_end,
		&s->env_start,
		&s->env_end,
		&s->exit_code);
	if (n < 50)
		goto err;

	return 0;

err:
	pr_err("Parsing %d's stat failed (#fields do not match)\n", pid);
	return -1;
}

int prepare_loginuid(unsigned int value, unsigned int loglevel)
{
	int fd, ret = 0;
	char buf[11]; /* 4294967295 is maximum for u32 */

	fd = open_proc_rw(PROC_SELF, "loginuid");
	if (fd < 0)
		return -1;

	snprintf(buf, 11, "%u", value);

	if (write(fd, buf, 11) < 0) {
		print_on_level(loglevel,
			"Write %s to /proc/self/loginuid failed: %s",
			buf, strerror(errno));
		ret = -1;
	}
	close(fd);
	return ret;
}

unsigned int parse_pid_loginuid(pid_t pid, int *err, bool ignore_noent)
{
	int fd;
	ssize_t num;

	*err = 0;
	fd = __open_proc(pid, (ignore_noent) ? ENOENT : 0,
			O_RDONLY, "loginuid");
	if (fd < 0)
		goto out;

	num = read(fd, buf, 10);
	close(fd);
	if (num < 0) {
		pr_perror("Unable to read /proc/%d/loginuid", pid);
		goto out;
	}
	buf[num] = '\0';

	return strtol(buf, NULL, 10);

out:
	*err = -1;
	return INVALID_UID; /* unset value */
}

int parse_pid_oom_score_adj(pid_t pid, int *err)
{
	int fd;
	ssize_t num;

	*err = 0;
	fd = open_proc(pid, "oom_score_adj");
	if (fd < 0)
		goto out;

	num = read(fd, buf, 10);
	close(fd);
	if (num < 0) {
		pr_perror("Unable to read /proc/%d/oom_score_adj", pid);
		goto out;
	}
	buf[num] = '\0';

	return strtol(buf, NULL, 10);

out:
	*err = -1;
	return 0;
}

static int ids_parse(char *str, unsigned int *arr)
{
	char *end;

	arr[0] = strtol(str, &end, 10);
	arr[1] = strtol(end + 1, &end, 10);
	arr[2] = strtol(end + 1, &end, 10);
	arr[3] = strtol(end + 1, &end, 10);
	if (*end)
		return -1;
	else
		return 0;
}

static int cap_parse(char *str, unsigned int *res)
{
	int i, ret;

	for (i = 0; i < PROC_CAP_SIZE; i++) {
		ret = sscanf(str, "%08x", &res[PROC_CAP_SIZE - 1 - i]);
		if (ret != 1)
			return -1;
		str += 8;
	}

	return 0;
}

int parse_pid_status(pid_t pid, struct proc_status_creds *cr)
{
	struct bfd f;
	int done = 0;
	int ret = -1;
	char *str;
	bool parsed_seccomp = false;

	f.fd = open_proc(pid, "status");
	if (f.fd < 0)
		return -1;

	cr->sigpnd = 0;
	cr->shdpnd = 0;

	if (bfdopenr(&f))
		return -1;

	while (done < 12) {
		str = breadline(&f);
		if (str == NULL)
			break;
		if (IS_ERR(str))
			goto err_parse;

		if (!strncmp(str, "State:", 6)) {
			cr->state = str[7];
			done++;
			continue;
		}

		if (!strncmp(str, "PPid:", 5)) {
			if (sscanf(str, "PPid:\t%d", &cr->ppid) != 1) {
				pr_err("Unable to parse: %s\n", str);
				goto err_parse;
			}
			done++;
			continue;
		}

		if (!strncmp(str, "Uid:", 4)) {
			if (ids_parse(str + 5, cr->uids))
				goto err_parse;

			done++;
			continue;
		}

		if (!strncmp(str, "Gid:", 4)) {
			if (ids_parse(str + 5, cr->gids))
				goto err_parse;

			done++;
			continue;
		}

		if (!strncmp(str, "CapInh:", 7)) {
			if (cap_parse(str + 8, cr->cap_inh))
				goto err_parse;

			done++;
			continue;
		}

		if (!strncmp(str, "CapEff:", 7)) {
			if (cap_parse(str + 8, cr->cap_eff))
				goto err_parse;

			done++;
			continue;
		}

		if (!strncmp(str, "CapPrm:", 7)) {
			if (cap_parse(str + 8, cr->cap_prm))
				goto err_parse;

			done++;
			continue;
		}

		if (!strncmp(str, "CapBnd:", 7)) {
			if (cap_parse(str + 8, cr->cap_bnd))
				goto err_parse;

			done++;
			continue;
		}

		if (!strncmp(str, "Seccomp:", 8)) {
			if (sscanf(str + 9, "%d", &cr->seccomp_mode) != 1) {
				goto err_parse;
			}

			parsed_seccomp = true;
			done++;
			continue;
		}

		if (!strncmp(str, "ShdPnd:", 7)) {
			unsigned long long sigpnd;

			if (sscanf(str + 7, "%llx", &sigpnd) != 1)
				goto err_parse;
			cr->shdpnd |= sigpnd;

			done++;
			continue;
		}
		if (!strncmp(str, "SigPnd:", 7)) {
			unsigned long long sigpnd;

			if (sscanf(str + 7, "%llx", &sigpnd) != 1)
				goto err_parse;
			cr->sigpnd |= sigpnd;

			done++;
			continue;
		}
	}

	/* seccomp is optional */
	if (done >= 11 || (done == 10 && !parsed_seccomp))
		ret = 0;

err_parse:
	if (ret)
		pr_err("Error parsing proc status file\n");
	bclose(&f);
	return ret;
}

struct opt2flag {
	char *opt;
	unsigned flag;
};

static bool sb_opt_cb(char *opt, char *unknown, size_t *uoff)
{
	unsigned int id;

	if (sscanf(opt, "gid=%d", &id) == 1) {
		*uoff += sprintf(unknown + *uoff, "gid=%d", userns_gid(id));
		unknown[*uoff] = ',';
		(*uoff)++;
		return true;
	} else if (sscanf(opt, "uid=%d", &id) == 1) {
		*uoff += sprintf(unknown + *uoff, "uid=%d", userns_uid(id));
		unknown[*uoff] = ',';
		(*uoff)++;
		return true;
	}
	return false;
}

static int do_opt2flag(char *opt, unsigned *flags,
		const struct opt2flag *opts, char *unknown,
		bool (*cb)(char *opt, char *unknown, size_t *uoff))
{
	int i;
	char *end;
	size_t uoff = 0;

	while (1) {
		end = strchr(opt, ',');
		if (end)
			*end = '\0';

		for (i = 0; opts[i].opt != NULL; i++)
			if (!strcmp(opts[i].opt, opt)) {
				(*flags) |= opts[i].flag;
				break;
			}

		if (opts[i].opt == NULL && cb && !cb(opt, unknown, &uoff)) {
			if (!unknown) {
				pr_err("Unknown option [%s]\n", opt);
				return -1;
			}

			strcpy(unknown + uoff, opt);
			uoff += strlen(opt);
			unknown[uoff] = ',';
			uoff++;
		}

		if (!end) {
			if (uoff)
				uoff--;
			if (unknown)
				unknown[uoff] = '\0';
			break;
		} else
			opt = end + 1;
	}

	return 0;
}

static int parse_mnt_flags(char *opt, unsigned *flags)
{
	static const struct opt2flag mnt_opt2flag[] = {
		{ "rw",		0,		},
		{ "ro",		MS_RDONLY,	},
		{ "nosuid",	MS_NOSUID,	},
		{ "nodev",	MS_NODEV,	},
		{ "noexec",	MS_NOEXEC,	},
		{ "noatime",	MS_NOATIME,	},
		{ "nodiratime",	MS_NODIRATIME,	},
		{ "relatime",	MS_RELATIME,	},
		{ },
	};

	if (do_opt2flag(opt, flags, mnt_opt2flag, NULL, NULL))
		return -1;

	/* Otherwise the kernel assumes RELATIME by default */
	if ((*flags & (MS_RELATIME | MS_NOATIME)) == 0)
		*flags |= MS_STRICTATIME;

	return 0;
}

static int parse_sb_opt(char *opt, unsigned *flags, char *uopt)
{
	static const struct opt2flag sb_opt2flag[] = {
		{ "rw",		0,		},
		{ "ro",		MS_RDONLY,	},
		{ "sync",	MS_SYNC,	},
		{ "dirsync",	MS_DIRSYNC,	},
		{ "mad",	MS_MANDLOCK,	},
		{ },
	};

	return do_opt2flag(opt, flags, sb_opt2flag, uopt, sb_opt_cb);
}

static int parse_mnt_opt(char *str, struct mount_info *mi, int *off)
{
	char *istr = str, *end;

	while (1) {
		end = strchr(str, ' ');
		if (!end) {
			pr_err("Error parsing mount options\n");
			return -1;
		}

		*end = '\0';
		if (!strncmp(str, "-", 1))
			break;
		else if (!strncmp(str, "shared:", 7)) {
			mi->flags |= MS_SHARED;
			mi->shared_id = atoi(str + 7);
		} else if (!strncmp(str, "master:", 7)) {
			mi->flags |= MS_SLAVE;
			mi->master_id = atoi(str + 7);
		} else if (!strncmp(str, "propagate_from:", 15)) {
			/* skip */;
		} else if (!strncmp(str, "unbindable", 11))
			mi->flags |= MS_UNBINDABLE;
		else {
			pr_err("Unknown option [%s]\n", str);
			return -1;
		}

		str = end + 1;
	}

	*off = end - istr + 1;
	return 0;
}

/*
 * mountinfo contains mangled paths. space, tab and back slash were replaced
 * with usual octal escape. This function replaces these symbols back.
 */
static void cure_path(char *path)
{
	int i, len, off = 0;

	if (strchr(path, '\\') == NULL) /* fast path */
		return;

	len = strlen(path);
	for (i = 0; i < len; i++) {
		if (!strncmp(path + i, "\\040", 4)) {
			path[i - off] = ' ';
			goto replace;
		} else if (!strncmp(path + i, "\\011", 4)) {
			path[i - off] = '\t';
			goto replace;
		} else if (!strncmp(path + i, "\\134", 4)) {
			path[i - off] = '\\';
			goto replace;
		}
		if (off)
			path[i - off] = path[i];
		continue;
replace:
		off += 3;
		i += 3;
	}
	path[len - off] = 0;
}

static int parse_mountinfo_ent(char *str, struct mount_info *new, char **fsname)
{
	struct fd_link root_link;
	unsigned int kmaj, kmin;
	int ret, n;
	char *sub, *opt = NULL;

	new->mountpoint = xmalloc(PATH_MAX);
	if (new->mountpoint == NULL)
		goto err;

	new->mountpoint[0] = '.';
	ret = sscanf(str, "%i %i %u:%u %ms %s %ms %n",
			&new->mnt_id, &new->parent_mnt_id,
			&kmaj, &kmin, &new->root, new->mountpoint + 1,
			&opt, &n);
	if (ret != 7)
		goto err;

	cure_path(new->mountpoint);
	cure_path(new->root);

	root_link.len = strlen(new->root);
	strcpy(root_link.name, new->root);
	if (strip_deleted(&root_link)) {
		strcpy(new->root, root_link.name);
		new->deleted = true;
	}

	new->mountpoint = xrealloc(new->mountpoint, strlen(new->mountpoint) + 1);
	if (!new->mountpoint)
		goto err;
	new->ns_mountpoint = new->mountpoint;
	new->is_ns_root = is_root(new->ns_mountpoint + 1);

	new->s_dev = new->s_dev_rt = MKKDEV(kmaj, kmin);
	new->flags = 0;
	if (parse_mnt_flags(opt, &new->flags))
		goto err;

	free(opt); /* we are going to reallocate/reuse this buffer */
	opt = NULL;

	str += n;
	if (parse_mnt_opt(str, new, &n))
		goto err;

	str += n;
	ret = sscanf(str, "%ms %ms %ms", fsname, &new->source, &opt);
	if (ret == 2) {
		/* src may be empty */
		opt = new->source;
		new->source = xstrdup("");
		if (new->source == NULL)
			goto err;
	} else if (ret != 3)
		goto err;

	cure_path(new->source);

	new->fsname = xstrdup(*fsname);
	if (!new->fsname)
		goto err;

	/*
	 * The kernel reports "subtypes" sometimes and the valid
	 * type-vs-subtype delimiter is the dot symbol. We disregard
	 * any subtypes for the purpose of finding the fstype.
	 */
	sub = strchr(*fsname, '.');
	if (sub)
		*sub = 0;

	new->fstype = find_fstype_by_name(*fsname);

	new->options = xmalloc(strlen(opt) + 1);
	if (!new->options)
		goto err;

	if (parse_sb_opt(opt, &new->sb_flags, new->options))
		goto err;

	ret = 0;
ret:
	xfree(opt);
	return ret;
err:
	ret = -1;
	goto ret;
}

static LIST_HEAD(skip_mount_list);

struct str_node {
	struct list_head node;
	char string[];
};

bool add_skip_mount(const char *mountpoint)
{
	struct str_node *skip = xmalloc(sizeof(struct str_node) +
					strlen(mountpoint) + 1);
	if (!skip)
		return false;

	strcpy(skip->string, mountpoint);
	list_add(&skip->node, &skip_mount_list);
	return true;
}

static bool should_skip_mount(const char *mountpoint)
{
	struct str_node *pos;

	list_for_each_entry(pos, &skip_mount_list, node) {
		if (strcmp(mountpoint, pos->string) == 0)
			return true;
	}

	return false;
}

struct mount_info *parse_mountinfo(pid_t pid, struct ns_id *nsid, bool for_dump)
{
	struct mount_info *list = NULL;
	FILE *f;

	f = fopen_proc(pid, "mountinfo");
	if (!f)
		return NULL;

	while (fgets(buf, BUF_SIZE, f)) {
		struct mount_info *new;
		int ret = -1;
		char *fsname = NULL;

		new = mnt_entry_alloc();
		if (!new)
			goto end;

		new->nsid = nsid;

		ret = parse_mountinfo_ent(buf, new, &fsname);
		if (ret < 0) {
			pr_err("Bad format in %d mountinfo: '%s'\n", pid, buf);
			goto end;
		}

		/*
		 * Drop this mountpoint early, so that lookup_mnt_id/etc will
		 * fail loudly at "dump" stage if an opened file or another mnt
		 * depends on this one.
		 */
		if (for_dump && should_skip_mount(new->mountpoint + 1)) {
			pr_info("\tskip %s @ %s\n", fsname,  new->mountpoint);
			mnt_entry_free(new);
			new = NULL;
			goto end;
		}

		pr_info("\ttype %s source %s mnt_id %d s_dev %#x %s @ %s flags %#x options %s\n",
				fsname, new->source,
				new->mnt_id, new->s_dev, new->root, new->mountpoint,
				new->flags, new->options);

		if (new->fstype->parse) {
			ret = new->fstype->parse(new);
			if (ret < 0) {
				pr_err("Failed to parse FS specific data on %s\n",
						new->mountpoint);
				mnt_entry_free(new);
				new = NULL;
				goto end;
			}

			if (ret > 0) {
				pr_info("\tskipping fs mounted at %s\n", new->mountpoint + 1);
				mnt_entry_free(new);
				new = NULL;
				ret = 0;
				goto end;

			}
		}
end:
		if (fsname)
			free(fsname);

		if (new) {
			new->next = list;
			list = new;
		}

		if (ret)
			goto err;
	}
out:
	fclose(f);
	return list;

err:
	while (list) {
		struct mount_info *next = list->next;
		mnt_entry_free(list);
		list = next;
	}
	goto out;
}

static char nybble(const char n)
{
	if (n >= '0' && n <= '9')
		return n - '0';
	else if (n >= 'A' && n <= 'F')
		return n - ('A' - 10);
	else if (n >= 'a' && n <= 'f')
		return n - ('a' - 10);
	return 0;
}

static int alloc_fhandle(FhEntry *fh)
{
	fh->n_handle = FH_ENTRY_SIZES__min_entries;
	fh->handle = xmalloc(pb_repeated_size(fh, handle));

	return fh->handle == NULL ? -1 : 0;
}

static void free_fhandle(FhEntry *fh)
{
	if (fh->handle)
		xfree(fh->handle);
}

void free_inotify_wd_entry(union fdinfo_entries *e)
{
	free_fhandle(e->ify.e.f_handle);
	xfree(e);
}

void free_fanotify_mark_entry(union fdinfo_entries *e)
{
	if (e->ffy.e.ie)
		free_fhandle(e->ffy.ie.f_handle);
	xfree(e);
}

void free_event_poll_entry(union fdinfo_entries *e)
{
	xfree(e);
}

static void parse_fhandle_encoded(char *tok, FhEntry *fh)
{
	char *d = (char *)fh->handle;
	int i = 0;

	memzero(d, pb_repeated_size(fh, handle));

	while (*tok == ' ')
		tok++;

	while (*tok) {
		if (i >= pb_repeated_size(fh, handle))
			break;
		d[i++] = (nybble(tok[0]) << 4) | nybble(tok[1]);
		if (tok[1])
			tok += 2;
		else
			break;
	}
}

static int parse_timerfd(struct bfd *f, char *str, TimerfdEntry *tfy)
{
	/*
	 * Format is
	 * clockid: 0
	 * ticks: 0
	 * settime flags: 01
	 * it_value: (0, 49406829)
	 * it_interval: (1, 0)
	 */
	if (sscanf(str, "clockid: %d", &tfy->clockid) != 1)
		goto parse_err;

	if (verify_timerfd(tfy) < 0)
		goto parse_err;

	str = breadline(f);
	if (IS_ERR_OR_NULL(str))
		goto nodata;
	if (sscanf(str, "ticks: %llu", (unsigned long long *)&tfy->ticks) != 1)
		goto parse_err;

	str = breadline(f);
	if (IS_ERR_OR_NULL(str))
		goto nodata;
	if (sscanf(str, "settime flags: 0%o", &tfy->settime_flags) != 1)
		goto parse_err;

	str = breadline(f);
	if (IS_ERR_OR_NULL(str))
		goto nodata;
	if (sscanf(str, "it_value: (%llu, %llu)",
		   (unsigned long long *)&tfy->vsec,
		   (unsigned long long *)&tfy->vnsec) != 2)
		goto parse_err;

	str = breadline(f);
	if (IS_ERR_OR_NULL(str))
		goto nodata;
	if (sscanf(str, "it_interval: (%llu, %llu)",
		   (unsigned long long *)&tfy->isec,
		   (unsigned long long *)&tfy->insec) != 2)
		goto parse_err;
	return 0;

parse_err:
	return -1;
nodata:
	pr_err("No data left in proc file while parsing timerfd\n");
	goto parse_err;
}

#define fdinfo_field(str, field)	!strncmp(str, field":", sizeof(field))

static int parse_file_lock_buf(char *buf, struct file_lock *fl,
				bool is_blocked);
static int parse_fdinfo_pid_s(int pid, int fd, int type,
		int (*cb)(union fdinfo_entries *e, void *arg), void *arg)
{
	struct bfd f;
	char *str;
	bool entry_met = false;
	int ret, exit_code = -1;;

	f.fd = open_proc(pid, "fdinfo/%d", fd);
	if (f.fd < 0)
		return -1;

	if (bfdopenr(&f))
		return -1;

	while (1) {
		union fdinfo_entries entry;

		str = breadline(&f);
		if (!str)
			break;
		if (IS_ERR(str))
			goto out;

		if (fdinfo_field(str, "pos") ||
		    fdinfo_field(str, "flags") ||
		    fdinfo_field(str, "mnt_id")) {
			unsigned long long val;
			struct fdinfo_common *fdinfo = arg;

			if (type != FD_TYPES__UND)
				continue;
			ret = sscanf(str, "%*s %lli", &val);
			if (ret != 1)
				goto parse_err;

			if (fdinfo_field(str, "pos"))
				fdinfo->pos = val;
			else if (fdinfo_field(str, "flags"))
				fdinfo->flags = val;
			else if (fdinfo_field(str, "mnt_id"))
				fdinfo->mnt_id = val;

			entry_met = true;
			continue;
		}

		if (fdinfo_field(str, "lock")) {
			struct file_lock *fl;
			struct fdinfo_common *fdinfo = arg;

			if (type != FD_TYPES__UND)
				continue;

			fl = alloc_file_lock();
			if (!fl) {
				pr_perror("Alloc file lock failed!");
				goto out;
			}

			if (parse_file_lock_buf(str + 6, fl, 0)) {
				xfree(fl);
				goto parse_err;
			}

			pr_info("lockinfo: %lld:%d %x %d %02x:%02x:%ld %lld %s\n",
				fl->fl_id, fl->fl_kind, fl->fl_ltype,
				fl->fl_owner, fl->maj, fl->min, fl->i_no,
				fl->start, fl->end);


			if (fl->fl_kind == FL_UNKNOWN) {
				pr_err("Unknown file lock!\n");
				xfree(fl);
				goto out;
			}

			fl->real_owner = fdinfo->owner;
			fl->owners_fd = fd;
			list_add_tail(&fl->list, &file_lock_list);
		}

		if (type == FD_TYPES__UND)
			continue;

		if (fdinfo_field(str, "eventfd-count")) {
			eventfd_file_entry__init(&entry.efd);

			if (type != FD_TYPES__EVENTFD)
				goto parse_err;
			ret = sscanf(str, "eventfd-count: %"PRIx64,
					&entry.efd.counter);
			if (ret != 1)
				goto parse_err;
			ret = cb(&entry, arg);
			if (ret)
				goto out;

			entry_met = true;
			continue;
		}
		if (fdinfo_field(str, "clockid")) {
			timerfd_entry__init(&entry.tfy);

			if (type != FD_TYPES__TIMERFD)
				goto parse_err;
			ret = parse_timerfd(&f, str, &entry.tfy);
			if (ret)
				goto parse_err;
			ret = cb(&entry, arg);
			if (ret)
				goto out;

			entry_met = true;
			continue;
		}
		if (fdinfo_field(str, "tfd")) {
			union fdinfo_entries *e;

			if (type != FD_TYPES__EVENTPOLL)
				goto parse_err;

			e = xmalloc(sizeof(union fdinfo_entries));
			if (!e)
				goto out;

			eventpoll_tfd_entry__init(&e->epl.e);

			ret = sscanf(str, "tfd: %d events: %x data: %"PRIx64,
					&e->epl.e.tfd, &e->epl.e.events, &e->epl.e.data);
			if (ret != 3) {
				free_event_poll_entry(e);
				goto parse_err;
			}
			ret = cb(e, arg);
			if (ret)
				goto out;

			entry_met = true;
			continue;
		}
		if (fdinfo_field(str, "sigmask")) {
			signalfd_entry__init(&entry.sfd);

			if (type != FD_TYPES__SIGNALFD)
				goto parse_err;
			ret = sscanf(str, "sigmask: %Lx",
					(unsigned long long *)&entry.sfd.sigmask);
			if (ret != 1)
				goto parse_err;
			ret = cb(&entry, arg);
			if (ret)
				goto out;

			entry_met = true;
			continue;
		}
		if (fdinfo_field(str, "fanotify flags")) {
			struct fsnotify_params *p = arg;

			if (type != FD_TYPES__FANOTIFY)
				goto parse_err;

			ret = sscanf(str, "fanotify flags:%x event-flags:%x",
				     &p->faflags, &p->evflags);
			if (ret != 2)
				goto parse_err;
			entry_met = true;
			continue;
		}
		if (fdinfo_field(str, "fanotify ino")) {
			union fdinfo_entries *e;
			int hoff = 0;

			if (type != FD_TYPES__FANOTIFY)
				goto parse_err;

			e = xmalloc(sizeof(*e));
			if (!e)
				goto parse_err;

			fanotify_mark_entry__init(&e->ffy.e);
			fanotify_inode_mark_entry__init(&e->ffy.ie);
			fh_entry__init(&e->ffy.f_handle);
			e->ffy.e.ie = &e->ffy.ie;
			e->ffy.ie.f_handle = &e->ffy.f_handle;

			ret = sscanf(str,
				     "fanotify ino:%"PRIx64" sdev:%x mflags:%x mask:%x ignored_mask:%x "
				     "fhandle-bytes:%x fhandle-type:%x f_handle: %n",
				     &e->ffy.ie.i_ino, &e->ffy.e.s_dev,
				     &e->ffy.e.mflags, &e->ffy.e.mask, &e->ffy.e.ignored_mask,
				     &e->ffy.f_handle.bytes, &e->ffy.f_handle.type,
				     &hoff);
			if (ret != 7 || hoff == 0) {
				free_fanotify_mark_entry(e);
				goto parse_err;
			}

			if (alloc_fhandle(&e->ffy.f_handle)) {
				free_fanotify_mark_entry(e);
				goto out;
			}
			parse_fhandle_encoded(str + hoff, &e->ffy.f_handle);

			e->ffy.e.type = MARK_TYPE__INODE;
			ret = cb(e, arg);


			if (ret)
				goto out;

			entry_met = true;
			continue;
		}
		if (fdinfo_field(str, "fanotify mnt_id")) {
			union fdinfo_entries *e;

			if (type != FD_TYPES__FANOTIFY)
				goto parse_err;

			e = xmalloc(sizeof(*e));
			if (!e)
				goto parse_err;

			fanotify_mark_entry__init(&e->ffy.e);
			fanotify_mount_mark_entry__init(&e->ffy.me);
			e->ffy.e.me = &e->ffy.me;

			ret = sscanf(str,
				     "fanotify mnt_id:%x mflags:%x mask:%x ignored_mask:%x",
				     &e->ffy.e.me->mnt_id, &e->ffy.e.mflags,
				     &e->ffy.e.mask, &e->ffy.e.ignored_mask);
			if (ret != 4)
				goto parse_err;

			e->ffy.e.type = MARK_TYPE__MOUNT;
			ret = cb(e, arg);
			if (ret)
				goto out;

			entry_met = true;
			continue;
		}
		if (fdinfo_field(str, "inotify wd")) {
			InotifyWdEntry *ify;
			union fdinfo_entries *e;
			int hoff;

			if (type != FD_TYPES__INOTIFY)
				goto parse_err;

			e = xmalloc(sizeof(*e));
			if (!e)
				goto parse_err;
			ify = &e->ify.e;

			inotify_wd_entry__init(ify);
			ify->f_handle = &e->ify.f_handle;
			fh_entry__init(ify->f_handle);

			ret = sscanf(str,
					"inotify wd:%x ino:%"PRIx64" sdev:%x "
					"mask:%x ignored_mask:%x "
					"fhandle-bytes:%x fhandle-type:%x "
					"f_handle: %n",
					&ify->wd, &ify->i_ino, &ify->s_dev,
					&ify->mask, &ify->ignored_mask,
					&ify->f_handle->bytes, &ify->f_handle->type,
					&hoff);
			if (ret != 7) {
				free_inotify_wd_entry(e);
				goto parse_err;
			}

			if (alloc_fhandle(ify->f_handle)) {
				free_inotify_wd_entry(e);
				goto out;
			}

			parse_fhandle_encoded(str + hoff, ify->f_handle);

			ret = cb(e, arg);

			if (ret)
				goto out;

			entry_met = true;
			continue;
		}
	}

	exit_code = 0;
	if (entry_met)
		goto out;
	/*
	 * An eventpoll/inotify file may have no target fds set thus
	 * resulting in no tfd: lines in proc. This is normal.
	 */
	if (type == FD_TYPES__EVENTPOLL || type == FD_TYPES__INOTIFY)
		goto out;

	pr_err("No records of type %d found in fdinfo file\n", type);
parse_err:
	exit_code = -1;
	pr_perror("%s: error parsing [%s] for %d", __func__, str, type);
out:
	bclose(&f);
	return exit_code;
}

int parse_fdinfo_pid(int pid, int fd, int type,
		int (*cb)(union fdinfo_entries *e, void *arg), void *arg)
{
	return parse_fdinfo_pid_s(pid, fd, type, cb, arg);
}

int parse_fdinfo(int fd, int type,
		int (*cb)(union fdinfo_entries *e, void *arg), void *arg)
{
	return parse_fdinfo_pid_s(PROC_SELF, fd, type, cb, arg);
}

int get_fd_mntid(int fd, int *mnt_id)
{
	struct fdinfo_common fdinfo = { .mnt_id = -1};

	if (parse_fdinfo(fd, FD_TYPES__UND, NULL, &fdinfo))
		return -1;

	*mnt_id = fdinfo.mnt_id;
	return 0;
}

static int parse_file_lock_buf(char *buf, struct file_lock *fl,
				bool is_blocked)
{
	int  num;
	char fl_flag[10], fl_type[15], fl_option[10];

	if (is_blocked) {
		num = sscanf(buf, "%lld: -> %s %s %s %d %x:%x:%ld %lld %s",
			&fl->fl_id, fl_flag, fl_type, fl_option,
			&fl->fl_owner, &fl->maj, &fl->min, &fl->i_no,
			&fl->start, fl->end);
	} else {
		num = sscanf(buf, "%lld:%s %s %s %d %x:%x:%ld %lld %s",
			&fl->fl_id, fl_flag, fl_type, fl_option,
			&fl->fl_owner, &fl->maj, &fl->min, &fl->i_no,
			&fl->start, fl->end);
	}

	if (num < 10) {
		pr_err("Invalid file lock info (%d): %s\n", num, buf);
		return -1;
	}

	if (!strcmp(fl_flag, "POSIX"))
		fl->fl_kind = FL_POSIX;
	else if (!strcmp(fl_flag, "FLOCK"))
		fl->fl_kind = FL_FLOCK;
	else if (!strcmp(fl_flag, "OFDLCK"))
		fl->fl_kind = FL_OFD;
	else
		fl->fl_kind = FL_UNKNOWN;

	if (!strcmp(fl_type, "MSNFS")) {
		fl->fl_ltype |= LOCK_MAND;

		if (!strcmp(fl_option, "READ")) {
			fl->fl_ltype |= LOCK_READ;
		} else if (!strcmp(fl_option, "RW")) {
			fl->fl_ltype |= LOCK_RW;
		} else if (!strcmp(fl_option, "WRITE")) {
			fl->fl_ltype |= LOCK_WRITE;
		} else {
			pr_err("Unknown lock option!\n");
			return -1;
		}
	} else {
		if (!strcmp(fl_option, "UNLCK")) {
			fl->fl_ltype |= F_UNLCK;
		} else if (!strcmp(fl_option, "WRITE")) {
			fl->fl_ltype |= F_WRLCK;
		} else if (!strcmp(fl_option, "READ")) {
			fl->fl_ltype |= F_RDLCK;
		} else {
			pr_err("Unknown lock option!\n");
			return -1;
		}
	}

	return 0;
}

static bool pid_in_pstree(pid_t pid)
{
	return pstree_item_by_real(pid) != NULL;
}

int parse_file_locks(void)
{
	struct file_lock *fl;

	FILE	*fl_locks;
	int	exit_code = -1;
	bool	is_blocked;

	if (kdat.has_fdinfo_lock)
		return 0;

	fl_locks = fopen_proc(PROC_GEN, "locks");
	if (!fl_locks)
		return -1;

	while (fgets(buf, BUF_SIZE, fl_locks)) {
		is_blocked = strstr(buf, "->") != NULL;

		fl = alloc_file_lock();
		if (!fl) {
			pr_perror("Alloc file lock failed!");
			goto err;
		}

		if (parse_file_lock_buf(buf, fl, is_blocked)) {
			xfree(fl);
			goto err;
		}

		pr_info("lockinfo: %lld:%d %x %d %02x:%02x:%ld %lld %s\n",
			fl->fl_id, fl->fl_kind, fl->fl_ltype,
			fl->fl_owner, fl->maj, fl->min, fl->i_no,
			fl->start, fl->end);


		if (fl->fl_kind == FL_UNKNOWN) {
			pr_err("Unknown file lock: %s!\n", buf);
			xfree(fl);
			goto err;
		}

		if (is_blocked) {
			/*
			 * All target processes are stopped in this moment and
			 * can't wait any locks.
			 */
			pr_debug("Skip blocked processes\n");
			xfree(fl);
			continue;
		}

		if ((fl->fl_kind == FL_POSIX) &&
				!pid_in_pstree(fl->fl_owner)) {
			/*
			 * We only care about tasks which are taken
			 * into dump, so we only collect file locks
			 * belong to these tasks.
			 */
			xfree(fl);
			continue;
		}

		list_add_tail(&fl->list, &file_lock_list);
	}

	exit_code = 0;
err:
	fclose(fl_locks);
	return exit_code;
}

void free_posix_timers(struct proc_posix_timers_stat *st)
{
	while (!list_empty(&st->timers)) {
		struct proc_posix_timer *timer;
		timer = list_first_entry(&st->timers, struct proc_posix_timer, list);
		list_del(&timer->list);
		xfree(timer);
	}
}

int parse_posix_timers(pid_t pid, struct proc_posix_timers_stat *args)
{
	int exit_code = -1;
	int pid_t;
	int i = 0;

	struct bfd f;
	char *s;
	char sigpid[7];
	char tidpid[4];

	struct proc_posix_timer *timer = NULL;

	INIT_LIST_HEAD(&args->timers);
	args->timer_n = 0;

	f.fd = open_proc(pid, "timers");
	if (f.fd < 0)
		return -1;

	if (bfdopenr(&f))
		return -1;

	while (1) {
		char pbuf[17]; /* 16 + eol */

		s = breadline(&f);
		if (!s)
			break;
		if (IS_ERR(s))
			goto err;

		switch (i % 4) {
		case 0:
			timer = xzalloc(sizeof(struct proc_posix_timer));
			if (timer == NULL)
				goto err;

			if (sscanf(s, "ID: %ld",
						&timer->spt.it_id) != 1)
				goto err;
			break;
		case 1:
			if (sscanf(s, "signal: %d/%16s",
						&timer->spt.si_signo, pbuf) != 2)
				goto err;
			break;
		case 2:
			if (sscanf(s, "notify: %6[a-z]/%3[a-z].%d\n",
						sigpid, tidpid, &pid_t) != 3)
				goto err;
			break;
		case 3:
			if (sscanf(s, "ClockID: %d\n",
					&timer->spt.clock_id) != 1)
				goto err;

			timer->spt.sival_ptr = NULL;
			if (sscanf(pbuf, "%p", &timer->spt.sival_ptr) != 1 &&
			    strcmp(pbuf, "(null)")) {
				pr_err("Unable to parse '%s'\n", pbuf);
				goto err;
			}

			if ( tidpid[0] == 't') {
				timer->spt.it_sigev_notify = SIGEV_THREAD_ID;
			} else {
				switch (sigpid[0]) {
					case 's' :
						timer->spt.it_sigev_notify = SIGEV_SIGNAL;
						break;
					case 't' :
						timer->spt.it_sigev_notify = SIGEV_THREAD;
						break;
					default :
						timer->spt.it_sigev_notify = SIGEV_NONE;
						break;
				}
			}

			list_add(&timer->list, &args->timers);
			timer = NULL;
			args->timer_n++;
			break;
		}
		i++;
	}

	exit_code = 0;
out:
	bclose(&f);
	return exit_code;
err:
	xfree(timer);
	free_posix_timers(args);
	pr_perror("Parse error in posix timers proc file!");
	goto out;
}

int parse_threads(int pid, struct pid **_t, int *_n)
{
	struct dirent *de;
	DIR *dir;
	struct pid *t = NULL;
	int nr = 1;

	if (*_t)
		t = *_t;

	dir = opendir_proc(pid, "task");
	if (!dir)
		return -1;

	while ((de = readdir(dir))) {
		struct pid *tmp;

		/* We expect numbers only here */
		if (de->d_name[0] == '.')
			continue;

		if (*_t == NULL) {
			tmp = xrealloc(t, nr * sizeof(struct pid));
			if (!tmp) {
				xfree(t);
				return -1;
			}
			t = tmp;
			t[nr - 1].ns[0].virt = -1;
		}
		t[nr - 1].real = atoi(de->d_name);
		t[nr - 1].state = TASK_THREAD;
		nr++;
	}

	closedir(dir);

	if (*_t == NULL) {
		*_t = t;
		*_n = nr - 1;
	} else
		BUG_ON(nr - 1 != *_n);

	return 0;
}

int parse_cgroup_file(FILE *f, struct list_head *retl, unsigned int *n)
{
	while (fgets(buf, BUF_SIZE, f)) {
		struct cg_ctl *ncc, *cc;
		char *name, *path = NULL, *e;

		ncc = xmalloc(sizeof(*cc));
		if (!ncc)
			goto err;

		/*
		 * Typical output (':' is a separator here)
		 *
		 * 4:cpu,cpuacct:/
		 * 3:cpuset:/
		 * 2:name=systemd:/user.slice/user-1000.slice/session-1.scope
		 */
		name = strchr(buf, ':');
		if (name)
			path = strchr(++name, ':');
		if (!name || !path) {
			pr_err("Failed parsing cgroup %s\n", buf);
			xfree(ncc);
			goto err;
		}
		e = strchr(name, '\n');
		*path++ = '\0';
		if (e)
			*e = '\0';

		/*
		 * Controllers and their props might be
		 * configured the way some of them are
		 * not taken into the image for migration
		 * sake or container specifics.
		 */
		if (cgp_should_skip_controller(name)) {
			pr_debug("cg-prop: Skipping controller %s\n", name);
			xfree(ncc);
			continue;
		}

		ncc->name = xstrdup(name);
		ncc->path = xstrdup(path);
		ncc->cgns_prefix = 0;
		if (!ncc->name || !ncc->path) {
			xfree(ncc->name);
			xfree(ncc->path);
			xfree(ncc);
			goto err;
		}

		list_for_each_entry(cc, retl, l)
			if (strcmp(cc->name, name) >= 0)
				break;

		list_add_tail(&ncc->l, &cc->l);
		(*n)++;
	}

	return 0;

err:
	put_ctls(retl);
	return -1;
}

int parse_task_cgroup(int pid, struct parasite_dump_cgroup_args *args, struct list_head *retl, unsigned int *n)
{
	FILE *f;
	int ret;
	LIST_HEAD(internal);
	unsigned int n_internal = 0;
	struct cg_ctl *intern, *ext;

	f = fopen_proc(pid, "cgroup");
	if (!f)
		return -1;

	ret = parse_cgroup_file(f, retl, n);
	fclose(f);
	if (ret < 0)
		return -1;

	/* No parasite args, we're dumping criu's cg set, so we don't need to
	 * try and parse the "internal" cgroup set to find namespace
	 * boundaries.
	 */
	if (!args)
		return 0;

	f = fmemopen(args->contents, strlen(args->contents), "r");
	if (!f) {
		pr_perror("couldn't fmemopen cgroup buffer %s", args->contents);
		return -1;
	}

	ret = parse_cgroup_file(f, &internal, &n_internal);
	fclose(f);
	if (ret < 0) {
		pr_err("couldn't parse internal cgroup file\n");
		return -1;
	}

	/* Here's where we actually compute the cgns prefix. Consider a task
	 * in /foo/bar which has unshared its namespace at /foo. The internal
	 * path is /bar, but the external path is /foo/bar, and the cgns
	 * prefix is /foo. The algorithm is:
	 *
	 * // no cg ns unshare in this case
	 * if (internal == external)
	 *   continue;
	 * idx = find_suffix_pos(external, internal)
	 * cgns_prefix = external[:idx]
	 */
	list_for_each_entry(intern, &internal, l) {
		list_for_each_entry(ext, retl, l) {
			char *pos;

			if (strcmp(ext->name, intern->name))
				continue;

			/* If the cgroup namespace was unshared at / (or there
			 * is no cgroup namespace relative to criu), the paths
			 * are equal and we don't need to set a prefix.
			 */
			if (!strcmp(ext->path, intern->path))
				continue;

			/* +1 here to chop off the leading / */
			pos = ext->path + strlen(ext->path) - strlen(intern->path+1);
			if (strcmp(pos, intern->path+1)) {
				pr_err("invalid cgroup configuration, %s is not a suffix of %s\n", intern->path, ext->path);
				ret = -1;
				goto out;
			}

			ext->cgns_prefix = pos - ext->path;
			if (ext->path[ext->cgns_prefix-1] == '/')
				ext->cgns_prefix--;
		}
	}

out:
	put_ctls(&internal);
	return ret;
}

void put_ctls(struct list_head *l)
{
	struct cg_ctl *c, *n;

	list_for_each_entry_safe(c, n, l, l) {
		xfree(c->name);
		xfree(c->path);
		xfree(c);
	}
	INIT_LIST_HEAD(l);
}

/* Parse and create all the real controllers. This does not include things with
 * the "name=" prefix, e.g. systemd.
 */
int collect_controllers(struct list_head *cgroups, unsigned int *n_cgroups)
{
	int exit_code = -1;
	FILE *f;

	f = fopen_proc(PROC_SELF, "cgroup");
	if (f == NULL)
		return -1;

	while (fgets(buf, BUF_SIZE, f)) {
		struct cg_controller *nc = NULL;
		char *controllers, *off;

		controllers = strchr(buf, ':');
		if (!controllers) {
			pr_err("Unable to parse \"%s\"\n", buf);
			goto err;
		}
		controllers++;

		off = strchr(controllers, ':');
		if (!off) {
			pr_err("Unable to parse \"%s\"\n", buf);
			goto err;
		}
		*off = '\0';
		while (1) {
			off = strchr(controllers, ',');
			if (off)
				*off = '\0';

			if (!strncmp("name=", controllers, 5))
				goto skip;

			if (!nc) {
				nc = new_controller(controllers);
				if (!nc)
					goto err;
				list_add_tail(&nc->l, cgroups);
				(*n_cgroups)++;
			} else {
				void *m;
				char *n;

				nc->n_controllers++;
				m = xrealloc(nc->controllers, sizeof(char *) * nc->n_controllers);
				if (!m)
					goto err;

				nc->controllers = m;

				n = xstrdup(controllers);
				if (!n)
					goto err;

				nc->controllers[nc->n_controllers-1] = n;
			}
			
skip:
			if (!off)
				break;
			controllers = off + 1;
		}
	}

	exit_code = 0;
err:
	fclose(f);
	return exit_code;
}

/*
 * If an OverlayFS mountpoint is found in the mountinfo table,
 * we enable opts.overlayfs, which is a workaround for the
 * OverlayFS Kernel bug.
 *
 * See fixup_overlayfs for details.
 */
int overlayfs_parse(struct mount_info *new)
{
	opts.overlayfs = true;
	return 0;
}

/*
 * AUFS callback function to "fix up" the root pathname.
 * See sysfs_parse.c for details.
 */
int aufs_parse(struct mount_info *new)
{
	int ret = 0;

	if (!strcmp(new->mountpoint, "./")) {
		opts.aufs = true;
		ret = parse_aufs_branches(new);
	}

	return ret;
}

int parse_children(pid_t pid, pid_t **_c, int *_n)
{
	pid_t *ch = NULL;
	int nr = 0;
	DIR *dir;
	struct dirent *de;
	struct bfd f;

	dir = opendir_proc(pid, "task");
	if (dir == NULL)
		return -1;

	while ((de = readdir(dir))) {
		char *pos, *end;

		if (dir_dots(de))
			continue;

		f.fd = open_proc(pid, "task/%s/children", de->d_name);
		if (f.fd < 0)
			goto err;

		if (bfdopenr(&f))
			goto err;

		while (1) {
			pid_t val, *tmp;

			pos = breadchr(&f, ' ');
			if (IS_ERR(pos))
				goto err_close;
			if (pos == NULL)
				break;

			val = strtol(pos, &end, 0);

			if (*end != 0 && *end != ' ') {
				pr_err("Unable to parse %s\n", end);
				goto err_close;
			}

			tmp = xrealloc(ch, (nr + 1) * sizeof(pid_t));
			if (!tmp)
				goto err_close;

			ch = tmp;
			ch[nr] = val;
			nr++;
		}
		bclose(&f);
	}

	*_c = ch;
	*_n = nr;

	closedir(dir);
	return 0;
err_close:
	bclose(&f);
err:
	closedir(dir);
	xfree(ch);
	return -1;
}

