#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <linux/kdev_t.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/vfs.h>

#include <linux/types.h>
#include "img_structs.h"

static int fdinfo_img;
static int pages_img;
static int core_img;
static int shmem_img;
static int pipes_img;

#define PIPEFS_MAGIC 0x50495045

static int prep_img_files(int pid)
{
	__u32 type;
	char name[64];

	sprintf(name, "fdinfo-%d.img", pid);
	fdinfo_img = open(name, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fdinfo_img < 0) {
		perror("Can't open fdinfo");
		return 1;
	}

	type = FDINFO_MAGIC;
	write(fdinfo_img, &type, 4);

	sprintf(name, "pages-%d.img", pid);
	pages_img = open(name, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (pages_img < 0) {
		perror("Can't open shmem");
		return 1;
	}

	type = PAGES_MAGIC;
	write(pages_img, &type, 4);

	sprintf(name, "core-%d.img", pid);
	core_img = open(name, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (core_img < 0) {
		perror("Can't open core");
		return 1;
	}

	sprintf(name, "shmem-%d.img", pid);
	shmem_img = open(name, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (shmem_img < 0) {
		perror("Can't open shmem");
		return 1;
	}

	type = SHMEM_MAGIC;
	write(shmem_img, &type, 4);

	sprintf(name, "pipes-%d.img", pid);
	pipes_img = open(name, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (pipes_img < 0) {
		perror("Can't open pipes");
		return 1;
	}

	type = PIPES_MAGIC;
	write(pipes_img, &type, 4);

	return 0;
}

static void kill_imgfiles(int pid)
{
	/* FIXME */
}

static int stop_task(int pid)
{
	return kill(pid, SIGSTOP);
}

static void continue_task(int pid)
{
	if (kill(pid, SIGCONT))
		perror("Can't cont task");
}

static char big_tmp_str[PATH_MAX];

static int read_fd_params(int pid, char *fd, unsigned long *pos, unsigned int *flags)
{
	char fd_str[128];
	int ifd;

	sprintf(fd_str, "/proc/%d/fdinfo/%s", pid, fd);

	printf("\tGetting fdinfo for fd %s\n", fd);
	ifd = open(fd_str, O_RDONLY);
	if (ifd < 0) {
		perror("Can't open fdinfo");
		return 1;
	}

	read(ifd, big_tmp_str, sizeof(big_tmp_str));
	close(ifd);

	sscanf(big_tmp_str, "pos:\t%lli\nflags:\t%o\n", pos, flags);
	return 0;
}

static int dump_one_reg_file(int type, unsigned long fd_name, int lfd,
		int lclose, unsigned long pos, unsigned int flags)
{
	char fd_str[128];
	int len;
	struct fdinfo_entry e;

	sprintf(fd_str, "/proc/self/fd/%d", lfd);
	len = readlink(fd_str, big_tmp_str, sizeof(big_tmp_str) - 1);
	if (len < 0) {
		perror("Can't readlink fd");
		return 1;
	}

	big_tmp_str[len] = '\0';
	printf("\tDumping path for %x fd via self %d [%s]\n", fd_name, lfd, big_tmp_str);

	if (lclose)
		close(lfd);

	e.type = type;
	e.addr = fd_name;
	e.len = len;
	e.pos = pos;
	e.flags = flags;

	write(fdinfo_img, &e, sizeof(e));
	write(fdinfo_img, big_tmp_str, len);

	return 0;
}

#define MAX_PIPE_BUF_SIZE	1024 /* FIXME - this is not so */
#define SPLICE_F_NONBLOCK	0x2

static int dump_pipe_and_data(int lfd, struct pipes_entry *e)
{
	int steal_pipe[2];
	int ret;

	printf("\tDumping data from pipe %x\n", e->pipeid);
	if (pipe(steal_pipe) < 0) {
		perror("Can't create pipe for stealing data");
		return 1;
	}

	ret = tee(lfd, steal_pipe[1], MAX_PIPE_BUF_SIZE, SPLICE_F_NONBLOCK);
	if (ret < 0) {
		if (errno != EAGAIN) {
			perror("Can't pick pipe data");
			return 1;
		}

		ret = 0;
	}

	e->bytes = ret;
	write(pipes_img, e, sizeof(*e));

	if (ret) {
		ret = splice(steal_pipe[0], NULL, pipes_img, NULL, ret, 0);
		if (ret < 0) {
			perror("Can't push pipe data");
			return 1;
		}
	}

	close(steal_pipe[0]);
	close(steal_pipe[1]);
	return 0;
}

static int dump_one_pipe(int fd, int lfd, unsigned int id, unsigned int flags)
{
	struct pipes_entry e;

	printf("\tDumping pipe %d/%x flags %x\n", fd, id, flags);

	e.fd = fd;
	e.pipeid = id;
	e.flags = flags;

	if (flags & O_WRONLY) {
		e.bytes = 0;
		write(pipes_img, &e, sizeof(e));
		return 0;
	}

	return dump_pipe_and_data(lfd, &e);
}

static int dump_one_fd(int dir, char *fd_name, unsigned long pos, unsigned int flags)
{
	int fd;
	struct stat st_buf;
	struct statfs stfs_buf;

	printf("\tDumping fd %s\n", fd_name);
	fd = openat(dir, fd_name, O_RDONLY);
	if (fd == -1) {
		printf("Tried to openat %d/%d %s\n", getpid(), dir, fd_name);
		perror("Can't open fd");
		return 1;
	}

	if (fstat(fd, &st_buf) < 0) {
		perror("Can't stat one");
		return 1;
	}

	if (S_ISREG(st_buf.st_mode))
		return dump_one_reg_file(FDINFO_FD, atoi(fd_name), fd, 1, pos, flags);

	if (S_ISFIFO(st_buf.st_mode)) {
		if (fstatfs(fd, &stfs_buf) < 0) {
			perror("Can't statfs one");
			return 1;
		}

		if (stfs_buf.f_type == PIPEFS_MAGIC)
			return dump_one_pipe(atoi(fd_name), fd, st_buf.st_ino, flags);
	}

	if (!strcmp(fd_name, "0")) {
		printf("\tSkipping stdin\n");
		return 0;
	}

	if (!strcmp(fd_name, "1")) {
		printf("\tSkipping stdout\n");
		return 0;
	}

	if (!strcmp(fd_name, "2")) {
		printf("\tSkipping stderr\n");
		return 0;
	}

	if (!strcmp(fd_name, "3")) {
		printf("\tSkipping tty\n");
		return 0;
	}

	fprintf(stderr, "Can't dump file %s of that type [%x]\n", fd_name, st_buf.st_mode);
	return 1;

}

static int dump_task_files(int pid)
{
	char pid_fd_dir[64];
	DIR *fd_dir;
	struct dirent *de;
	unsigned long pos;
	unsigned int flags;

	printf("Dumping open files for %d\n", pid);

	sprintf(pid_fd_dir, "/proc/%d/fd", pid);
	fd_dir = opendir(pid_fd_dir);
	if (fd_dir == NULL) {
		perror("Can't open fd dir");
		return -1;
	}

	while ((de = readdir(fd_dir)) != NULL) {
		if (de->d_name[0] == '.')
			continue;

		if (read_fd_params(pid, de->d_name, &pos, &flags))
			return 1;

		if (dump_one_fd(dirfd(fd_dir), de->d_name, pos, flags))
			return 1;
	}

	closedir(fd_dir);
	return 0;
}

#define PAGE_SIZE	4096
#define PAGE_RSS	0x1

static unsigned long rawhex(char *str, char **end)
{
	unsigned long ret = 0;

	while (1) {
		if (str[0] >= '0' && str[0] <= '9') {
			ret <<= 4;
			ret += str[0] - '0';
		} else if (str[0] >= 'a' && str[0] <= 'f') {
			ret <<= 4;
			ret += str[0] - 'a' + 0xA;
		} else if (str[0] >= 'A' && str[0] <= 'F') {
			ret <<= 4;
			ret += str[0] - 'A' + 0xA;
		} else {
			if (end)
				*end = str;
			return ret;
		}

		str++;
	}
}

static void map_desc_parm(char *desc, unsigned long *pgoff, unsigned long *len)
{
	char *s;
	unsigned long start, end;

	start = rawhex(desc, &s);
	if (*s != '-') {
		goto bug;
	}

	end = rawhex(s + 1, &s);
	if (*s != ' ') {
		goto bug;
	}

	s = strchr(s + 1, ' ');
	*pgoff = rawhex(s + 1, &s);
	if (*s != ' ') {
		goto bug;
	}

	if (start > end)
		goto bug;

	*len = end - start;

	if (*len % PAGE_SIZE) {
		goto bug;
	}
	if (*pgoff % PAGE_SIZE) {
		goto bug;
	}

	return;
bug:
	fprintf(stderr, "BUG\n");
	exit(1);
}

static int dump_map_pages(int lfd, unsigned long start, unsigned long pgoff, unsigned long len)
{
	unsigned int nrpages, pfn;
	void *mem;
	unsigned char *mc;

	printf("\t\tDumping pages start %x len %x off %x\n", start, len, pgoff);
	mem = mmap(NULL, len, PROT_READ, MAP_FILE | MAP_PRIVATE, lfd, pgoff);
	if (mem == MAP_FAILED) {
		perror("Can't map");
		return 1;
	}

	nrpages = len / PAGE_SIZE;
	mc = malloc(nrpages);
	if (mincore(mem, len, mc)) {
		perror("Can't mincore mapping");
		return 1;
	}

	for (pfn = 0; pfn < nrpages; pfn++)
		if (mc[pfn] & PAGE_RSS) {
			__u64 vaddr;

			vaddr = start + pfn * PAGE_SIZE;
			write(pages_img, &vaddr, 8);
			write(pages_img, mem + pfn * PAGE_SIZE, PAGE_SIZE);
		}

	munmap(mem, len);

	return 0;
}

static int dump_anon_private_map(char *start)
{
	printf("\tSkipping anon private mapping at %s\n", start);
	return 0;
}

static int dump_anon_shared_map(char *_start, char *mdesc, int lfd, struct stat *st)
{
	unsigned long pgoff, len;
	struct shmem_entry e;
	unsigned long start;
	struct stat buf;

	map_desc_parm(mdesc, &pgoff, &len);

	start = rawhex(_start, NULL);
	e.start = start;
	e.end = start + len;
	e.shmid = st->st_ino;

	write(shmem_img, &e, sizeof(e));

	if (dump_map_pages(lfd, start, pgoff, len))
		return 1;

	close(lfd);
	return 0;
}

static int dump_file_shared_map(char *start, char *mdesc, int lfd)
{
	printf("\tSkipping file shared mapping at %s\n", start);
	close(lfd);
	return 0;
}

static int dump_file_private_map(char *_start, char *mdesc, int lfd)
{
	unsigned long pgoff, len;
	unsigned long start;

	map_desc_parm(mdesc, &pgoff, &len);

	start = rawhex(_start, NULL);
	if (dump_one_reg_file(FDINFO_MAP, start, lfd, 0, 0, O_RDONLY))
		return 1;

	close(lfd);
	return 0;
}

static int dump_one_mapping(char *mdesc, DIR *mfd_dir)
{
	char *flags, *tmp;
	char map_start[32];
	int lfd;
	struct stat st_buf;

	tmp = strchr(mdesc, '-');
	memset(map_start, 0, sizeof(map_start));
	strncpy(map_start, mdesc, tmp - mdesc);
	flags = strchr(mdesc, ' ');
	flags++;

	printf("\tDumping %s\n", map_start);
	lfd = openat(dirfd(mfd_dir), map_start, O_RDONLY);
	if (lfd == -1) {
		if (errno != ENOENT) {
			perror("Can't open mapping");
			return 1;
		}

		if (flags[3] != 'p') {
			fprintf(stderr, "Bogus mapping [%s]\n", mdesc);
			return 1;
		}

		return dump_anon_private_map(map_start);
	}

	if (fstat(lfd, &st_buf) < 0) {
		perror("Can't stat mapping!");
		return 1;
	}

	if (!S_ISREG(st_buf.st_mode)) {
		perror("Can't handle non-regular mapping");
		return 1;
	}

	if (MAJOR(st_buf.st_dev) == 0) {
		if (flags[3] != 's') {
			fprintf(stderr, "Bogus mapping [%s]\n", mdesc);
			return 1;
		}

		/* FIXME - this can be tmpfs visible file mapping */
		return dump_anon_shared_map(map_start, mdesc, lfd, &st_buf);
	}

	if (flags[3] == 'p')
		return dump_file_private_map(map_start, mdesc, lfd);
	else
		return dump_file_shared_map(map_start, mdesc, lfd);
}

static int dump_task_ext_mm(int pid)
{
	char path[64];
	DIR *mfd_dir;
	FILE *maps;

	printf("Dumping mappings for %d\n", pid);

	sprintf(path, "/proc/%d/mfd", pid);
	mfd_dir = opendir(path);
	if (mfd_dir == NULL) {
		perror("Can't open mfd dir");
		return -1;
	}

	sprintf(path, "/proc/%d/maps", pid);
	maps = fopen(path, "r");
	if (maps == NULL) {
		perror("Can't open maps file");
		return 1;
	}

	while (fgets(big_tmp_str, sizeof(big_tmp_str), maps) != NULL)
		if (dump_one_mapping(big_tmp_str, mfd_dir))
			return 1;

	fclose(maps);
	closedir(mfd_dir);
	return 0;
}

static int dump_task_state(int pid)
{
	char path[64];
	int dump_fd;
	void *mem;

	printf("Dumping task image for %d\n", pid);
	sprintf(path, "/proc/%d/kstate_dump", pid);
	dump_fd = open(path, O_RDONLY);
	if (dump_fd < 0) {
		perror("Can't open dump file");
		return 1;
	}

	mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, 0, 0);
	if (mem == MAP_FAILED) {
		perror("Can't get mem");
		return 1;
	}

	while (1) {
		int r, w;

		r = read(dump_fd, mem, 4096);
		if (r == 0)
			break;
		if (r < 0) {
			perror("Can't read dump file");
			return 1;
		}

		w = 0;
		while (w < r) {
			int ret;

			ret = write(core_img, mem + w, r - w);
			if (ret <= 0) {
				perror("Can't write core");
				return 1;
			}

			w += ret;
		}
	}

	munmap(mem, 4096);
	close(dump_fd);

	return 0;
}

static int dump_one_task(int pid, int stop)
{
	printf("Dumping task %d\n", pid);

	if (prep_img_files(pid))
		return 1;

	if (stop && stop_task(pid))
		goto err_task;

	if (dump_task_files(pid))
		goto err;

	if (dump_task_ext_mm(pid))
		goto err;

	if (dump_task_state(pid))
		goto err;

	if (stop)
		continue_task(pid);

	printf("Dump is complete\n");
	return 0;

err:
	if (stop)
		continue_task(pid);
err_task:
	kill_imgfiles(pid);
	return 1;
}

static int pstree_fd;
static char big_tmp_str[4096];
static int *pids, nr_pids;

static char *get_children_pids(int pid)
{
	FILE *f;
	int len;
	char *ret, *tmp;

	sprintf(big_tmp_str, "/proc/%d/status", pid);
	f = fopen(big_tmp_str, "r");
	if (f == NULL)
		return NULL;

	while ((fgets(big_tmp_str, sizeof(big_tmp_str), f)) != NULL) {
		if (strncmp(big_tmp_str, "Children:", 9))
			continue;

		tmp = big_tmp_str + 10;
		len = strlen(tmp);
		ret = malloc(len + 1);
		strcpy(ret, tmp);
		if (len)
			ret[len - 1] = ' ';

		fclose(f);
		return ret;
	}

	fclose(f);
	return NULL;
}

static int dump_pid_and_children(int pid)
{
	struct pstree_entry e;
	char *chlist, *tmp, *tmp2;

	printf("\tReading %d children list\n", pid);
	chlist = get_children_pids(pid);
	if (chlist == NULL)
		return 1;

	printf("\t%d has children %s\n", pid, chlist);

	e.pid = pid;
	e.nr_children = 0;

	pids = realloc(pids, (nr_pids + 1) * sizeof(int));
	pids[nr_pids++] = e.pid;

	tmp = chlist;
	while ((tmp = strchr(tmp, ' ')) != NULL) {
		tmp++;
		e.nr_children++;
	}

	write(pstree_fd, &e, sizeof(e));
	tmp = chlist;
	while (1) {
		__u32 cpid;

		cpid = strtol(tmp, &tmp, 10);
		if (cpid == 0)
			break;
		if (*tmp != ' ') {
			fprintf(stderr, "Error in string with children!\n");
			return 1;
		}

		write(pstree_fd, &cpid, sizeof(cpid));
		tmp++;
	}

	tmp = chlist;
	while ((tmp2 = strchr(tmp, ' ')) != NULL) {
		*tmp2 = '\0';
		if (dump_pid_and_children(atoi(tmp)))
			return 1;
		tmp = tmp2 + 1;
	}

	free(chlist);
	return 0;
}

static int __dump_all_tasks(void)
{
	int i, pid;

	printf("Dumping tasks' images for");
	for (i = 0; i < nr_pids; i++)
		printf(" %d", pids[i]);
	printf("\n");

	printf("Stopping tasks\n");
	for (i = 0; i < nr_pids; i++)
		if (stop_task(pids[i]))
			goto err;

	for (i = 0; i < nr_pids; i++) {
		if (dump_one_task(pids[i], 0))
			goto err;
	}

	printf("Resuming tasks\n");
	for (i = 0; i < nr_pids; i++)
		continue_task(pids[i]);

	return 0;

err:
	for (i = 0; i < nr_pids; i++)
		continue_task(pids[i]);
	return 1;

}

static int dump_all_tasks(int pid)
{
	char *chlist;
	__u32 type;

	pids = NULL;
	nr_pids = 0;

	printf("Dumping process tree, start from %d\n", pid);

	sprintf(big_tmp_str, "pstree-%d.img", pid);
	pstree_fd = open(big_tmp_str, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (pstree_fd < 0) {
		perror("Can't create pstree");
		return 1;
	}

	type = PSTREE_MAGIC;
	write(pstree_fd, &type, sizeof(type));

	if (dump_pid_and_children(pid))
		return 1;

	close(pstree_fd);

	return __dump_all_tasks();
}

int main(int argc, char **argv)
{
	if (argc != 3)
		goto usage;
	if (argv[1][0] != '-')
		goto usage;
	if (argv[1][1] == 'p')
		return dump_one_task(atoi(argv[2]), 1);
	if (argv[1][1] == 't')
		return dump_all_tasks(atoi(argv[2]));

usage:
	printf("Usage: %s (-p|-t) <pid>\n", argv[0]);
	return 1;
}
