#include <unistd.h>
#include <sys/mman.h>
#include <stdlib.h>

#include "shmem.h"
#include "image.h"
#include "crtools.h"
#include "restorer.h"

#include "protobuf.h"

struct shmems *rst_shmems;

void show_saved_shmems(void)
{
	int i;

	pr_info("\tSaved shmems:\n");

	for (i = 0; i < rst_shmems->nr_shmems; i++)
		pr_info("\t\tstart: 0x%016lx shmid: 0x%lx pid: %d\n",
			rst_shmems->entries[i].start,
			rst_shmems->entries[i].shmid,
			rst_shmems->entries[i].pid);
}

static int collect_shmem(int pid, VmaEntry *vi)
{
	int nr_shmems = rst_shmems->nr_shmems;
	unsigned long size = vi->pgoff + vi->end - vi->start;
	struct shmem_info *si;

	si = find_shmem(rst_shmems, vi->shmid);
	if (si) {

		if (si->size < size)
			si->size = size;

		/*
		 * Only the shared mapping with a lowest
		 * pid will be created in real, other processes
		 * will wait until the kernel propagate this mapping
		 * into /proc
		 */
		if (si->pid <= pid)
			return 0;

		si->pid	 = pid;
		si->start = vi->start;
		si->end	 = vi->end;

		return 0;
	}

	if ((nr_shmems + 1) * sizeof(struct shmem_info) +
					sizeof (struct shmems) >= SHMEMS_SIZE) {
		pr_err("OOM storing shmems\n");
		return -1;
	}

	pr_info("Add new shmem 0x%lx (0x0160x%lx-0x0160x%lx)",
				vi->shmid, vi->start, vi->end);

	si = &rst_shmems->entries[nr_shmems];
	rst_shmems->nr_shmems++;

	si->start = vi->start;
	si->end	  = vi->end;
	si->shmid = vi->shmid;
	si->pid	  = pid;
	si->size  = size;
	si->fd    = -1;

	futex_init(&si->lock);

	return 0;
}

int prepare_shmem_pid(int pid)
{
	int fd, ret = -1;
	VmaEntry *vi;

	fd = open_image_ro(CR_FD_VMAS, pid);
	if (fd < 0) {
		if (errno == ENOENT)
			return 0;
		else
			return -1;
	}

	while (1) {
		ret = pb_read_eof(fd, &vi, vma_entry);
		if (ret <= 0)
			break;

		pr_info("vma 0x%lx 0x%lx\n", vi->start, vi->end);

		if (!vma_entry_is(vi, VMA_ANON_SHARED) ||
		    vma_entry_is(vi, VMA_AREA_SYSVIPC)) {
			vma_entry__free_unpacked(vi, NULL);
			continue;
		}

		ret = collect_shmem(pid, vi);
		vma_entry__free_unpacked(vi, NULL);

		if (ret)
			break;
	}

	close(fd);
	return ret;
}

static int shmem_wait_and_open(int pid, struct shmem_info *si)
{
	char path[128];
	int ret;

	snprintf(path, sizeof(path), "/proc/%d/map_files/%lx-%lx",
		si->pid, si->start, si->end);

	pr_info("Waiting for [%s] to appear\n", path);
	futex_wait_until(&si->lock, 1);

	pr_info("Opening shmem [%s] \n", path);
	ret = open_proc_rw(si->pid, "map_files/%lx-%lx", si->start, si->end);
	if (ret < 0)
		pr_perror("     %d: Can't stat shmem at %s",
				si->pid, path);
	return ret;
}

static int restore_shmem_content(void *addr, struct shmem_info *si)
{
	u64 offset;
	int fd, ret = 0;

	fd = open_image_ro(CR_FD_SHMEM_PAGES, si->shmid);
	if (fd < 0) {
		munmap(addr,  si->size);
		return -1;
	}

	while (1) {
		ret = read_img_buf_eof(fd, &offset, sizeof(offset));
		if (ret <= 0)
			break;

		if (offset + PAGE_SIZE > si->size)
			break;

		ret = read_img_buf(fd, addr + offset, PAGE_SIZE);
		if (ret < 0)
			break;
	}

	close(fd);
	return ret;
}

int get_shmem_fd(int pid, VmaEntry *vi)
{
	struct shmem_info *si;
	void *addr;
	int f;

	si = find_shmem(rst_shmems, vi->shmid);
	pr_info("Search for 0x%016lx shmem 0x%lx %p/%d\n", vi->start, vi->shmid, si, si ? si->pid : -1);
	if (!si) {
		pr_err("Can't find my shmem 0x%016lx\n", vi->start);
		return -1;
	}

	if (si->pid != pid)
		return shmem_wait_and_open(pid, si);

	if (si->fd != -1)
		return dup(si->fd);

	/* The following hack solves problems:
	 * vi->pgoff may be not zero in a target process.
	 * This mapping may be mapped more then once.
	 * The restorer doesn't have snprintf.
	 * Here is a good place to restore content
	 */
	addr = mmap(NULL, si->size,
			PROT_WRITE | PROT_READ,
			MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED) {
		pr_err("Can't mmap shmid=0x%lx size=%ld\n",
				vi->shmid, si->size);
		return -1;
	}

	if (restore_shmem_content(addr, si) < 0) {
		pr_err("Can't restore shmem content\n");
		return -1;
	}

	f = open_proc_rw(getpid(), "map_files/%lx-%lx",
			(unsigned long) addr,
			(unsigned long) addr + si->size);
	munmap(addr, si->size);
	if (f < 0)
		return -1;

	si->fd = f;
	return f;
}

int prepare_shmem_restore(void)
{
	rst_shmems = mmap(NULL, SHMEMS_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, 0, 0);
	if (rst_shmems == MAP_FAILED) {
		pr_perror("Can't map shmem");
		return -1;
	}

	rst_shmems->nr_shmems = 0;
	return 0;
}

struct shmem_info_dump
{
	unsigned long	size;
	unsigned long	shmid;
	unsigned long	start;
	unsigned long	end;
	int		pid;
};

static int nr_shmems;
static struct shmem_info_dump *dump_shmems;

static struct shmem_info_dump* shmem_find(unsigned long shmid)
{
	int i;

	for (i = 0; i < nr_shmems; i++)
		if (dump_shmems[i].shmid == shmid)
			return &dump_shmems[i];

	return NULL;
}

int add_shmem_area(pid_t pid, VmaEntry *vma)
{
	struct shmem_info_dump *si;
	unsigned long size = vma->pgoff + (vma->end - vma->start);

	si = shmem_find(vma->shmid);
	if (si) {
		if (si->size < size)
			si->size = size;
		return 0;
	}

	nr_shmems++;
	if (nr_shmems * sizeof(*si) == SHMEMS_SIZE) {
		pr_err("OOM storing shmems\n");
		return -1;
	}

	si = &dump_shmems[nr_shmems - 1];
	si->size = size;
	si->pid = pid;
	si->start = vma->start;
	si->end = vma->end;
	si->shmid = vma->shmid;

	return 0;
}

int cr_dump_shmem(void)
{
	int err, fd;
	unsigned char *map = NULL;
	void *addr = NULL;
	struct shmem_info_dump *si;
	unsigned long pfn, nrpages;

	for (si = dump_shmems; si < &dump_shmems[nr_shmems]; si++) {
		pr_info("Dumping shared memory 0x%lx\n", si->shmid);

		nrpages = (si->size + PAGE_SIZE -1) / PAGE_SIZE;
		map = xmalloc(nrpages * sizeof(*map));
		if (!map)
			goto err;

		fd = open_proc(si->pid, "map_files/%lx-%lx", si->start, si->end);
		if (fd < 0)
			goto err;

		addr = mmap(NULL, si->size, PROT_READ, MAP_SHARED, fd, 0);
		close(fd);
		if (addr == MAP_FAILED) {
			pr_err("Can't map shmem 0x%lx (0x%lx-0x%lx)\n",
					si->shmid, si->start, si->end);
			goto err;
		}

		/*
		 * We can't use pagemap here, because this vma is
		 * not mapped to us at all, but mincore reports the
		 * pagecache status of a file, which is correct in
		 * this case.
		 */

		err = mincore(addr, si->size, map);
		if (err)
			goto err_unmap;

		fd = open_image(CR_FD_SHMEM_PAGES, O_DUMP, si->shmid);
		if (fd < 0)
			goto err_unmap;

		for (pfn = 0; pfn < nrpages; pfn++) {
			u64 offset = pfn * PAGE_SIZE;

			if (!(map[pfn] & PAGE_RSS))
				continue;

			if (write_img_buf(fd, &offset, sizeof(offset)))
				break;
			if (write_img_buf(fd, addr + offset, PAGE_SIZE))
				break;
		}

		if (pfn != nrpages)
			goto err_close;

		close(fd);
		munmap(addr,  si->size);
		xfree(map);
	}

	return 0;

err_close:
	close(fd);
err_unmap:
	munmap(addr,  si->size);
err:
	xfree(map);
	return -1;
}

int init_shmem_dump(void)
{
	nr_shmems = 0;
	dump_shmems = xmalloc(SHMEMS_SIZE);
	return dump_shmems == NULL ? -1 : 0;
}

void fini_shmem_dump(void)
{
	xfree(dump_shmems);
}
