/*
 * cuda_gpu_pages.c - shared GPU VRAM page I/O routines
 *
 * See cuda_gpu_pages.h for the interface description.
 */

#include "cuda_gpu_pages.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef SYS_process_vm_readv
#define SYS_process_vm_readv 310
#endif

#ifndef SYS_process_vm_writev
#define SYS_process_vm_writev 311
#endif

#ifndef O_DIRECT
#define O_DIRECT 040000 /* Linux x86-64 */
#endif

#ifndef MADV_HUGEPAGE
#define MADV_HUGEPAGE 14
#endif

#include "log.h"

double now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

/*
 * Return the innermost namespace PID for 'pid' by reading NSpid from
 * /proc/<pid>/status.  The host PID changes on every restore cycle (CRIU
 * preserves the in-container PID, not the host PID), so we key the
 * gpu-pages image file on the namespace PID to get a stable filename.
 * Falls back to 'pid' if the info is unavailable.
 *
 * Limitation: this only works when CRIU preserves namespace PIDs (the
 * normal case: the PID namespace is restored with the same PIDs). If the
 * namespace PIDs change (e.g. the image is restored without the PID
 * namespace), the image is not found and the restore fails.
 */
static int get_ns_pid(int pid)
{
	char path[64];
	FILE *f;
	char line[256];
	int ns_pid = pid;

	snprintf(path, sizeof(path), "/proc/%d/status", pid);
	f = fopen(path, "r");
	if (!f)
		return pid;

	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, "NSpid:", 6) == 0) {
			int val, last = pid, consumed;
			char *p = line + 6;

			while (sscanf(p, " %d%n", &val, &consumed) == 1) {
				last = val;
				p += consumed;
			}
			ns_pid = last;
			break;
		}
	}
	fclose(f);
	return ns_pid;
}

/*
 * Scan /proc/<pid>/maps for anonymous private rw- VMAs.
 * Anonymous = dev 0:0, ino 0, no filename.
 */
int scan_anon_private_vmas(int pid, struct gpu_region **out, int *count)
{
	char maps_path[64];
	FILE *f;
	char line[256];
	struct gpu_region *regions = NULL;
	int n = 0, cap = 0;

	snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
	f = fopen(maps_path, "r");
	if (!f) {
		pr_perror("Cannot open %s", maps_path);
		return -1;
	}

	while (fgets(line, sizeof(line), f)) {
		unsigned long start, end, offset, ino;
		unsigned int dev_maj, dev_min;
		char perms[8];
		char name[128];
		int n_parsed;
		struct gpu_region *tmp;
		int new_cap;

		name[0] = '\0';
		n_parsed = sscanf(line, "%lx-%lx %7s %lx %x:%x %lu %127s",
				  &start, &end, perms, &offset,
				  &dev_maj, &dev_min, &ino, name);
		if (n_parsed < 7)
			continue;

		/* anonymous: dev=0:0, ino=0, no filename */
		if (dev_maj != 0 || dev_min != 0 || ino != 0)
			continue;
		if (n_parsed >= 8 && name[0] != '\0')
			continue;

		/* private, read-write */
		if (perms[3] != 'p' || perms[0] != 'r' || perms[1] != 'w')
			continue;

		if (n >= cap) {
			new_cap = cap ? cap * 2 : 64;
			tmp = realloc(regions, (size_t)new_cap * sizeof(*regions));
			if (!tmp) {
				pr_err("OOM in scan_anon_private_vmas\n");
				fclose(f);
				free(regions);
				return -1;
			}
			regions = tmp;
			cap = new_cap;
		}

		regions[n].start = (uint64_t)start;
		regions[n].size = (uint64_t)(end - start);
		n++;
	}

	fclose(f);
	*out = regions;
	*count = n;
	return 0;
}

/*
 * Find VMAs present in 'after' but not in 'before'.
 * These are the new anonymous mappings created by cuda-checkpoint for VRAM.
 */
int diff_anon_vmas(struct gpu_region *before, int n_before,
		   struct gpu_region *after, int n_after,
		   struct gpu_region **diff_out, int *diff_count)
{
	struct gpu_region *diff = NULL;
	int n = 0, cap = 0;
	int i, j;

	for (i = 0; i < n_after; i++) {
		bool found = false;

		for (j = 0; j < n_before; j++) {
			if (before[j].start == after[i].start && before[j].size == after[i].size) {
				found = true;
				break;
			}
		}
		if (!found) {
			struct gpu_region *tmp;
			int new_cap;

			if (n >= cap) {
				new_cap = cap ? cap * 2 : 16;
				tmp = realloc(diff, (size_t)new_cap * sizeof(*diff));
				if (!tmp) {
					pr_err("OOM in diff_anon_vmas\n");
					free(diff);
					return -1;
				}
				diff = tmp;
				cap = new_cap;
			}
			diff[n++] = after[i];
		}
	}

	*diff_out = diff;
	*diff_count = n;
	return 0;
}

/*
 * Dump GPU memory regions to gpu-pages-<pid>.img in the image directory.
 * File format: gpu_pages_hdr | gpu_region[num_regions] | raw page data
 * Page data starts at GPU_PAGES_DATA_OFFSET (page-aligned for mmap on restore).
 */
int dump_gpu_pages(int pid, int img_dir_fd, struct gpu_region *regions, int count)
{
	char fname[64];
	int fd, ret = -1, i;
	struct gpu_pages_hdr hdr;
	char *buf = NULL;
	double t0, t_readv = 0, t_write = 0;

	int ns_pid = get_ns_pid(pid);

	hdr.magic = GPU_PAGES_MAGIC;
	hdr.num_regions = (uint32_t)count;

	pr_info("dump_gpu_pages: host_pid=%d ns_pid=%d\n", pid, ns_pid);
	snprintf(fname, sizeof(fname), "gpu-pages-%d.img", ns_pid);
	/*
	 * O_DIRECT bypasses the page cache: no dirty pages accumulate, so
	 * restore's O_DIRECT pread finds nothing to invalidate and runs at
	 * full NVMe bandwidth.  Without this, 6 GB of dirty pages require
	 * sync_file_range (blocks 4 s walking 1.5M page entries) before
	 * restore can read fast.  Header + regions are packed into one
	 * 4096-byte aligned block to meet O_DIRECT alignment requirements.
	 */
	fd = openat(img_dir_fd, fname,
		    O_WRONLY | O_CREAT | O_TRUNC | O_DIRECT, 0600);
	if (fd < 0 && errno == EINVAL) {
		pr_info("O_DIRECT not supported for dump, falling back to buffered I/O\n");
		fd = openat(img_dir_fd, fname,
			    O_WRONLY | O_CREAT | O_TRUNC, 0600);
	}
	if (fd < 0) {
		pr_perror("Cannot create %s", fname);
		return -1;
	}

	if (posix_memalign((void **)&buf, 4096, GPU_IO_CHUNK_SIZE) != 0) {
		pr_err("OOM: cannot allocate aligned IO buffer\n");
		goto out;
	}

	/* Pack header + region table into one 4096-byte O_DIRECT write */
	memset(buf, 0, GPU_PAGES_DATA_OFFSET);
	memcpy(buf, &hdr, sizeof(hdr));
	if (count > 0)
		memcpy(buf + sizeof(hdr), regions, (size_t)count * sizeof(*regions));
	if (write(fd, buf, GPU_PAGES_DATA_OFFSET) != (ssize_t)GPU_PAGES_DATA_OFFSET) {
		pr_perror("Cannot write header block to %s", fname);
		goto out;
	}

	t0 = now_ms();
	for (i = 0; i < count; i++) {
		uint64_t offset = 0;
		uint64_t remaining = regions[i].size;

		while (remaining > 0) {
			size_t chunk = (remaining > GPU_IO_CHUNK_SIZE) ? GPU_IO_CHUNK_SIZE : (size_t)remaining;
			struct iovec local_iov = { .iov_base = buf, .iov_len = chunk };
			struct iovec remote_iov = { .iov_base = (void *)(uintptr_t)(regions[i].start + offset),
						    .iov_len = chunk };
			ssize_t n, written = 0;
			double t1;

			t1 = now_ms();
			n = (ssize_t)syscall(SYS_process_vm_readv, (pid_t)pid, &local_iov, 1UL, &remote_iov, 1UL, 0UL);
			t_readv += now_ms() - t1;
			if (n < 0) {
				pr_perror("process_vm_readv failed for pid %d at 0x%lx", pid,
					  (unsigned long)(regions[i].start + offset));
				goto out;
			}

			t1 = now_ms();
			while (written < n) {
				ssize_t w = write(fd, buf + written, (size_t)(n - written));

				if (w < 0) {
					pr_perror("write to %s failed", fname);
					goto out;
				}
				written += w;
			}
			t_write += now_ms() - t1;
			offset += (uint64_t)n;
			remaining -= (uint64_t)n;
		}
	}

	pr_info("[timing] dump: process_vm_readv=%.0f ms O_DIRECT_write=%.0f ms total=%.0f ms\n",
		t_readv, t_write, now_ms() - t0);
	ret = 0;
	pr_info("Dumped %d GPU regions for pid %d\n", count, pid);
out:
	free(buf);
	close(fd);
	if (ret != 0)
		unlinkat(img_dir_fd, fname, 0);
	return ret;
}

/*
 * Find a 'syscall' instruction (0x0f 0x05) in the vdso of pid.
 * Returns the address, or 0 on failure.
 */
uint64_t find_syscall_addr(int pid)
{
	char maps_path[64];
	FILE *f;
	char line[256];
	uint64_t vdso_start = 0, vdso_end = 0;
	uint8_t *buf;
	size_t vdso_size, i;
	struct iovec local_iov, remote_iov;

	snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
	f = fopen(maps_path, "r");
	if (!f)
		return 0;

	while (fgets(line, sizeof(line), f)) {
		unsigned long start, end;
		char name[64];

		name[0] = '\0';
		if (sscanf(line, "%lx-%lx %*s %*s %*s %*s %63s", &start, &end, name) >= 2 &&
		    strcmp(name, "[vdso]") == 0) {
			vdso_start = start;
			vdso_end = end;
			break;
		}
	}
	fclose(f);

	if (!vdso_start)
		return 0;

	vdso_size = vdso_end - vdso_start;
	buf = malloc(vdso_size);
	if (!buf)
		return 0;

	local_iov.iov_base = buf;
	local_iov.iov_len = vdso_size;
	remote_iov.iov_base = (void *)(uintptr_t)vdso_start;
	remote_iov.iov_len = vdso_size;

	if (syscall(SYS_process_vm_readv, (pid_t)pid, &local_iov, 1UL, &remote_iov, 1UL, 0UL) < 0) {
		free(buf);
		return 0;
	}

	for (i = 0; i + 1 < vdso_size; i++) {
		if (buf[i] == 0x0f && buf[i + 1] == 0x05) { /* syscall */
			free(buf);
			return vdso_start + i;
		}
	}

	free(buf);
	return 0;
}

/*
 * Generic 6-argument syscall injector for a stopped thread.
 * syscall_addr must point to a 'syscall' (0x0f 0x05) instruction in the
 * target's vdso. The thread must be in ptrace-stop state.
 * Returns the syscall return value (rax), or LONG_MIN on ptrace error.
 */
long inject_syscall(int tid, uint64_t syscall_addr,
		    long nr, long a1, long a2, long a3,
		    long a4, long a5, long a6)
{
	struct user_regs_struct saved_regs, regs, after_regs;
	int status;

	if (ptrace(PTRACE_GETREGS, tid, NULL, &saved_regs) < 0) {
		pr_perror("PTRACE_GETREGS failed for tid %d", tid);
		return LONG_MIN;
	}

	regs = saved_regs;
	regs.rax = (unsigned long long)nr;
	regs.rdi = (unsigned long long)a1;
	regs.rsi = (unsigned long long)a2;
	regs.rdx = (unsigned long long)a3;
	regs.r10 = (unsigned long long)a4;
	regs.r8 = (unsigned long long)a5;
	regs.r9 = (unsigned long long)a6;
	regs.rip = syscall_addr;
	regs.orig_rax = (unsigned long long)-1; /* not in a syscall-stop */

	if (ptrace(PTRACE_SETREGS, tid, NULL, &regs) < 0) {
		pr_perror("PTRACE_SETREGS failed for tid %d", tid);
		ptrace(PTRACE_SETREGS, tid, NULL, &saved_regs);
		return LONG_MIN;
	}

	if (ptrace(PTRACE_SINGLESTEP, tid, NULL, NULL) < 0) {
		pr_perror("PTRACE_SINGLESTEP failed for tid %d", tid);
		ptrace(PTRACE_SETREGS, tid, NULL, &saved_regs);
		return LONG_MIN;
	}

	if (waitpid(tid, &status, __WALL) < 0) {
		pr_perror("waitpid after SINGLESTEP failed for tid %d", tid);
		ptrace(PTRACE_SETREGS, tid, NULL, &saved_regs);
		return LONG_MIN;
	}

	if (ptrace(PTRACE_GETREGS, tid, NULL, &after_regs) < 0) {
		pr_perror("PTRACE_GETREGS after syscall failed for tid %d", tid);
		ptrace(PTRACE_SETREGS, tid, NULL, &saved_regs);
		return LONG_MIN;
	}

	if (ptrace(PTRACE_SETREGS, tid, NULL, &saved_regs) < 0) {
		pr_perror("PTRACE_SETREGS restore failed for tid %d", tid);
		return LONG_MIN;
	}

	return (long)after_regs.rax;
}

/*
 * Inject madvise(addr, len, MADV_DONTNEED) into the stopped thread 'tid'.
 */
int inject_madvise_dontneed(int tid, uint64_t addr, uint64_t len, uint64_t syscall_addr)
{
	long ret = inject_syscall(tid, syscall_addr,
				  SYS_madvise, (long)addr, (long)len,
				  MADV_DONTNEED, 0, 0, 0);

	if (ret < 0) {
		pr_warn("injected madvise(DONTNEED) returned %ld for addr=0x%lx len=%lu\n",
			ret, (unsigned long)addr, (unsigned long)len);
		return -1;
	}
	return 0;
}

/*
 * Free GPU pages from the stopped thread 'tid' by injecting madvise(MADV_DONTNEED).
 * The VMAs remain in the address space (empty), ready to be remapped on restore.
 * tid must be in ptrace-stop state; syscall_addr must be a 'syscall' insn in vdso.
 */
int release_gpu_pages(int tid, uint64_t syscall_addr, struct gpu_region *regions, int count)
{
	int i, failed = 0;

	for (i = 0; i < count; i++) {
		if (inject_madvise_dontneed(tid, regions[i].start, regions[i].size, syscall_addr) != 0) {
			pr_warn("inject madvise(DONTNEED) failed for region %d (0x%llx+%llu)\n",
				i, (unsigned long long)regions[i].start,
				(unsigned long long)regions[i].size);
			failed++;
		}
	}

	if (failed == 0)
		pr_info("Released %d GPU regions via injected madvise(DONTNEED)\n", count);
	else
		pr_warn("Released %d/%d GPU regions via injected madvise(DONTNEED)\n",
			count - failed, count);

	return (failed == count) ? -1 : 0;
}

/*
 * Parallel page-fill worker.
 *
 * Faulting in and zero-filling the target's anonymous pages from a single
 * thread is much slower than both fast storage and the kernel's parallel
 * fault throughput, so it, and not the O_DIRECT read, bounds the restore.
 *
 * Instead we fan the work out across N plugin threads.  Each thread pulls
 * fixed-size chunks from a shared queue, reads each chunk from the image file
 * (O_DIRECT when supported) into a private aligned bounce buffer, then writes
 * it into the target's existing anonymous VMAs with process_vm_writev.  The
 * cross-process write faults the target pages in parallel — anonymous write
 * faults scale near-linearly with threads on modern kernels (split page-table
 * locks) — and fills them with the real data in one pass.  No injected
 * syscalls are needed for the data path, so the earlier injected-pread path and the
 * serial mlock/pread/munlock are all gone.
 *
 * process_madvise(MADV_POPULATE_WRITE) would be a cleaner fault trigger but is
 * rejected (EINVAL) cross-process by the kernel allowlist on 6.12, so we drive
 * the faulting via process_vm_writev, which is permitted and also delivers the
 * data.  The pages are left present and warm (not locked); cuda-checkpoint
 * reads them back to VRAM.
 */
struct gpu_chunk {
	uint64_t target_addr;
	uint64_t file_offset;
	uint64_t len;
};

struct gpu_restore_ctx {
	int pid;
	int data_fd;
	struct gpu_chunk *chunks;
	int n_chunks;
	_Atomic int next;
	_Atomic int err;
};

static void *gpu_restore_worker(void *arg)
{
	struct gpu_restore_ctx *c = arg;
	void *buf = NULL;
	int i;

	if (posix_memalign(&buf, 4096, GPU_IO_CHUNK_SIZE) != 0) {
		atomic_store(&c->err, ENOMEM);
		return NULL;
	}

	while ((i = atomic_fetch_add(&c->next, 1)) < c->n_chunks) {
		struct gpu_chunk *ch = &c->chunks[i];
		uint64_t rdone = 0, wdone = 0;

		/* Read the whole chunk first so O_DIRECT offsets stay aligned. */
		while (rdone < ch->len) {
			ssize_t n = pread(c->data_fd, (char *)buf + rdone,
					  (size_t)(ch->len - rdone),
					  (off_t)(ch->file_offset + rdone));
			if (n <= 0) {
				atomic_store(&c->err, errno ? errno : EIO);
				goto out;
			}
			rdone += (uint64_t)n;
		}

		/* Fault + fill the target's pages (parallel across threads). */
		while (wdone < ch->len) {
			struct iovec liov = { .iov_base = (char *)buf + wdone,
					      .iov_len = (size_t)(ch->len - wdone) };
			struct iovec riov = { .iov_base = (void *)(uintptr_t)(ch->target_addr + wdone),
					      .iov_len = (size_t)(ch->len - wdone) };
			ssize_t w = (ssize_t)syscall(SYS_process_vm_writev, (pid_t)c->pid,
						     &liov, 1UL, &riov, 1UL, 0UL);
			if (w <= 0) {
				atomic_store(&c->err, errno ? errno : EIO);
				goto out;
			}
			wdone += (uint64_t)w;
		}
	}
out:
	free(buf);
	return NULL;
}

static int gpu_restore_thread_count(void)
{
	const char *env = getenv("CUDA_RESTORE_THREADS");
	int n = 8;

	if (env && *env) {
		n = atoi(env);
		if (n < 1)
			n = 1;
	}
	if (n > 32)
		n = 32;
	return n;
}

/*
 * Restore GPU pages into the target process.
 *
 * Reads gpu-pages-<ns_pid>.img and fills the target's anonymous GPU VMAs in
 * parallel via process_vm_writev (see gpu_restore_worker).  An injected
 * MADV_HUGEPAGE per region first hints 2MB THP for the about-to-be-faulted
 * pages.  On return the pages are present and warm (not locked); the caller's
 * cuda-checkpoint restore reads them back to VRAM.
 *
 * O_DIRECT is used for the image reads when the filesystem supports it (full
 * NVMe bandwidth, no page-cache pollution); otherwise buffered reads.
 * O_DIRECT alignment holds: region sizes are page multiples,
 * GPU_PAGES_DATA_OFFSET and GPU_IO_CHUNK_SIZE are page multiples, and the
 * bounce buffer is posix_memalign'd to 4096.
 */
int restore_gpu_pages(int pid, int tid, uint64_t syscall_addr, int img_dir_fd)
{
	char fname[64];
	int img_fd = -1, data_fd = -1, ret = -1;
	struct gpu_pages_hdr hdr;
	struct gpu_region *regions = NULL;
	struct gpu_chunk *chunks = NULL;
	struct gpu_restore_ctx ctx;
	pthread_t threads[32];
	uint64_t fbase, total_bytes = 0;
	int n_threads, started = 0, i, direct = 1, cap = 0, nc = 0;
	uint32_t r;
	double t0;
	int ns_pid = get_ns_pid(pid);

	pr_info("restore_gpu_pages: host_pid=%d ns_pid=%d\n", pid, ns_pid);
	snprintf(fname, sizeof(fname), "gpu-pages-%d.img", ns_pid);
	img_fd = openat(img_dir_fd, fname, O_RDONLY);
	if (img_fd < 0) {
		if (errno == ENOENT) {
			pr_info("No gpu-pages file for pid %d (ns_pid=%d), skipping\n", pid, ns_pid);
			return 0;
		}
		pr_perror("Cannot open %s", fname);
		return -1;
	}

	if (read(img_fd, &hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr) ||
	    hdr.magic != GPU_PAGES_MAGIC) {
		pr_err("Bad header in %s\n", fname);
		goto out;
	}

	if (hdr.num_regions == 0) {
		ret = 0;
		goto out;
	}

	regions = malloc(hdr.num_regions * sizeof(*regions));
	if (!regions) {
		pr_err("OOM in restore_gpu_pages\n");
		goto out;
	}
	if (read(img_fd, regions, hdr.num_regions * sizeof(*regions)) !=
	    (ssize_t)(hdr.num_regions * sizeof(*regions))) {
		pr_perror("Cannot read region table");
		goto out;
	}
	close(img_fd);
	img_fd = -1;

	/*
	 * Hint THP per region, and slice all regions into a flat chunk
	 * work-list.  Slicing within regions (not just one chunk per region) is
	 * what lets a single huge VMA be filled by all threads at once.
	 */
	fbase = GPU_PAGES_DATA_OFFSET;
	for (r = 0; r < hdr.num_regions; r++) {
		uint64_t off = 0;

		total_bytes += regions[r].size;
		if (syscall_addr)
			inject_syscall(tid, syscall_addr, SYS_madvise,
				       (long)regions[r].start, (long)regions[r].size,
				       MADV_HUGEPAGE, 0, 0, 0);

		while (off < regions[r].size) {
			uint64_t len = regions[r].size - off;

			if (len > GPU_IO_CHUNK_SIZE)
				len = GPU_IO_CHUNK_SIZE;
			if (nc >= cap) {
				int ncap = cap ? cap * 2 : 64;
				struct gpu_chunk *tmp = realloc(chunks, (size_t)ncap * sizeof(*chunks));

				if (!tmp) {
					pr_err("OOM building chunk list\n");
					goto out;
				}
				chunks = tmp;
				cap = ncap;
			}
			chunks[nc].target_addr = regions[r].start + off;
			chunks[nc].file_offset = fbase + off;
			chunks[nc].len = len;
			nc++;
			off += len;
		}
		fbase += regions[r].size;
	}

	/*
	 * Try O_DIRECT; on EINVAL (filesystem doesn't support it) fall back to
	 * buffered reads.  The plugin opens the image itself, so the target
	 * never needs the file visible in its mount namespace.
	 */
	data_fd = openat(img_dir_fd, fname, O_RDONLY | O_DIRECT);
	if (data_fd < 0) {
		if (errno != EINVAL) {
			pr_perror("Cannot open %s for data", fname);
			goto out;
		}
		direct = 0;
		data_fd = openat(img_dir_fd, fname, O_RDONLY);
		if (data_fd < 0) {
			pr_perror("Cannot open %s (buffered)", fname);
			goto out;
		}
		pr_info("O_DIRECT not supported, using buffered reads\n");
	}

	ctx.pid = pid;
	ctx.data_fd = data_fd;
	ctx.chunks = chunks;
	ctx.n_chunks = nc;
	atomic_init(&ctx.next, 0);
	atomic_init(&ctx.err, 0);

	n_threads = gpu_restore_thread_count();
	if (n_threads > nc)
		n_threads = nc;

	t0 = now_ms();
	for (i = 0; i < n_threads; i++) {
		if (pthread_create(&threads[i], NULL, gpu_restore_worker, &ctx) != 0) {
			pr_perror("pthread_create failed");
			break;
		}
		started++;
	}
	if (started == 0)
		gpu_restore_worker(&ctx); /* fall back to inline single-threaded */
	else
		for (i = 0; i < started; i++)
			pthread_join(threads[i], NULL);

	if (atomic_load(&ctx.err) != 0) {
		errno = atomic_load(&ctx.err);
		pr_perror("GPU page restore failed");
		goto out;
	}

	{
		double ms = now_ms() - t0;

		pr_info("[timing] parallel restore: %.0f ms (%.1f GB/s) [%d threads, %d chunks, %s]\n",
			ms, (double)total_bytes / ms / 1e6, started ? started : 1, nc,
			direct ? "O_DIRECT" : "buffered");
	}
	pr_info("Loaded %u GPU regions for pid %d via parallel process_vm_writev\n",
		hdr.num_regions, pid);
	ret = 0;
out:
	free(chunks);
	free(regions);
	if (data_fd >= 0)
		close(data_fd);
	if (img_fd >= 0)
		close(img_fd);
	return ret;
}
