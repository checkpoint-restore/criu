/* Exercise the production positioned-read helpers and real clone3 lifecycle. */
#define sys_preadv_raw test_preadv_raw
#define sys_mmap test_mmap
#define sys_mprotect test_mprotect
#define sys_munmap test_munmap
#define sys_wait4 test_wait4
#define sys_kill test_kill
#define sys_prctl test_prctl
#define sys_getppid test_getppid
#define sys_exit_group test_exit_group
#define sys_close test_close
#define __stack_chk_fail test_unused_stack_chk_fail
#include "../../../criu/pie/restorer.c"
#include <assert.h>
#include <setjmp.h>

extern long kernel_mmap(void *, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long) asm("sys_mmap");
extern long kernel_mprotect(const void *, unsigned long, unsigned long) asm("sys_mprotect");
extern long kernel_munmap(void *, unsigned long) asm("sys_munmap");
extern long kernel_wait4(int, int *, int, struct rusage *) asm("sys_wait4");
extern long kernel_kill(long, int) asm("sys_kill");
extern long kernel_prctl(int, unsigned long, unsigned long, unsigned long, unsigned long) asm("sys_prctl");
extern long kernel_getppid(void) asm("sys_getppid");

struct event { unsigned long offset, bytes; long pid; };
static struct event events[32768];
static unsigned event_count, child_entered, inject_read, inject_wait_eintr, inject_wait_error;
static unsigned fail_parent, fail_child, fail_protect, fail_prctl, wrong_parent;
static unsigned mapped, unmapped, protected, waited, killed, closed, expected_children;
static void *mappings[4];
static unsigned long lengths[4];
static long parent_pid, last_waited;
static struct task_entries entries;
static const struct restore_vma_io *current_rio;
static jmp_buf fatal_jump;

void print_on_level(unsigned int level, const char *format, ...) {}

static int record(unsigned long offset, unsigned long bytes)
{
	unsigned index = __sync_fetch_and_add(&event_count, 1);
	if (index >= ARRAY_SIZE(events))
		return -E2BIG;
	events[index] = (struct event){ offset, bytes, sys_getpid() };
	return 0;
}

long test_preadv_raw(int fd, struct iovec *iov, unsigned long nr, unsigned long offset, unsigned long high)
{
	size_t bytes = 0, skip = offset - current_rio->off;
	unsigned index = 0, injection;
	bool child = sys_getpid() != parent_pid;

	if (fd != 42 || high || !nr || nr > RAW_RESTORE_IOVS || !atomic_read(&entries.last_pid_mutex.raw))
		return -EINVAL;
	if (child) {
		__sync_fetch_and_add(&child_entered, 1);
		if (fail_child)
			return -EIO;
		while (fail_parent)
			asm volatile("pause" ::: "memory");
	} else if (fail_parent) {
		while (__sync_fetch_and_add(&child_entered, 0) < expected_children)
			asm volatile("pause" ::: "memory");
		return -ENOMEM;
	}
	while (index < current_rio->nr_iovs && skip >= current_rio->iovs[index].iov_len) {
		skip -= current_rio->iovs[index].iov_len;
		index++;
	}
	for (unsigned i = 0; i < nr; i++) {
		if (index >= current_rio->nr_iovs || !iov[i].iov_len ||
		    iov[i].iov_base != (char *)current_rio->iovs[index].iov_base + skip ||
		    iov[i].iov_len > current_rio->iovs[index].iov_len - skip)
			return -EINVAL;
		bytes += iov[i].iov_len;
		skip += iov[i].iov_len;
		if (skip == current_rio->iovs[index].iov_len) {
			index++;
			skip = 0;
		}
	}
	if (!bytes || bytes > RAW_RESTORE_CHUNK || (bytes & ~PAGE_MASK))
		return -EINVAL;
	injection = __sync_lock_test_and_set(&inject_read, 0);
	if (injection == 1)
		return -EINTR;
	if (injection == 2 && bytes > PAGE_SIZE)
		bytes = PAGE_SIZE;
	if (injection == 3)
		return 0;
	if (injection == 4)
		return PAGE_SIZE - 1;
	if (injection == 5)
		return bytes + PAGE_SIZE;
	if (record(offset, bytes))
		return -E2BIG;
	return bytes;
}

long test_mmap(void *address, unsigned long length, unsigned long prot, unsigned long flags,
	       unsigned long fd, unsigned long offset)
{
	long result = kernel_mmap(address, length, prot, flags, fd, offset);
	assert(mapped < ARRAY_SIZE(mappings) && flags == (MAP_PRIVATE | MAP_ANONYMOUS));
	assert(prot == ((expected_children && mapped % 2) ? PROT_NONE : PROT_READ | PROT_WRITE));
	if (!IS_ERR_VALUE(result)) {
		mappings[mapped] = (void *)result;
		lengths[mapped++] = length;
	}
	return result;
}

long test_mprotect(const void *address, unsigned long length, unsigned long prot)
{
	assert(length == (64UL << 10) && prot == (PROT_READ | PROT_WRITE));
	assert((char *)address >= (char *)mappings[mapped - 1] + PAGE_SIZE);
	protected++;
	if (fail_protect && protected == fail_protect)
		return -ENOMEM;
	return kernel_mprotect(address, length, prot);
}

long test_munmap(void *address, unsigned long length)
{
	bool found = false;

	assert(!atomic_read(&entries.last_pid_mutex.raw));
	assert(waited == (unmapped / 2 + 1) * expected_children);
	for (unsigned i = 0; i < mapped; i++)
		found |= address == mappings[i] && length == lengths[i];
	assert(found);
	unmapped++;
	return kernel_munmap(address, length);
}

long test_prctl(int option, unsigned long a, unsigned long b, unsigned long c, unsigned long d)
{
	if (option != PR_SET_PDEATHSIG || a != SIGKILL || b || c || d)
		return -EINVAL;
	return fail_prctl ? -EPERM : kernel_prctl(option, a, b, c, d);
}

long test_getppid(void) { return wrong_parent ? parent_pid + 1 : kernel_getppid(); }

long test_wait4(int pid, int *status, int options, struct rusage *usage)
{
	long result;
	assert(pid > 0 && pid != parent_pid && options == __WCLONE && unmapped % 2 == 0);
	assert(atomic_read(&entries.last_pid_mutex.raw));
	if (inject_wait_eintr) {
		inject_wait_eintr--;
		return -EINTR;
	}
	result = kernel_wait4(pid, status, options, usage);
	if (result == pid) {
		waited++;
		last_waited = pid;
	}
	if (inject_wait_error) {
		assert(expected_children == 1 && result == pid);
		return -ECHILD;
	}
	return result;
}

long test_kill(long pid, int signal)
{
	assert(pid > 0 && pid != parent_pid && signal == SIGKILL && !unmapped);
	assert(atomic_read(&entries.last_pid_mutex.raw));
	killed++;
	return kernel_kill(pid, signal);
}

long test_exit_group(int status)
{
	assert(inject_wait_error && status == 1 && waited == 1 && !killed && !unmapped);
	assert(atomic_read(&entries.last_pid_mutex.raw));
	longjmp(fatal_jump, 1);
}

long test_close(int fd)
{
	assert(fd == 42 && mapped == unmapped && !atomic_read(&entries.last_pid_mutex.raw));
	closed++;
	return 0;
}

static void reset(unsigned workers)
{
	memset(&entries, 0, sizeof(entries));
	task_entries_local = &entries;
	parent_pid = sys_getpid();
	expected_children = workers - 1;
	event_count = child_entered = inject_read = inject_wait_eintr = inject_wait_error = 0;
	fail_parent = fail_child = fail_protect = fail_prctl = wrong_parent = 0;
	mapped = unmapped = protected = waited = killed = closed = 0;
}

static int by_offset(const void *a, const void *b)
{
	const struct event *left = a, *right = b;
	return (left->offset > right->offset) - (left->offset < right->offset);
}

static void coverage(const struct restore_vma_io *rio, size_t bytes)
{
	unsigned long offset = rio->off;
	qsort(events, event_count, sizeof(events[0]), by_offset);
	for (unsigned i = 0; i < event_count; i++) {
		assert(events[i].offset == offset);
		offset += events[i].bytes;
	}
	assert(event_count && offset == rio->off + bytes);
}

int main(void)
{
	const unsigned storages[] = { VMA_IO_PACKED_RAW, VMA_IO_ZERO, VMA_IO_ENCODED };
	struct { struct restore_vma_io rio; struct iovec iovs[2050]; } image = {};
	struct task_restore_args args = { .vma_ios_fd = 42 };
	size_t bytes;
	void *original;
	image.rio.nr_iovs = ARRAY_SIZE(image.iovs);
	image.rio.off = 3 * PAGE_SIZE;
	image.iovs[0] = (struct iovec){ (void *)0x100000000UL, (128UL << 20) + PAGE_SIZE };
	for (unsigned i = 1; i < ARRAY_SIZE(image.iovs); i++)
		image.iovs[i] = (struct iovec){ (void *)(0x110000000UL + i * 2 * PAGE_SIZE), PAGE_SIZE };
	current_rio = &image.rio;
	original = malloc(sizeof(image));
	assert(original);
	memcpy(original, &image, sizeof(image));
	assert(raw_restore_size(current_rio, &bytes) == 0);
	for (unsigned workers = 1; workers <= 16; workers *= 2) {
		struct raw_restore_stats stats = {};
		reset(workers);
		args.raw_restore_workers = workers;
		inject_read = workers == 1 ? 2 : 1;
		inject_wait_eintr = workers > 1;
		assert(raw_restore_wave(&args, current_rio, bytes, &stats) == 0);
		assert(stats.read_bytes == bytes && stats.read_calls);
		assert(stats.helper_spawned == workers - 1 && stats.helper_reaped == workers - 1);
		assert(mapped == unmapped && waited == workers - 1 && !killed && !atomic_read(&entries.last_pid_mutex.raw));
		assert(sys_getpid() == parent_pid);
		coverage(current_rio, bytes);
	}
	puts("PASS actual 1/2/4/8/16 workers: disjoint aligned slices, 64MiB/IOV_MAX chunks, holes, short reads and EINTR");
	reset(4);
	args.raw_restore_workers = 4;
	args.vma_ios = &image.rio;
	args.vma_ios_n = 1;
	args.vma_ios_fd = 42;
	assert(restore_vma_workers(&args) == 0 && args.vma_ios_fd == -1 && closed == 1);
	assert(waited == 3);
	coverage(current_rio, bytes);
	assert(memcmp(original, &image, sizeof(image)) == 0);
	puts("PASS worker dispatch, image descriptor cleanup and immutable original RIO");
	args.vma_ios_fd = 42;
	{
		struct raw_restore_stats stats = {};
		reset(3);
		args.raw_restore_workers = 16;
		image.rio.nr_iovs = 1;
		image.iovs[0].iov_len = 3 * PAGE_SIZE;
		assert(raw_restore_wave(&args, current_rio, 3 * PAGE_SIZE, &stats) == 0);
		assert(stats.read_bytes == 3 * PAGE_SIZE && stats.helper_spawned == 2 && stats.helper_reaped == 2);
		memcpy(&image, original, sizeof(image));
	}
	puts("PASS fewer pages than requested workers create only nonempty disjoint shards");
	for (unsigned mode = 0; mode < 8; mode++) {
		struct raw_restore_stats stats = {};
		reset(4);
		args.raw_restore_workers = 4;
		fail_parent = mode == 0;
		fail_child = mode == 1;
		fail_protect = mode == 2 ? 2 : 0;
		if (fail_protect)
			expected_children = 1;
		fail_prctl = mode == 3;
		wrong_parent = mode == 4;
		inject_read = mode == 5 ? 3 : mode == 6 ? 4 : mode == 7 ? 5 : 0;
		assert(raw_restore_wave(&args, current_rio, bytes, &stats) < 0);
		assert(stats.helper_spawned == expected_children && stats.helper_reaped == expected_children);
		assert(mapped == unmapped && waited == expected_children && !atomic_read(&entries.last_pid_mutex.raw));
	}
	puts("PASS parent/child read failure, partial worker startup, parent-death setup/race, EOF, unaligned and excessive progress join before cleanup");
	reset(2);
	args.raw_restore_workers = 2;
	inject_wait_error = 1;
	if (!setjmp(fatal_jump)) {
		struct raw_restore_stats stats = {};
		raw_restore_wave(&args, current_rio, bytes, &stats);
		assert(0);
	} else {
		assert(kernel_wait4(last_waited, NULL, __WCLONE | WNOHANG, NULL) == -ECHILD);
		assert(kernel_munmap(mappings[1], lengths[1]) == 0);
		assert(kernel_munmap(mappings[0], lengths[0]) == 0);
	}
	puts("PASS unproven reap aborts without releasing stack or PID lock and without an unowned kill");
	image.rio.off++;
	assert(raw_restore_size(current_rio, &bytes) == -EINVAL);
	image.rio.off--;
	image.iovs[0].iov_len++;
	assert(raw_restore_size(current_rio, &bytes) == -EINVAL);
	image.iovs[0].iov_len--;
	image.rio.off = LLONG_MAX & PAGE_MASK;
	assert(raw_restore_size(current_rio, &bytes) == -EOVERFLOW);
	image.rio.nr_iovs = -1;
	assert(raw_restore_size(current_rio, &bytes) == -EINVAL);
	for (unsigned i = 0; i < ARRAY_SIZE(storages); i++) {
		image.rio.storage = storages[i];
		assert(raw_restore_size(current_rio, &bytes) == -ENOTSUP);
	}
	free(original);
	puts("PASS invalid alignment, negative vector count source-offset overflow and unsupported storage reject before worker creation");
	return 0;
}
