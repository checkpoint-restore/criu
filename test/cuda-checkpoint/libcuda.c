#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * Mock implementation of the CUDA checkpoint Driver API used by CRIU tests.
 *
 * This library does not access a GPU or maintain real CUDA state. By default,
 * it reports every PID as CUDA and keeps a synthetic process state so
 * tests can verify the plugin's API calls, ptrace coordination, state
 * transitions, and rollback handling without NVIDIA hardware.
 *
 * Built with MOCK_CUDA_CUSTOM_STORAGE, it also provides the CUDA 13.4
 * custom-storage mode. The memory of the CRIU_CUDA_MOCK_CS_DEVICES devices
 * (default 2) is one host buffer split in equal parts: filled from
 * CRIU_CUDA_MOCK_CS_INPUT on checkpoint, written to CRIU_CUDA_MOCK_CS_OUTPUT
 * when a restore completes, so the test can compare the two files.
 * CRIU_CUDA_MOCK_CS_SYNC_ERROR makes the synchronisations fail, as they do
 * when an asynchronous copy failed.
 *
 * Device i's memory is on GPU i at checkpoint. On restore, it goes to the GPU
 * that the device map gives for the dumping host's GPU i (whose UUIDs start at
 * CRIU_CUDA_MOCK_CS_DUMP_UUID_OFFSET), and CRIU_CUDA_MOCK_CS_REVERSE lists the
 * devices in reverse order: the output only matches if CRIU moved each
 * device's memory to the GPU of its region.
 */

#define MOCK_CUDA_SUCCESS	      0
#define MOCK_CUDA_ERROR_INVALID_VALUE 1
#define MOCK_PROCESS_MAX	      64
#define MOCK_GPU_COUNT		      4
#define MOCK_DEVICE_HANDLE_BASE	      100

#ifndef MOCK_CUDA_DRIVER_VERSION
#define MOCK_CUDA_DRIVER_VERSION 13000
#endif

/* Keep these test-local declarations ABI-compatible with the plugin. */
typedef int mock_cuda_result_t;

typedef enum {
	MOCK_CUDA_PROCESS_STATE_RUNNING = 0,
	MOCK_CUDA_PROCESS_STATE_LOCKED,
	MOCK_CUDA_PROCESS_STATE_CHECKPOINTED,
	MOCK_CUDA_PROCESS_STATE_FAILED,
} mock_cuda_process_state_t;

struct mock_cuda_gpu_pair {
	unsigned char old_uuid[16];
	unsigned char new_uuid[16];
};

struct mock_cuda_restore_args {
	struct mock_cuda_gpu_pair *gpu_pairs;
	unsigned int gpu_pairs_count;
};

struct mock_process {
	int pid;
	mock_cuda_process_state_t state;
};

/* Shared, so that a state change made in a child of CRIU is seen by CRIU, as with the real driver. */
static struct mock_processes {
	struct mock_process process[MOCK_PROCESS_MAX];
	unsigned int nr;
} *processes;

__attribute__((constructor)) static void mock_processes_init(void)
{
	processes = mmap(NULL, sizeof(*processes), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (processes == MAP_FAILED)
		_exit(1);
}

static int environment_matches(const char *name, const char *expected_name);

/* Report a misconfigured test case instead of crashing inside CRIU. */
static int required_env_int(const char *name)
{
	const char *value = getenv(name);

	if (!value) {
		fprintf(stderr, "mock libcuda: %s is not set\n", name);
		_exit(1);
	}
	return atoi(value);
}

static void record_api(const char *operation, int pid)
{
	const char *path = getenv("CRIU_CUDA_MOCK_API_MARKER");
	FILE *file;

	if (!path)
		return;
	file = fopen(path, "a");
	if (!file)
		_exit(1);
	fprintf(file, "%s %d %ld\n", operation, pid, (long)syscall(SYS_gettid));
	if (fclose(file))
		_exit(1);
}

static mock_cuda_process_state_t initial_process_state(void)
{
	const char *state = getenv("CRIU_CUDA_MOCK_INITIAL_STATE");

	if (!state || !strcmp(state, "running"))
		return MOCK_CUDA_PROCESS_STATE_RUNNING;
	if (!strcmp(state, "locked"))
		return MOCK_CUDA_PROCESS_STATE_LOCKED;
	if (!strcmp(state, "checkpointed"))
		return MOCK_CUDA_PROCESS_STATE_CHECKPOINTED;
	if (!strcmp(state, "failed"))
		return MOCK_CUDA_PROCESS_STATE_FAILED;
	return MOCK_CUDA_PROCESS_STATE_RUNNING;
}

static struct mock_process *get_process(int pid)
{
	unsigned int i;

	for (i = 0; i < processes->nr; i++) {
		if (processes->process[i].pid == pid)
			return &processes->process[i];
	}

	if (processes->nr == MOCK_PROCESS_MAX)
		return NULL;

	processes->process[processes->nr].pid = pid;
	processes->process[processes->nr].state = initial_process_state();
	return &processes->process[processes->nr++];
}

static bool checkpoint_behavior(int pid, const char *behavior);

static void format_uuid(FILE *file, const unsigned char uuid[16])
{
	unsigned int i;

	fputs("GPU-", file);
	for (i = 0; i < 16; i++) {
		if (i == 4 || i == 6 || i == 8 || i == 10)
			fputc('-', file);
		fprintf(file, "%02x", uuid[i]);
	}
}

static int record_device_map(const struct mock_cuda_restore_args *args)
{
	const char *path = getenv("CRIU_CUDA_MOCK_DEVICE_MAP_MARKER");
	FILE *file;
	unsigned int i;

	if (!path)
		return 0;
	if (!args || !args->gpu_pairs || !args->gpu_pairs_count)
		return MOCK_CUDA_ERROR_INVALID_VALUE;

	file = fopen(path, "a");
	if (!file)
		return MOCK_CUDA_ERROR_INVALID_VALUE;
	for (i = 0; i < args->gpu_pairs_count; i++) {
		if (i)
			fputc(',', file);
		format_uuid(file, args->gpu_pairs[i].old_uuid);
		fputc('=', file);
		format_uuid(file, args->gpu_pairs[i].new_uuid);
	}
	fputc('\n', file);
	fclose(file);
	return 0;
}

mock_cuda_result_t cuInit(unsigned int flags)
{
	const char *marker = getenv("CRIU_CUDA_MOCK_INIT_MARKER");
	const char *delay = getenv("CRIU_CUDA_MOCK_INIT_DELAY_MS");

	record_api("init", 0);
	(void)flags;
	if (getenv("CRIU_CUDA_MOCK_INIT_FAULT") &&
	    checkpoint_behavior(required_env_int("CRIU_CUDA_MOCK_TARGET_PID"), "fault"))
		return MOCK_CUDA_ERROR_INVALID_VALUE;
	if (getenv("CRIU_CUDA_MOCK_INIT_HANG")) {
		for (;;)
			pause();
	}
	if (delay)
		usleep((useconds_t)atoi(delay) * 1000);
	if (marker) {
		FILE *file = fopen(marker, "a");

		if (!file)
			return MOCK_CUDA_ERROR_INVALID_VALUE;
		fprintf(file, "%ld\n", (long)getpid());
		if (fclose(file))
			return MOCK_CUDA_ERROR_INVALID_VALUE;
	}
	if (getenv("CRIU_CUDA_MOCK_INIT_EXIT"))
		_exit(EXIT_FAILURE);
	if (getenv("CRIU_CUDA_MOCK_INIT_ERROR"))
		return MOCK_CUDA_ERROR_INVALID_VALUE;
	if (!environment_matches("CUDA_VISIBLE_DEVICES", "CRIU_CUDA_MOCK_EXPECT_VISIBLE_DEVICES") ||
	    !environment_matches("CUDA_DEVICE_ORDER", "CRIU_CUDA_MOCK_EXPECT_DEVICE_ORDER"))
		return MOCK_CUDA_ERROR_INVALID_VALUE;
	return MOCK_CUDA_SUCCESS;
}

static int environment_matches(const char *name, const char *expected_name)
{
	const char *expected = getenv(expected_name);
	const char *value;

	if (!expected)
		return 1;
	value = getenv(name);
	return value && !strcmp(value, expected);
}

mock_cuda_result_t cuDeviceGetCount(int *count)
{
	if (!count ||
	    !environment_matches("CUDA_VISIBLE_DEVICES", "CRIU_CUDA_MOCK_EXPECT_VISIBLE_DEVICES") ||
	    !environment_matches("CUDA_DEVICE_ORDER", "CRIU_CUDA_MOCK_EXPECT_DEVICE_ORDER"))
		return MOCK_CUDA_ERROR_INVALID_VALUE;

	/* CRIU_CUDA_MOCK_VISIBLE_GPUS: CRIU sees fewer GPUs, as in a container's device cgroup */
	*count = getenv("CRIU_CUDA_MOCK_VISIBLE_GPUS") ? atoi(getenv("CRIU_CUDA_MOCK_VISIBLE_GPUS")) : MOCK_GPU_COUNT;
	return MOCK_CUDA_SUCCESS;
}

mock_cuda_result_t cuDeviceGet(int *device, int ordinal)
{
	if (!device || ordinal < 0 || ordinal >= MOCK_GPU_COUNT)
		return MOCK_CUDA_ERROR_INVALID_VALUE;

	/* Device handles differ from ordinals so callers must use cuDeviceGet(). */
	*device = MOCK_DEVICE_HANDLE_BASE + ordinal;
	return MOCK_CUDA_SUCCESS;
}

/* Like a MIG instance, the original symbol reports only a parent GPU UUID. */
mock_cuda_result_t cuDeviceGetUuid(void *uuid, int device)
{
	if (!uuid || device < MOCK_DEVICE_HANDLE_BASE || device >= MOCK_DEVICE_HANDLE_BASE + MOCK_GPU_COUNT)
		return MOCK_CUDA_ERROR_INVALID_VALUE;

	memset(uuid, 0xee, 16);
	return MOCK_CUDA_SUCCESS;
}

/* UUID of GPU ordinal on a host whose UUIDs start at the offset in the environment variable name. */
static int mock_uuid(const char *name, int ordinal, unsigned char *bytes)
{
	const char *offset_value = getenv(name);
	unsigned long offset = 0;
	char *end = NULL;
	unsigned int i;

	if (offset_value) {
		errno = 0;
		offset = strtoul(offset_value, &end, 0);
		if (errno || end == offset_value || *end || offset > 0xff)
			return -1;
	}

	for (i = 0; i < 16; i++)
		bytes[i] = (unsigned char)(offset + (unsigned int)ordinal * 16 + i);
	return 0;
}

mock_cuda_result_t cuDeviceGetUuid_v2(void *uuid, int device)
{
	if (!uuid || device < MOCK_DEVICE_HANDLE_BASE || device >= MOCK_DEVICE_HANDLE_BASE + MOCK_GPU_COUNT)
		return MOCK_CUDA_ERROR_INVALID_VALUE;
	if (mock_uuid("CRIU_CUDA_MOCK_UUID_OFFSET", device - MOCK_DEVICE_HANDLE_BASE, uuid))
		return MOCK_CUDA_ERROR_INVALID_VALUE;
	return MOCK_CUDA_SUCCESS;
}

mock_cuda_result_t cuDriverGetVersion(int *driver_version)
{
	const char *marker = getenv("CRIU_CUDA_MOCK_DRIVER_MARKER");

	if (marker) {
		FILE *marker_file = fopen(marker, "a");

		if (!marker_file)
			return MOCK_CUDA_ERROR_INVALID_VALUE;
		fputs("invoked\n", marker_file);
		fclose(marker_file);
	}

	if (getenv("CRIU_CUDA_MOCK_DRIVER_VERSION_ERROR"))
		return MOCK_CUDA_ERROR_INVALID_VALUE;
	if (!driver_version)
		return MOCK_CUDA_ERROR_INVALID_VALUE;

	*driver_version = MOCK_CUDA_DRIVER_VERSION;
	return MOCK_CUDA_SUCCESS;
}

mock_cuda_result_t cuGetErrorName(mock_cuda_result_t error, const char **pstr)
{
	*pstr = error == MOCK_CUDA_SUCCESS ? "CUDA_SUCCESS" : "CUDA_ERROR_MOCK";
	return MOCK_CUDA_SUCCESS;
}

mock_cuda_result_t cuGetErrorString(mock_cuda_result_t error, const char **pstr)
{
	*pstr = error == MOCK_CUDA_SUCCESS ? "success" : "mock CUDA error";
	return MOCK_CUDA_SUCCESS;
}

mock_cuda_result_t cuCheckpointProcessGetRestoreThreadId(int pid, int *tid)
{
	const char *error = getenv("CRIU_CUDA_MOCK_TID_ERROR");
	const char *cuda_pid = getenv("CRIU_CUDA_MOCK_CUDA_PID");

	record_api("get-tid", pid);
	/* A selected PID can remain CUDA while the rest of a process tree is not. */
	if (error && (!cuda_pid || atoi(cuda_pid) != pid))
		return atoi(error);

	*tid = getenv("CRIU_CUDA_MOCK_RESTORE_TID") ? atoi(getenv("CRIU_CUDA_MOCK_RESTORE_TID")) : pid;
	return MOCK_CUDA_SUCCESS;
}

mock_cuda_result_t cuCheckpointProcessGetState(int pid, mock_cuda_process_state_t *state)
{
	struct mock_process *process = get_process(pid);

	record_api("get-state", pid);
	if (!process)
		return MOCK_CUDA_ERROR_INVALID_VALUE;
	*state = process->state;
	return MOCK_CUDA_SUCCESS;
}

mock_cuda_result_t cuCheckpointProcessLock(int pid, void *args)
{
	struct mock_process *process = get_process(pid);
	const char *marker = getenv("CRIU_CUDA_MOCK_LOCK_MARKER");

	(void)args;
	record_api("lock", pid);
	if (getenv("CRIU_CUDA_MOCK_LOCK_HANG")) {
		for (;;)
			pause();
	}

	if (marker) {
		FILE *file = fopen(marker, "a");

		if (!file)
			return MOCK_CUDA_ERROR_INVALID_VALUE;
		fputs("lock\n", file);
		fclose(file);
	}

	if (!process || process->state != MOCK_CUDA_PROCESS_STATE_RUNNING)
		return MOCK_CUDA_ERROR_INVALID_VALUE;
	process->state = MOCK_CUDA_PROCESS_STATE_LOCKED;
	return MOCK_CUDA_SUCCESS;
}

/* Model a blocking driver request with a pipe held open by the target.
 * Killing the target closes the pipe and lets the worker return normally.
 */
static bool checkpoint_behavior(int pid, const char *behavior)
{
	const char *tid_value = getenv("CRIU_CUDA_MOCK_RESTORE_TID");
	int tid = tid_value ? atoi(tid_value) : pid;
	bool fault;

	if (!behavior)
		return false;
	if (!strcmp(behavior, "exit"))
		_exit(77);
	if (!strcmp(behavior, "unrelated")) {
		int fd = required_env_int("CRIU_CUDA_MOCK_OTHER_FD");

		if (write(fd, "x", 1) != 1)
			_exit(1);
	}
	fault = !strcmp(behavior, "fault") || !strcmp(behavior, "target-exit");
	if (fault) {
		const char *path = getenv("CRIU_CUDA_MOCK_FAULT_TRIGGER");
		FILE *file = path ? fopen(path, "w") : NULL;

		if (!file || fclose(file))
			_exit(1);
	}
	if (!strcmp(behavior, "trap") && syscall(SYS_tgkill, pid, tid, SIGTRAP))
		_exit(1);
	if (!strcmp(behavior, "target-kill") && kill(pid, SIGKILL))
		_exit(1);
	if (fault || !strcmp(behavior, "trap") || !strcmp(behavior, "target-kill")) {
		int fd = required_env_int("CRIU_CUDA_MOCK_TARGET_PIPE");
		char byte;
		ssize_t ret;

		do {
			ret = read(fd, &byte, 1);
		} while (ret < 0 && errno == EINTR);
		if (ret != 0)
			_exit(1);
		return true;
	}
	if (!strcmp(behavior, "hang")) {
		for (;;)
			pause();
	}
	return false;
}

#ifdef MOCK_CUDA_CUSTOM_STORAGE
/* Layouts from plugins/cuda/cuda_custom_storage.h */
struct mock_cs_device {
	unsigned long long dev_ptr;
	size_t size;
	void *stream;
};

struct mock_cs_info {
	void *handle;
	struct mock_cs_device *devices;
	unsigned int device_count;
};

static struct mock_cs_device cs_devices[MOCK_GPU_COUNT];
static char cs_ctx[MOCK_GPU_COUNT];	/* the primary context of each GPU */
static int cs_retained[MOCK_GPU_COUNT]; /* references to it */
static int cs_gpu[MOCK_GPU_COUNT];	/* the GPU of each device */
static struct mock_cs_info cs_info = { &cs_info, cs_devices, 0 };
static char *cs_buf;
static size_t cs_size;
static bool cs_restoring;
static __thread void *current_ctx; /* copies need a context set in the calling thread */

/* GPU ordinal that a restore with this device map puts the dumping host's GPU i on. */
static int mock_cs_restore_gpu(const struct mock_cuda_restore_args *args, int i)
{
	unsigned char old_uuid[16], new_uuid[16];
	unsigned int p;
	int j;

	if (!args->gpu_pairs_count)
		return i;
	if (mock_uuid("CRIU_CUDA_MOCK_CS_DUMP_UUID_OFFSET", i, old_uuid))
		return -1;
	for (p = 0; p < args->gpu_pairs_count; p++) {
		if (memcmp(args->gpu_pairs[p].old_uuid, old_uuid, 16))
			continue;
		for (j = 0; j < MOCK_GPU_COUNT; j++)
			if (!mock_uuid("CRIU_CUDA_MOCK_UUID_OFFSET", j, new_uuid) &&
			    !memcmp(args->gpu_pairs[p].new_uuid, new_uuid, 16))
				return j;
	}
	return -1;
}

/* customStorageInfo_out is at offset 0 of the checkpoint args, 16 of the restore args. */
static int mock_cs_begin(bool restore, void *args, size_t out_offset)
{
	struct mock_cs_info **out = *(struct mock_cs_info ***)((char *)args + out_offset);
	int i, n = atoi(getenv("CRIU_CUDA_MOCK_CS_DEVICES") ?: "2");
	char *buf = NULL;
	FILE *file;
	long size;

	if (n < 1 || n > MOCK_GPU_COUNT)
		return -1;
	if (!out)
		return 0; /* custom storage not requested */
	file = fopen(getenv("CRIU_CUDA_MOCK_CS_INPUT") ?: "", "r");
	if (!file || fseek(file, 0, SEEK_END) || (size = ftell(file)) <= 0 || !(buf = malloc(size)))
		return -1;
	rewind(file);
	if (restore)
		memset(buf, 0xa5, size);
	else if (fread(buf, 1, size, file) != (size_t)size)
		return -1;
	fclose(file);
	for (i = 0; i < n; i++) {
		size_t start = size * i / n, end = size * (i + 1) / n;
		int k = restore && getenv("CRIU_CUDA_MOCK_CS_REVERSE") ? n - 1 - i : i;

		cs_devices[k] = (struct mock_cs_device){ (uintptr_t)(buf + start), end - start, &cs_devices[k] };
		cs_gpu[k] = restore ? mock_cs_restore_gpu(args, i) : i;
		/* like CUDA_ERROR_INVALID_CONTEXT: the caller must retain the primary context of each GPU */
		if (cs_gpu[k] < 0 || !cs_retained[cs_gpu[k]])
			return -1;
	}
	cs_info.device_count = n;
	cs_buf = buf;
	cs_size = size;
	cs_restoring = restore;
	*out = &cs_info;
	return 0;
}

mock_cuda_result_t cuCheckpointOperationComplete(void *handle)
{
	FILE *file;

	if (handle != &cs_info)
		return MOCK_CUDA_ERROR_INVALID_VALUE;
	if (cs_restoring) {
		file = fopen(getenv("CRIU_CUDA_MOCK_CS_OUTPUT") ?: "", "w");
		if (!file || fwrite(cs_buf, 1, cs_size, file) != cs_size || fclose(file))
			return MOCK_CUDA_ERROR_INVALID_VALUE;
	}
	free(cs_buf);
	return MOCK_CUDA_SUCCESS;
}

#define MOCK_NOOP(name, ...)                 \
	mock_cuda_result_t name(__VA_ARGS__) \
	{                                    \
		return MOCK_CUDA_SUCCESS;    \
	}
MOCK_NOOP(cuStreamDestroy, void *stream)
MOCK_NOOP(cuEventRecord, void *event, void *stream)
MOCK_NOOP(cuEventDestroy, void *event)

/* Errors of asynchronous copies show up when synchronising. */
mock_cuda_result_t cuEventSynchronize(void *event)
{
	return getenv("CRIU_CUDA_MOCK_CS_SYNC_ERROR") ? MOCK_CUDA_ERROR_INVALID_VALUE : MOCK_CUDA_SUCCESS;
}

mock_cuda_result_t cuStreamSynchronize(void *stream)
{
	return getenv("CRIU_CUDA_MOCK_CS_SYNC_ERROR") ? MOCK_CUDA_ERROR_INVALID_VALUE : MOCK_CUDA_SUCCESS;
}

/* CRIU_CUDA_MOCK_CTX_MARKER records the ordinal of each GPU whose primary context is retained. */
mock_cuda_result_t cuDevicePrimaryCtxRetain(void **ctx, int device)
{
	const char *marker = getenv("CRIU_CUDA_MOCK_CTX_MARKER");
	int ordinal = device - MOCK_DEVICE_HANDLE_BASE;

	if (ordinal < 0 || ordinal >= MOCK_GPU_COUNT)
		return MOCK_CUDA_ERROR_INVALID_VALUE;
	if (marker) {
		FILE *file = fopen(marker, "a");

		if (!file)
			return MOCK_CUDA_ERROR_INVALID_VALUE;
		fprintf(file, "%d\n", ordinal);
		fclose(file);
	}
	cs_retained[ordinal]++;
	*ctx = &cs_ctx[ordinal];
	return MOCK_CUDA_SUCCESS;
}

mock_cuda_result_t cuDevicePrimaryCtxRelease(int device)
{
	int ordinal = device - MOCK_DEVICE_HANDLE_BASE;

	if (ordinal < 0 || ordinal >= MOCK_GPU_COUNT || !cs_retained[ordinal])
		return MOCK_CUDA_ERROR_INVALID_VALUE;
	cs_retained[ordinal]--;
	return MOCK_CUDA_SUCCESS;
}

mock_cuda_result_t cuCtxGetDevice(int *device)
{
	char *ctx = current_ctx;

	if (ctx < cs_ctx || ctx >= cs_ctx + MOCK_GPU_COUNT)
		return MOCK_CUDA_ERROR_INVALID_VALUE;
	*device = MOCK_DEVICE_HANDLE_BASE + (int)(ctx - cs_ctx);
	return MOCK_CUDA_SUCCESS;
}

mock_cuda_result_t cuCtxSetCurrent(void *ctx)
{
	current_ctx = ctx;
	return MOCK_CUDA_SUCCESS;
}

mock_cuda_result_t cuStreamCreate(void **stream, unsigned int flags)
{
	*stream = &cs_info;
	return current_ctx ? MOCK_CUDA_SUCCESS : MOCK_CUDA_ERROR_INVALID_VALUE;
}

mock_cuda_result_t cuEventCreate(void **event, unsigned int flags)
{
	*event = &cs_info;
	return MOCK_CUDA_SUCCESS;
}

/* CRIU_CUDA_MOCK_CS_MAX_HOST_ALLOCS caps the pinned allocations of one CRIU run. */
mock_cuda_result_t cuMemHostAlloc(void **ptr, size_t size, unsigned int flags)
{
	static int allocs;
	const char *max = getenv("CRIU_CUDA_MOCK_CS_MAX_HOST_ALLOCS");

	if (max && ++allocs > atoi(max))
		return MOCK_CUDA_ERROR_INVALID_VALUE;
	return posix_memalign(ptr, 4096, size) ? MOCK_CUDA_ERROR_INVALID_VALUE : MOCK_CUDA_SUCCESS;
}

mock_cuda_result_t cuMemFreeHost(void *ptr)
{
	free(ptr);
	return MOCK_CUDA_SUCCESS;
}

mock_cuda_result_t cuMemcpyDtoHAsync(void *dst, unsigned long long src, size_t size, void *stream)
{
	memcpy(dst, (void *)(uintptr_t)src, size);
	return current_ctx ? MOCK_CUDA_SUCCESS : MOCK_CUDA_ERROR_INVALID_VALUE;
}

mock_cuda_result_t cuMemcpyHtoDAsync(unsigned long long dst, const void *src, size_t size, void *stream)
{
	memcpy((void *)(uintptr_t)dst, src, size);
	return current_ctx ? MOCK_CUDA_SUCCESS : MOCK_CUDA_ERROR_INVALID_VALUE;
}

/* Only the 3-argument cuStreamGetCtx_v2 exists; the plugin must get it through cuGetProcAddress. */
static mock_cuda_result_t stream_get_ctx_v2(void *stream, void **ctx, void **green_ctx)
{
	struct mock_cs_device *d = stream;

	if (d < cs_devices || d >= cs_devices + MOCK_GPU_COUNT)
		return MOCK_CUDA_ERROR_INVALID_VALUE;
	*ctx = &cs_ctx[cs_gpu[d - cs_devices]];
	*green_ctx = NULL;
	return MOCK_CUDA_SUCCESS;
}

/* The plugin resolves everything here; versioned symbols get their latest ABI, as from the driver. */
mock_cuda_result_t cuGetProcAddress_v2(const char *symbol, void **pfn, int version, unsigned long long flags,
				       int *status)
{
	Dl_info self;
	void *handle;

	if (!strcmp(symbol, "cuStreamGetCtx")) {
		*pfn = (void *)stream_get_ctx_v2;
	} else if (!strcmp(symbol, "cuDeviceGetUuid")) {
		*pfn = (void *)cuDeviceGetUuid_v2;
	} else {
		if (!dladdr((void *)cuGetProcAddress_v2, &self) ||
		    !(handle = dlopen(self.dli_fname, RTLD_LAZY | RTLD_NOLOAD)))
			return MOCK_CUDA_ERROR_INVALID_VALUE;
		*pfn = dlsym(handle, symbol);
		dlclose(handle);
	}
	/* CU_GET_PROC_ADDRESS_SUCCESS or CU_GET_PROC_ADDRESS_SYMBOL_NOT_FOUND */
	if (status)
		*status = *pfn ? 0 : 1;
	return *pfn ? MOCK_CUDA_SUCCESS : MOCK_CUDA_ERROR_INVALID_VALUE;
}
#endif /* MOCK_CUDA_CUSTOM_STORAGE */

mock_cuda_result_t cuCheckpointProcessCheckpoint(int pid, void *args)
{
	struct mock_process *process = get_process(pid);

	(void)args;
	record_api("checkpoint", pid);
	if (checkpoint_behavior(pid, getenv("CRIU_CUDA_MOCK_CHECKPOINT_BEHAVIOR")))
		return MOCK_CUDA_ERROR_INVALID_VALUE;

	if (!process || process->state != MOCK_CUDA_PROCESS_STATE_LOCKED)
		return MOCK_CUDA_ERROR_INVALID_VALUE;
	process->state = MOCK_CUDA_PROCESS_STATE_CHECKPOINTED;
#ifdef MOCK_CUDA_CUSTOM_STORAGE
	if (mock_cs_begin(false, args, 0))
		return MOCK_CUDA_ERROR_INVALID_VALUE;
#endif
	/* Test rollback when the mock changes state before reporting an error. */
	if (getenv("CRIU_CUDA_MOCK_CHECKPOINT_ERROR_AFTER_TRANSITION"))
		return MOCK_CUDA_ERROR_INVALID_VALUE;
	return MOCK_CUDA_SUCCESS;
}

mock_cuda_result_t cuCheckpointProcessRestore(int pid, void *args)
{
	struct mock_process *process = get_process(pid);

	record_api("restore", pid);
	if (checkpoint_behavior(pid, getenv("CRIU_CUDA_MOCK_RESTORE_BEHAVIOR")))
		return MOCK_CUDA_ERROR_INVALID_VALUE;

	if (getenv("CRIU_CUDA_MOCK_RESTORE_ERROR"))
		return MOCK_CUDA_ERROR_INVALID_VALUE;

	if (!process || process->state != MOCK_CUDA_PROCESS_STATE_CHECKPOINTED)
		return MOCK_CUDA_ERROR_INVALID_VALUE;
	if (record_device_map(args))
		return MOCK_CUDA_ERROR_INVALID_VALUE;
#ifdef MOCK_CUDA_CUSTOM_STORAGE
	if (mock_cs_begin(true, args, 16))
		return MOCK_CUDA_ERROR_INVALID_VALUE;
#endif
	process->state = MOCK_CUDA_PROCESS_STATE_LOCKED;
	return MOCK_CUDA_SUCCESS;
}

mock_cuda_result_t cuCheckpointProcessUnlock(int pid, void *args)
{
	struct mock_process *process = get_process(pid);

	(void)args;
	record_api("unlock", pid);

	if (getenv("CRIU_CUDA_MOCK_UNLOCK_ERROR"))
		return MOCK_CUDA_ERROR_INVALID_VALUE;

	if (!process || process->state != MOCK_CUDA_PROCESS_STATE_LOCKED)
		return MOCK_CUDA_ERROR_INVALID_VALUE;
	process->state = MOCK_CUDA_PROCESS_STATE_RUNNING;
	return MOCK_CUDA_SUCCESS;
}
