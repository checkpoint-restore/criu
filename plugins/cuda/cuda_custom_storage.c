/*
 * CUDA custom-storage checkpoint/restore engine (CUDA 13.4 driver API, driver >= R615).
 *
 * The Driver API backend calls cuCheckpointProcessCheckpoint()/Restore() with
 * customStorageInfo_out set; the driver then maps the target's GPU memory into
 * CRIU (one contiguous region per GPU, with a stream in that GPU's primary
 * context) and this file moves the bytes between those regions and
 * gpu-cs-<nspid>.img with N worker threads, each owning a CUDA stream and two
 * pinned 64 MB buffers (disk I/O of one chunk overlaps the PCIe transfer of the
 * other).  cuda_cs_complete() then lets the driver finish the operation.
 *
 * Notes: driver symbols are resolved through cuGetProcAddress, since dlsym
 * returns the legacy ABI of versioned symbols (CUDA_ERROR_INVALID_CONTEXT on
 * memcpy); for cuStreamGetCtx that is the 3-argument cuStreamGetCtx_v2 (the
 * third returns a green context, NULL for the primary contexts used here).
 * The caller must be allowed to ptrace the target, as CRIU already is.
 * The mapped pointer carries no CU_POINTER_ATTRIBUTE_CONTEXT; use the stream's.
 */
#include "criu-log.h"
#include "cuda_custom_storage.h"
#include "cuda.pb-c.h"

#include <dlfcn.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif
#define LOG_PREFIX "cuda_cs: "

#define CS_CHUNK	 (64UL << 20)
#define CS_MAXTHR	 32
#define CS_HDR		 4096
#define CS_MAGIC	 "CUCS"
#define CS_IMAGE_VERSION 1
#define CS_MAXGPU	 64

enum cuda_cs_mode cuda_cs_mode = CUDA_CS_AUTO;
static bool cs_available;

typedef int CUdevice;
typedef void *CUcontext;
typedef void *CUstream;
typedef void *CUevent;
typedef unsigned long long CUdeviceptr;

static struct {
	CUresult (*get_proc_address)(const char *, void **, int, unsigned long long, int *);
	CUresult (*get_error_string)(CUresult, const char **);
	CUresult (*device_get_count)(int *);
	CUresult (*device_get)(CUdevice *, int);
	CUresult (*primary_ctx_retain)(CUcontext *, CUdevice);
	CUresult (*primary_ctx_release)(CUdevice);
	CUresult (*ctx_set_current)(CUcontext);
	CUresult (*ctx_get_device)(CUdevice *);
	CUresult (*device_get_uuid)(unsigned char *, CUdevice);
	CUresult (*stream_get_ctx)(CUstream, CUcontext *, void ** /* CUgreenCtx */);
	CUresult (*stream_create)(CUstream *, unsigned);
	CUresult (*stream_destroy)(CUstream);
	CUresult (*stream_synchronize)(CUstream);
	CUresult (*mem_host_alloc)(void **, size_t, unsigned);
	CUresult (*mem_free_host)(void *);
	CUresult (*memcpy_dtoh_async)(void *, CUdeviceptr, size_t, CUstream);
	CUresult (*memcpy_htod_async)(CUdeviceptr, const void *, size_t, CUstream);
	CUresult (*event_create)(CUevent *, unsigned);
	CUresult (*event_destroy)(CUevent);
	CUresult (*event_record)(CUevent, CUstream);
	CUresult (*event_synchronize)(CUevent);
	CUresult (*operation_complete)(CUcheckpointOperationHandle);
} cs;

#define CS_CUDA_VERSION 13040 /* ABI version to request from cuGetProcAddress */

#define CU_GET_PROC_ADDRESS_SUCCESS 0

static const char *cs_err(CUresult res)
{
	const char *s = "?";
	if (cs.get_error_string)
		cs.get_error_string(res, &s);
	return s;
}

/*
 * Resolve every symbol through cuGetProcAddress at the custom-storage ABI
 * version: dlsym returns the oldest ABI of a versioned symbol (the
 * 2-argument cuStreamGetCtx, the parent-GPU cuDeviceGetUuid, ...).
 */
static void *cs_resolve(const char *name)
{
	void *fn = NULL;
	int status = -1;

	if (cs.get_proc_address(name, &fn, CS_CUDA_VERSION, 0, &status) != CUDA_SUCCESS ||
	    status != CU_GET_PROC_ADDRESS_SUCCESS)
		return NULL;
	return fn;
}

int cuda_cs_init(void *h)
{
	cs_available = false;
	if (!h)
		return -EINVAL;
	/* CUDA 12.0+; the driver reports whether it has the 13.4 API through it. */
	cs.get_proc_address = dlsym(h, "cuGetProcAddress_v2");
	if (!cs.get_proc_address) {
		pr_debug("libcuda has no cuGetProcAddress_v2: custom storage unavailable\n");
		return -ENOTSUP;
	}
	cs.operation_complete = cs_resolve("cuCheckpointOperationComplete");
	if (!cs.operation_complete) {
		pr_debug("libcuda has no cuCheckpointOperationComplete: custom storage unavailable\n");
		return -ENOTSUP;
	}
#define R(field, name)                                                       \
	do {                                                                 \
		cs.field = cs_resolve(name);                                 \
		if (!cs.field) {                                             \
			pr_err("Unable to resolve %s from libcuda\n", name); \
			return -ENOENT;                                      \
		}                                                            \
	} while (0)
	R(get_error_string, "cuGetErrorString");
	R(device_get_count, "cuDeviceGetCount");
	R(device_get, "cuDeviceGet");
	R(primary_ctx_retain, "cuDevicePrimaryCtxRetain");
	R(primary_ctx_release, "cuDevicePrimaryCtxRelease");
	R(ctx_set_current, "cuCtxSetCurrent");
	R(ctx_get_device, "cuCtxGetDevice");
	/* the instance's UUID for a MIG instance, not its parent GPU's */
	R(device_get_uuid, "cuDeviceGetUuid");
	/* the 3-argument ABI, which also reports a green context */
	R(stream_get_ctx, "cuStreamGetCtx");
	R(stream_create, "cuStreamCreate");
	R(stream_destroy, "cuStreamDestroy");
	R(stream_synchronize, "cuStreamSynchronize");
	R(mem_host_alloc, "cuMemHostAlloc");
	R(mem_free_host, "cuMemFreeHost");
	R(memcpy_dtoh_async, "cuMemcpyDtoHAsync");
	R(memcpy_htod_async, "cuMemcpyHtoDAsync");
	R(event_create, "cuEventCreate");
	R(event_destroy, "cuEventDestroy");
	R(event_record, "cuEventRecord");
	R(event_synchronize, "cuEventSynchronize");
#undef R
	cs_available = true;
	pr_info("custom-storage checkpoint API available\n");
	return 0;
}

bool cuda_cs_active(void)
{
	return cs_available && cuda_cs_mode != CUDA_CS_OFF;
}

int cuda_cs_check_restore(int pid)
{
	if (!cs_available) {
		pr_err("pid %d was checkpointed to custom storage, but libcuda has no custom-storage checkpoint API\n",
		       pid);
		return -1;
	}
	if (cuda_cs_mode == CUDA_CS_OFF) {
		pr_err("pid %d was checkpointed to custom storage and cannot be restored with cuda_plugin.custom-storage=off\n",
		       pid);
		return -1;
	}
	return 0;
}

int cuda_cs_complete(CUcheckpointOperationHandle handle)
{
	CUresult res = cs.operation_complete(handle);
	if (res != CUDA_SUCCESS) {
		pr_err("cuCheckpointOperationComplete: %s\n", cs_err(res));
		return -1;
	}
	return 0;
}

/* The pid of a task in its own pid namespace: the last NSpid field. */
static int cs_ns_pid(int pid)
{
	char path[64], line[256];
	int ns = -1;
	FILE *f;

	snprintf(path, sizeof(path), "/proc/%d/status", pid);
	f = fopen(path, "r");
	if (!f) {
		pr_perror("Unable to open %s", path);
		return -1;
	}
	while (fgets(line, sizeof(line), f)) {
		if (!strncmp(line, "NSpid:", 6)) {
			char *p = line + 6, *last = NULL, *tok, *save;

			for (tok = strtok_r(p, " \t\n", &save); tok; tok = strtok_r(NULL, " \t\n", &save))
				last = tok;
			if (last)
				ns = atoi(last);
			break;
		}
	}
	fclose(f);
	if (ns <= 0)
		pr_err("Unable to find the namespace pid of %d\n", pid);
	return ns;
}

static int cs_image_name(int pid, char *buf, size_t len)
{
	int ns = cs_ns_pid(pid);

	if (ns <= 0)
		return -1;
	snprintf(buf, len, "gpu-cs-%d.img", ns);
	return 0;
}

int cuda_cs_image_exists(int pid, int img_dir_fd)
{
	char fname[64];

	if (cs_image_name(pid, fname, sizeof(fname)))
		return -1;
	if (!faccessat(img_dir_fd, fname, F_OK, 0))
		return 1;
	if (errno == ENOENT)
		return 0;
	pr_perror("Unable to check for %s", fname);
	return -1;
}

int cuda_cs_image_remove(int pid, int img_dir_fd)
{
	char fname[64];

	if (cs_image_name(pid, fname, sizeof(fname)))
		return -1;
	if (unlinkat(img_dir_fd, fname, 0) && errno != ENOENT) {
		pr_perror("Unable to remove stale %s", fname);
		return -1;
	}
	return 0;
}

/* "GPU-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" as NVML prints it */
static int cs_parse_uuid(const char *text, unsigned char uuid[16])
{
	int digits = 0, v;

	if (strncmp(text, "GPU-", 4))
		return -1;
	for (text += 4; *text; text++) {
		if (*text == '-')
			continue;
		if (*text >= '0' && *text <= '9')
			v = *text - '0';
		else if (*text >= 'a' && *text <= 'f')
			v = *text - 'a' + 10;
		else if (*text >= 'A' && *text <= 'F')
			v = *text - 'A' + 10;
		else
			return -1;
		if (digits == 32)
			return -1;
		if (digits & 1)
			uuid[digits / 2] |= v;
		else
			uuid[digits / 2] = v << 4;
		digits++;
	}
	return digits == 32 ? 0 : -1;
}

static double cs_now_ms(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec * 1e3 + tv.tv_usec / 1e3;
}

static int cs_threads(void)
{
	const char *e = getenv("CUDA_CS_THREADS");
	int n = e ? atoi(e) : 0;
	/* Copies into the custom-storage mapping slow down with many concurrent streams, so default
	 * to a few threads; more threads only help when the storage is the bottleneck. */
	if (n <= 0)
		n = 4;
	if (n > CS_MAXTHR)
		n = CS_MAXTHR;
	return n;
}

/*
 * One region's transfer, shared by all its workers. Only next (the next chunk
 * to take) and err change while they run, hence the atomics; the rest is set
 * before the workers start.
 */
struct cs_xfer {
	int fd;
	off_t file_off;
	CUdeviceptr dptr;
	size_t size;
	CUcontext ctx;
	bool restore, direct;
	size_t nchunks;
	atomic_size_t next;
	atomic_int err;
};

struct cs_warg {
	struct cs_xfer *xfer;
	int id;
	void **buf; /* its two pinned buffers */
};

/* Pinned buffers of the workers, allocated once for all the regions of a transfer. */
struct cs_pool {
	void *buf[CS_MAXTHR][2];
};

static int cs_pool_grow(struct cs_pool *pool, int n)
{
	CUresult res;
	int i, b;

	for (i = 0; i < n; i++) {
		for (b = 0; b < 2; b++) {
			if (pool->buf[i][b])
				continue;
			res = cs.mem_host_alloc(&pool->buf[i][b], CS_CHUNK, 1 /* CU_MEMHOSTALLOC_PORTABLE */);
			if (res != CUDA_SUCCESS) {
				pool->buf[i][b] = NULL;
				pr_err("cuMemHostAlloc: %s\n", cs_err(res));
				return -1;
			}
		}
	}
	return 0;
}

static void cs_pool_free(struct cs_pool *pool)
{
	int i, b;

	for (i = 0; i < CS_MAXTHR; i++)
		for (b = 0; b < 2; b++)
			if (pool->buf[i][b])
				cs.mem_free_host(pool->buf[i][b]);
	memset(pool, 0, sizeof(*pool));
}

/* A failed copy may only be reported by a later synchronisation: check every call. */
#define CS_CALL(call, name)                                                         \
	do {                                                                        \
		CUresult cu_res = (call);                                           \
		if (cu_res != CUDA_SUCCESS) {                                       \
			pr_err("[w%d] %s: %s\n", worker->id, name, cs_err(cu_res)); \
			goto fail;                                                  \
		}                                                                   \
	} while (0)

static size_t cs_align(size_t n)
{
	return (n + 4095) & ~4095UL;
}

/* Wait for the copy of a chunk into buf, then store it. */
static int cs_store(struct cs_warg *worker, void *buf, CUevent event, size_t off, size_t len)
{
	struct cs_xfer *xfer = worker->xfer;
	size_t iolen = xfer->direct ? cs_align(len) : len;
	ssize_t done;

	/* Wait for the DtoH copy into buf to complete. */
	CS_CALL(cs.event_synchronize(event), "cuEventSynchronize");

	/*
	 * The O_DIRECT tail of the last chunk would hold the previous chunk's
	 * bytes. Costs nothing: iolen - len is non-zero only for the last chunk
	 * of each GPU region.
	 */
	memset((char *)buf + len, 0, iolen - len);
	if ((done = pwrite(xfer->fd, buf, iolen, xfer->file_off + off)) != (ssize_t)iolen) {
		if (done < 0)
			pr_perror("[w%d] pwrite", worker->id);
		else
			pr_err("[w%d] short write: %zd of %zu bytes\n", worker->id, done, iolen);
		goto fail;
	}
	return 0;
fail:
	return -1;
}

/*
 * Used in both directions. Each worker alternates between its two buffers:
 * while one is in an asynchronous GPU copy (DtoH on dump, HtoD on restore),
 * the other is written to (dump) or read from (restore) the image.
 */
static void *cs_worker(void *p)
{
	struct cs_warg *worker = p;
	struct cs_xfer *xfer = worker->xfer;
	void **buf = worker->buf;
	CUevent events[2] = { NULL, NULL };
	CUstream stream = NULL;
	size_t prev_off = 0, prev_len = 0;
	bool pending = false;
	ssize_t done;
	int handled_idx = 0, other_idx, i;

	CS_CALL(cs.ctx_set_current(xfer->ctx), "cuCtxSetCurrent");
	CS_CALL(cs.stream_create(&stream, 1 /* CU_STREAM_NON_BLOCKING */), "cuStreamCreate");
	for (i = 0; i < 2; i++) {
		CS_CALL(cs.event_create(&events[i], 2 /* CU_EVENT_DISABLE_TIMING */), "cuEventCreate");
	}

	for (;; handled_idx ^= 1) {
		size_t chunk = atomic_fetch_add(&xfer->next, 1), off, len, iolen;

		other_idx = handled_idx ^ 1;
		if (chunk >= xfer->nchunks || atomic_load(&xfer->err))
			break;
		off = chunk * CS_CHUNK;
		len = xfer->size - off < CS_CHUNK ? xfer->size - off : CS_CHUNK;
		iolen = xfer->direct ? cs_align(len) : len;
		if (!xfer->restore) {
			/* Dump: copy this chunk from the GPU while the previous one, in the other buffer, is stored. */
			CS_CALL(cs.memcpy_dtoh_async(buf[handled_idx], xfer->dptr + off, len, stream), "cuMemcpyDtoHAsync");
			CS_CALL(cs.event_record(events[handled_idx], stream), "cuEventRecord");
			/* pending is false only for the very first chunk. */
			if (pending && cs_store(worker, buf[other_idx], events[other_idx], prev_off, prev_len))
				goto fail;
			pending = true;
			prev_off = off;
			prev_len = len;
		} else {
			/* Restore: wait for this buffer's previous HtoD copy before overwriting it (no-op the first time). */
			CS_CALL(cs.event_synchronize(events[handled_idx]), "cuEventSynchronize");
			if ((done = pread(xfer->fd, buf[handled_idx], iolen, xfer->file_off + off)) < (ssize_t)len) {
				if (done < 0)
					pr_perror("[w%d] pread", worker->id);
				else
					pr_err("[w%d] short read: %zd of %zu bytes, the image is truncated\n", worker->id, done,
					       len);
				goto fail;
			}
			CS_CALL(cs.memcpy_htod_async(xfer->dptr + off, buf[handled_idx], len, stream), "cuMemcpyHtoDAsync");
			CS_CALL(cs.event_record(events[handled_idx], stream), "cuEventRecord");
		}
	}
	/*
	 * The loop toggled handled_idx after the last chunk, and the iteration
	 * that broke out recomputed other_idx from it: other_idx holds the last
	 * chunk.
	 */
	if (pending && cs_store(worker, buf[other_idx], events[other_idx], prev_off, prev_len))
		goto fail;
	CS_CALL(cs.stream_synchronize(stream), "cuStreamSynchronize");
	goto out;
fail:
	atomic_store(&xfer->err, 1);
out:
	if (stream) {
		cs.stream_synchronize(stream);
		cs.stream_destroy(stream);
	}
	for (i = 0; i < 2; i++)
		if (events[i])
			cs.event_destroy(events[i]);
	return NULL;
}
#undef CS_CALL

/* Make the context of a mapped region current; the mapped pointer has none, its stream does. */
static int cs_region_ctx(CUcheckpointCustomStoragePerDeviceData *mapping, CUcontext *ctx)
{
	void *green = NULL;
	CUresult res;

	*ctx = NULL;
	if ((res = cs.stream_get_ctx(mapping->stream, ctx, &green)) != CUDA_SUCCESS) {
		pr_err("Unable to get the mapping's context: %s\n", cs_err(res));
		return -1;
	}
	if (!*ctx) {
		pr_err("The mapping's stream has no regular context (green context %p)\n", green);
		return -1;
	}
	if ((res = cs.ctx_set_current(*ctx)) != CUDA_SUCCESS) {
		pr_err("Unable to set the mapping's context: %s\n", cs_err(res));
		return -1;
	}
	return 0;
}

/* UUID of the GPU a mapped region is on. */
static int cs_region_uuid(CUcheckpointCustomStoragePerDeviceData *mapping, unsigned char uuid[16])
{
	CUcontext ctx;
	CUdevice dev;
	CUresult res;

	if (cs_region_ctx(mapping, &ctx))
		return -1;
	if ((res = cs.ctx_get_device(&dev)) != CUDA_SUCCESS || (res = cs.device_get_uuid(uuid, dev)) != CUDA_SUCCESS) {
		pr_err("Unable to get the GPU of a mapped region: %s\n", cs_err(res));
		return -1;
	}
	return 0;
}

static const char *cs_uuid_str(const unsigned char uuid[16], char buf[33])
{
	int i;

	for (i = 0; i < 16; i++)
		sprintf(buf + 2 * i, "%02x", uuid[i]);
	return buf;
}

/*
 * The driver gives no order for the regions it maps, and a restore can move
 * the task to other GPUs. Give each mapped region, on GPU cur[j], the
 * checkpointed region of the GPU it comes from: the one the device map (pairs,
 * old to new UUID) gives, or the same GPU. Without a map, the driver also
 * restores a task onto another GPU on its own, e.g. a container given another
 * GPU: a single region left on each side can only go together. Fail on
 * anything else rather than give a GPU the memory of another one.
 */
static int cs_assign(const unsigned char (*cur)[16], const unsigned char (*old)[16], unsigned int n,
		     const CUcheckpointGpuPair *pairs, unsigned int npairs, int *src)
{
	bool used[CUDA_CS_MAXDEV] = {};
	int left_cur = -1, left_old = -1;
	unsigned int i, j, nleft = 0;
	char a[33], b[33];

	for (j = 0; j < n; j++) {
		const unsigned char *want = cur[j];

		for (i = 0; i < npairs; i++) {
			if (!memcmp(pairs[i].newUuid, cur[j], 16)) {
				want = pairs[i].oldUuid;
				break;
			}
		}
		src[j] = -1;
		for (i = 0; i < n; i++) {
			if (memcmp(old[i], want, 16))
				continue;
			if (used[i]) {
				pr_err("GPU %s was checkpointed once but is restored twice\n", cs_uuid_str(want, a));
				return -1;
			}
			used[i] = true;
			src[j] = i;
			break;
		}
		if (src[j] < 0) {
			left_cur = j;
			nleft++;
		}
	}
	if (!nleft)
		return 0;
	for (i = 0; i < n; i++)
		if (!used[i])
			left_old = i;
	if (nleft == 1 && !npairs) {
		pr_info("GPU %s takes the memory checkpointed on GPU %s\n", cs_uuid_str(cur[left_cur], a),
			cs_uuid_str(old[left_old], b));
		src[left_cur] = left_old;
		return 0;
	}
	for (j = 0; j < n; j++)
		if (src[j] < 0)
			pr_err("No checkpointed GPU memory for GPU %s\n", cs_uuid_str(cur[j], a));
	if (!npairs)
		pr_err("%u GPUs changed since the checkpoint: restoring them needs cuda_plugin.device-map\n", nleft);
	return -1;
}

static int cs_xfer_region(int fd, off_t file_off, CUcheckpointCustomStoragePerDeviceData *mapping, bool restore, bool direct,
			  struct cs_pool *pool)
{
	struct cs_xfer xfer;
	struct cs_warg wa[CS_MAXTHR];
	pthread_t th[CS_MAXTHR];
	CUcontext ctx = NULL;
	CUresult res;
	double t0;
	int nthreads, i;

	if (cs_region_ctx(mapping, &ctx))
		return -1;
	/*
	 * The workers copy on streams of their own, which do not wait for other
	 * streams: wait for any work the driver queued on the mapping's stream.
	 */
	if ((res = cs.stream_synchronize(mapping->stream)) != CUDA_SUCCESS) {
		pr_err("cuStreamSynchronize on the mapping's stream: %s\n", cs_err(res));
		return -1;
	}
	memset(&xfer, 0, sizeof(xfer));
	xfer.fd = fd;
	xfer.file_off = file_off;
	xfer.dptr = mapping->devPtr;
	xfer.size = mapping->size;
	xfer.ctx = ctx;
	xfer.restore = restore;
	xfer.direct = direct;
	xfer.nchunks = (mapping->size + CS_CHUNK - 1) / CS_CHUNK;
	atomic_init(&xfer.next, 0);
	atomic_init(&xfer.err, 0);

	nthreads = cs_threads();
	if ((size_t)nthreads > xfer.nchunks)
		nthreads = (int)xfer.nchunks;
	if (cs_pool_grow(pool, nthreads))
		return -1;
	t0 = cs_now_ms();
	for (i = 0; i < nthreads; i++) {
		wa[i].xfer = &xfer;
		wa[i].id = i;
		wa[i].buf = pool->buf[i];
		errno = pthread_create(&th[i], NULL, cs_worker, &wa[i]);
		if (errno) {
			pr_perror("pthread_create");
			atomic_store(&xfer.err, 1);
			nthreads = i;
			break;
		}
	}
	for (i = 0; i < nthreads; i++)
		pthread_join(th[i], NULL);

	pr_info("[timing] custom-storage %s: %.2f GB, %d threads, %.0f ms (%.1f GB/s, %s)\n",
		restore ? "restore copy" : "checkpoint copy", mapping->size / 1e9, nthreads, cs_now_ms() - t0,
		mapping->size / (cs_now_ms() - t0) / 1e6, direct ? "O_DIRECT" : "buffered");
	return atomic_load(&xfer.err) ? -1 : 0;
}

/* Lay the regions out after the header and write it. */
static int cs_write_header(int fd, void *hdr_buf, CUcheckpointCustomStorageInfo *info, CudaCsRegion *regions,
			   unsigned char (*uuids)[16], const char *fname)
{
	CudaCsRegion *rp[CUDA_CS_MAXDEV];
	CudaCsImage img = CUDA_CS_IMAGE__INIT;
	uint32_t len32;
	size_t len;
	off_t off = CS_HDR;
	unsigned int i;

	for (i = 0; i < info->deviceCount; i++) {
		cuda_cs_region__init(&regions[i]);
		regions[i].has_size = regions[i].has_offset = true;
		regions[i].size = info->perDeviceData[i].size;
		regions[i].offset = off;
		regions[i].has_uuid = true;
		regions[i].uuid.len = 16;
		regions[i].uuid.data = uuids[i];
		off += cs_align(regions[i].size);
		rp[i] = &regions[i];
	}
	img.has_version = true;
	img.version = CS_IMAGE_VERSION;
	img.n_regions = info->deviceCount;
	img.regions = rp;
	len = cuda_cs_image__get_packed_size(&img);
	if (len > CS_HDR - 8) {
		pr_err("%s: header of %zu bytes does not fit\n", fname, len);
		return -1;
	}
	len32 = htole32(len);
	memcpy(hdr_buf, CS_MAGIC, 4);
	memcpy((char *)hdr_buf + 4, &len32, 4);
	cuda_cs_image__pack(&img, (uint8_t *)hdr_buf + 8);

	if (pwrite(fd, hdr_buf, CS_HDR, 0) != CS_HDR) {
		pr_perror("Unable to write %s header", fname);
		return -1;
	}
	return 0;
}

static CudaCsImage *cs_read_header(int fd, void *hdr_buf, const char *fname)
{
	CudaCsImage *img;
	uint32_t len;
	unsigned int i;
	ssize_t n;

	n = pread(fd, hdr_buf, CS_HDR, 0);
	if (n != CS_HDR) {
		if (n < 0)
			pr_perror("Unable to read %s header", fname);
		else
			pr_err("%s: truncated header\n", fname);
		return NULL;
	}
	memcpy(&len, (char *)hdr_buf + 4, 4);
	len = le32toh(len);
	if (memcmp(hdr_buf, CS_MAGIC, 4) || len > CS_HDR - 8) {
		pr_err("%s is not a custom-storage image\n", fname);
		return NULL;
	}
	img = cuda_cs_image__unpack(NULL, len, (uint8_t *)hdr_buf + 8);
	if (!img) {
		pr_err("Unable to unpack the %s header\n", fname);
		return NULL;
	}
	if (img->version != CS_IMAGE_VERSION) {
		pr_err("%s: unsupported version %u\n", fname, img->version);
		goto err;
	}
	if (img->n_regions > CUDA_CS_MAXDEV) {
		pr_err("%s: %zu regions, at most %d are supported\n", fname, img->n_regions, CUDA_CS_MAXDEV);
		goto err;
	}
	for (i = 0; i < img->n_regions; i++) {
		if (!img->regions[i]->has_size || !img->regions[i]->has_offset || !img->regions[i]->has_uuid ||
		    img->regions[i]->uuid.len != 16 || img->regions[i]->offset % 4096 ||
		    img->regions[i]->offset < CS_HDR) {
			pr_err("%s: invalid region %u\n", fname, i);
			goto err;
		}
	}
	return img;
err:
	cuda_cs_image__free_unpacked(img, NULL);
	return NULL;
}

int cuda_cs_transfer(int pid, CUcheckpointCustomStorageInfo *info, int img_dir_fd, bool restore,
		     const CUcheckpointGpuPair *pairs, unsigned int npairs)
{
	char fname[64];
	int fd, flags = restore ? O_RDONLY : (O_WRONLY | O_CREAT | O_TRUNC);
	bool direct = true;
	CudaCsRegion regions[CUDA_CS_MAXDEV];
	unsigned char uuids[CUDA_CS_MAXDEV][16], old[CUDA_CS_MAXDEV][16];
	int src[CUDA_CS_MAXDEV];
	struct cs_pool pool = {};
	CudaCsImage *img = NULL;
	void *hdr_buf = NULL;
	unsigned int i;
	int ret = -1;

	if (!info) {
		pr_err("No custom storage info for pid %d\n", pid);
		return -1;
	}
	if (info->deviceCount > CUDA_CS_MAXDEV) {
		pr_err("pid %d uses %u GPUs, at most %d are supported\n", pid, info->deviceCount, CUDA_CS_MAXDEV);
		return -1;
	}
	if (img_dir_fd < 0) {
		pr_err("No image directory for the custom-storage image of pid %d\n", pid);
		return -1;
	}
	if (cs_image_name(pid, fname, sizeof(fname)))
		return -1;
	fd = openat(img_dir_fd, fname, flags | O_DIRECT, 0600);
	if (fd < 0 && errno == EINVAL) {
		direct = false;
		fd = openat(img_dir_fd, fname, flags, 0600);
	}
	if (fd < 0) {
		pr_perror("Unable to open %s", fname);
		return -1;
	}
	if (posix_memalign(&hdr_buf, 4096, CS_HDR))
		goto out;
	memset(hdr_buf, 0, CS_HDR);
	for (i = 0; i < info->deviceCount; i++)
		if (cs_region_uuid(&info->perDeviceData[i], uuids[i]))
			goto out;

	if (!restore) {
		if (cs_write_header(fd, hdr_buf, info, regions, uuids, fname))
			goto out;
	} else {
		img = cs_read_header(fd, hdr_buf, fname);
		if (!img)
			goto out;
		if (img->n_regions != info->deviceCount) {
			pr_err("%s holds %zu devices, the driver maps %u\n", fname, img->n_regions, info->deviceCount);
			goto out;
		}
		for (i = 0; i < img->n_regions; i++)
			memcpy(old[i], img->regions[i]->uuid.data, 16);
		if (cs_assign(uuids, old, info->deviceCount, pairs, npairs, src))
			goto out;
	}

	for (i = 0; i < info->deviceCount; i++) {
		CUcheckpointCustomStoragePerDeviceData *mapping = &info->perDeviceData[i];
		CudaCsRegion *region = restore ? img->regions[src[i]] : &regions[i];

		if (mapping->size != region->size) {
			pr_err("%s: device %u size mismatch (image %llu, driver %zu)\n", fname, i,
			       (unsigned long long)region->size, mapping->size);
			goto out;
		}
		if (cs_xfer_region(fd, region->offset, mapping, restore, direct, &pool))
			goto out;
	}
	/* O_DIRECT bypasses the page cache, not the device's write cache. */
	if (!restore && fdatasync(fd)) {
		pr_perror("Unable to sync %s", fname);
		goto out;
	}
	ret = 0;
out:
	cs_pool_free(&pool);
	if (img)
		cuda_cs_image__free_unpacked(img, NULL);
	free(hdr_buf);
	close(fd);
	return ret;
}

/* The devices whose primary context CRIU retains, released by cuda_cs_fini(). */
static CUdevice cs_retained[CS_MAXGPU];
static int cs_nr_retained;

/* The GPUs CRIU sees, with their UUIDs. */
static int cs_visible_gpus(CUdevice *devs, unsigned char (*uuids)[16], int *nvis)
{
	CUresult res;
	int i;

	if ((res = cs.device_get_count(nvis)) != CUDA_SUCCESS) {
		pr_err("cuDeviceGetCount: %s\n", cs_err(res));
		return -1;
	}
	if (*nvis > CS_MAXGPU) {
		pr_err("%d GPUs, at most %d are supported\n", *nvis, CS_MAXGPU);
		return -1;
	}
	for (i = 0; i < *nvis; i++) {
		if ((res = cs.device_get(&devs[i], i)) != CUDA_SUCCESS ||
		    (res = cs.device_get_uuid(uuids[i], devs[i])) != CUDA_SUCCESS) {
			pr_err("Unable to get GPU %d: %s\n", i, cs_err(res));
			return -1;
		}
	}
	return 0;
}

static int cs_find_uuid(const unsigned char (*uuids)[16], int n, const unsigned char uuid[16])
{
	int i;

	for (i = 0; i < n; i++)
		if (!memcmp(uuids[i], uuid, 16))
			return i;
	return -1;
}

int cuda_cs_retain(const unsigned char (*gpus)[16], unsigned int n)
{
	unsigned char uuids[CS_MAXGPU][16];
	CUdevice devs[CS_MAXGPU];
	unsigned int i;
	char buf[33];
	int nvis, j, k;
	CUcontext c;
	CUresult res;

	if (cs_visible_gpus(devs, uuids, &nvis))
		return -1;
	for (i = 0; i < n; i++) {
		j = cs_find_uuid(uuids, nvis, gpus[i]);
		if (j < 0) {
			pr_err("GPU %s is not visible to CRIU\n", cs_uuid_str(gpus[i], buf));
			return -1;
		}
		for (k = 0; k < cs_nr_retained; k++)
			if (cs_retained[k] == devs[j])
				break;
		if (k < cs_nr_retained)
			continue;
		if ((res = cs.primary_ctx_retain(&c, devs[j])) != CUDA_SUCCESS) {
			pr_err("Unable to retain the primary context of GPU %s: %s\n", cs_uuid_str(gpus[i], buf),
			       cs_err(res));
			return -1;
		}
		cs_retained[cs_nr_retained++] = devs[j];
		pr_info("Retained the primary context of GPU %s\n", cs_uuid_str(gpus[i], buf));
	}
	return 0;
}

void cuda_cs_fini(void)
{
	/* A primary context holds GPU memory that the restored tasks may need. */
	while (cs_nr_retained)
		cs.primary_ctx_release(cs_retained[--cs_nr_retained]);
}

/*
 * NVML, loaded only to find the GPUs of a task: it lists the processes with
 * memory on each GPU without creating a context on any.
 */
typedef void *nvmlDevice_t;
typedef struct {
	unsigned int pid;
	unsigned long long usedGpuMemory;
	unsigned int gpuInstanceId;
	unsigned int computeInstanceId;
} nvmlProcessInfo_t;

/* The inode of the init pid namespace, fixed by the kernel (PROC_PID_INIT_INO). */
#define CS_PID_INIT_INO 0xEFFFFFFCU

static bool cs_in_init_pidns(void)
{
	struct stat st;

	return !stat("/proc/self/ns/pid", &st) && st.st_ino == CS_PID_INIT_INO;
}

#define NVML_SUCCESS		     0
#define NVML_ERROR_INSUFFICIENT_SIZE 7

int cuda_cs_task_gpus(int pid, unsigned char (*gpus)[16], unsigned int *n)
{
	int (*init)(void), (*shutdown)(void), (*get_count)(unsigned int *);
	int (*get_handle)(unsigned int, nvmlDevice_t *), (*get_uuid)(nvmlDevice_t, char *, unsigned int);
	int (*get_procs)(nvmlDevice_t, unsigned int *, nvmlProcessInfo_t *);
	nvmlProcessInfo_t *procs = NULL;
	unsigned int count, i, j, nprocs;
	char text[96];
	void *h;
	int res, ret = -1;

	*n = 0;
	/* NVML reports init pid namespace pids: from another one, pid could match another task. */
	if (!cs_in_init_pidns()) {
		pr_warn("CRIU is not in the init pid namespace: NVML cannot find the GPUs of pid %d\n", pid);
		return -1;
	}
	h = dlopen("libnvidia-ml.so.1", RTLD_NOW | RTLD_LOCAL);
	if (!h) {
		pr_warn("Unable to load NVML to find the GPUs of pid %d: %s\n", pid, dlerror());
		return -1;
	}
	init = dlsym(h, "nvmlInit_v2");
	shutdown = dlsym(h, "nvmlShutdown");
	get_count = dlsym(h, "nvmlDeviceGetCount_v2");
	get_handle = dlsym(h, "nvmlDeviceGetHandleByIndex_v2");
	get_uuid = dlsym(h, "nvmlDeviceGetUUID");
	get_procs = dlsym(h, "nvmlDeviceGetComputeRunningProcesses_v3");
	if (!init || !shutdown || !get_count || !get_handle || !get_uuid || !get_procs) {
		pr_warn("NVML lacks the functions to find the GPUs of pid %d\n", pid);
		goto close;
	}
	if ((res = init()) != NVML_SUCCESS) {
		pr_warn("nvmlInit failed: %d\n", res);
		goto close;
	}
	if ((res = get_count(&count)) != NVML_SUCCESS) {
		pr_warn("nvmlDeviceGetCount failed: %d\n", res);
		goto shutdown;
	}
	/*
	 * MIG is not handled: the processes of a MIG instance are listed on its
	 * own device handle, and the context to retain is the instance's.
	 */
	for (i = 0; i < count; i++) {
		nvmlDevice_t dev;

		if ((res = get_handle(i, &dev)) != NVML_SUCCESS) {
			pr_warn("nvmlDeviceGetHandleByIndex(%u) failed: %d\n", i, res);
			goto shutdown;
		}
		nprocs = 0;
		res = get_procs(dev, &nprocs, NULL);
		while (res == NVML_ERROR_INSUFFICIENT_SIZE) {
			free(procs);
			nprocs += 8; /* processes may start in between */
			procs = calloc(nprocs, sizeof(*procs));
			if (!procs)
				goto shutdown;
			res = get_procs(dev, &nprocs, procs);
		}
		if (res != NVML_SUCCESS) {
			pr_warn("nvmlDeviceGetComputeRunningProcesses(%u) failed: %d\n", i, res);
			goto shutdown;
		}
		for (j = 0; j < nprocs && procs; j++)
			if (procs[j].pid == (unsigned int)pid)
				break;
		if (!procs || j == nprocs)
			continue;
		if (*n == CUDA_CS_MAXDEV) {
			pr_warn("pid %d uses more than %d GPUs\n", pid, CUDA_CS_MAXDEV);
			goto shutdown;
		}
		if ((res = get_uuid(dev, text, sizeof(text))) != NVML_SUCCESS || cs_parse_uuid(text, gpus[*n])) {
			pr_warn("Unable to get the UUID of GPU %u: %d\n", i, res);
			goto shutdown;
		}
		(*n)++;
	}
	ret = 0;
shutdown:
	shutdown();
close:
	free(procs);
	dlclose(h);
	return ret;
}

int cuda_cs_restore_gpus(int pid, int img_dir_fd, const CUcheckpointGpuPair *pairs, unsigned int npairs,
			 unsigned char (*gpus)[16], unsigned int *n)
{
	unsigned char uuids[CS_MAXGPU][16];
	CUdevice devs[CS_MAXGPU];
	CudaCsImage *img = NULL;
	int nvis, left = -1, extra = -1, nleft = 0, nextra = 0;
	char fname[64], a[33], b[33];
	unsigned int i, k;
	void *hdr_buf = NULL;
	int fd, j, ret = -1;

	*n = 0;
	if (cs_visible_gpus(devs, uuids, &nvis) || cs_image_name(pid, fname, sizeof(fname)))
		return -1;
	fd = openat(img_dir_fd, fname, O_RDONLY);
	if (fd < 0) {
		pr_perror("Unable to open %s", fname);
		return -1;
	}
	if (posix_memalign(&hdr_buf, 4096, CS_HDR))
		goto out;
	img = cs_read_header(fd, hdr_buf, fname);
	if (!img)
		goto out;

	/* The same choice as cs_assign() makes once the driver mapped the memory. */
	for (i = 0; i < img->n_regions; i++) {
		const unsigned char *old = img->regions[i]->uuid.data;
		const unsigned char *dst = old;

		for (k = 0; k < npairs; k++) {
			if (!memcmp(pairs[k].oldUuid, old, 16)) {
				dst = pairs[k].newUuid;
				break;
			}
		}
		if (!npairs && cs_find_uuid(uuids, nvis, old) < 0) {
			left = i;
			nleft++;
			continue;
		}
		memcpy(gpus[(*n)++], dst, 16);
	}
	if (nleft) {
		/* Without a map, a single GPU that changed: the single GPU CRIU sees and the task did not use. */
		for (j = 0; j < nvis; j++) {
			for (i = 0; i < img->n_regions; i++)
				if (!memcmp(img->regions[i]->uuid.data, uuids[j], 16))
					break;
			if (i == img->n_regions) {
				extra = j;
				nextra++;
			}
		}
		if (nleft > 1 || nextra != 1) {
			pr_err("%d GPUs changed since the checkpoint and CRIU sees %d other GPUs: restoring them needs cuda_plugin.device-map\n",
			       nleft, nextra);
			goto out;
		}
		pr_info("GPU %s, not visible, is restored onto GPU %s\n",
			cs_uuid_str(img->regions[left]->uuid.data, a), cs_uuid_str(uuids[extra], b));
		memcpy(gpus[(*n)++], uuids[extra], 16);
	}
	ret = 0;
out:
	if (img)
		cuda_cs_image__free_unpacked(img, NULL);
	free(hdr_buf);
	close(fd);
	return ret;
}
