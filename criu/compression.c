#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <lz4.h>

#include "page.h"
#include "log.h"
#include "common/bug.h"
#include "compression.h"
#include "common/xmalloc.h"

#undef LOG_PREFIX
#define LOG_PREFIX "compression: "

#define PARALLEL_DECOMPRESS_MIN_BYTES_PER_THREAD (512UL << 10)
#define PARALLEL_DECOMPRESS_STACK_SIZE (256UL << 10)
#define PARALLEL_DECOMPRESS_MAX_JOB_CHUNK 8
#define PARALLEL_DECOMPRESS_MAX_BATCHES 2

/*
 * asyncd can restore several shmem or memfd objects concurrently.  Each of
 * those requests may enter decompress_jobs_parallel_pool(), so limiting one
 * invocation to the available CPUs is not sufficient: independent calls can
 * otherwise multiply the worker count. Account for the calling thread as
 * well as workers. Restore processes use one budget in shared restore memory;
 * callers outside restore fall back to a process-wide budget.
 */
static pthread_once_t decompress_budget_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t decompress_budget_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t decompress_budget_cond = PTHREAD_COND_INITIALIZER;
static unsigned int decompress_budget_available = 1;
static unsigned int decompress_budget_capacity_cached = 1;
static pthread_mutex_t decompress_batch_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t decompress_batch_cond = PTHREAD_COND_INITIALIZER;
static unsigned int decompress_batches_available = PARALLEL_DECOMPRESS_MAX_BATCHES;
static struct decompression_shared_budget *decompress_shared_budget;

static unsigned int decompression_available_cpus(void)
{
	cpu_set_t *affinity;
	size_t affinity_size;
	size_t nr_cpus = CPU_SETSIZE;
	long available_cpus;
	int affinity_errno;

	available_cpus = sysconf(_SC_NPROCESSORS_CONF);
	if (available_cpus > (long)nr_cpus)
		nr_cpus = (size_t)available_cpus;

	for (;;) {
		affinity = CPU_ALLOC(nr_cpus);
		if (!affinity) {
			pr_warn("Unable to allocate a CPU affinity mask, using serial decompression\n");
			return 1;
		}
		affinity_size = CPU_ALLOC_SIZE(nr_cpus);
		CPU_ZERO_S(affinity_size, affinity);
		if (sched_getaffinity(0, affinity_size, affinity) == 0) {
			available_cpus = CPU_COUNT_S(affinity_size, affinity);
			CPU_FREE(affinity);
			goto found;
		}
		affinity_errno = errno;
		CPU_FREE(affinity);
		if (affinity_errno != EINVAL) {
			pr_warn("Unable to read the CPU affinity mask: %s; using serial decompression\n",
				strerror(affinity_errno));
			return 1;
		}
		if (nr_cpus > UINT_MAX / 2) {
			pr_warn("CPU affinity mask is too large, using serial decompression\n");
			return 1;
		}
		nr_cpus *= 2;
	}
found:
	if (available_cpus < 1)
		return 1;
	return (unsigned int)available_cpus;
}

unsigned int decompression_thread_limit(unsigned int requested, unsigned int available_cpus)
{
	if (!available_cpus)
		available_cpus = 1;
	if (!requested)
		return available_cpus;
	return min(requested, available_cpus);
}

static unsigned int decompression_cpu_limit(unsigned int requested)
{
	return decompression_thread_limit(requested, decompression_available_cpus());
}

/*
 * Automatic (0) and serial (1) settings must not serialize independent asyncd
 * jobs: both leave the restore-wide budget at the available-CPU capacity, and a
 * serial setting still limits each worker-pool call to its caller. Explicit
 * parallel settings cap all callers to the requested number of CPUs.
 */
static unsigned int decompression_budget_capacity(unsigned int configured_threads)
{
	if (configured_threads < 2)
		return decompression_cpu_limit(0);

	return decompression_cpu_limit(configured_threads);
}

static void decompress_budget_init(void)
{
	decompress_budget_capacity_cached = decompression_cpu_limit(0);
	decompress_budget_available = decompress_budget_capacity_cached;
}

void decompression_shared_budget_init(struct decompression_shared_budget *budget, unsigned int requested_threads)
{
	unsigned int threads = decompression_budget_capacity(requested_threads);

	/* Reduce an explicit request that exceeds the CPUs available to CRIU. */
	if (requested_threads > threads)
		pr_warn("Reducing compressed-page worker concurrency from %u to %u (available CPUs)\n",
			requested_threads, threads);

	futex_set(&budget->threads, threads);
	budget->thread_capacity = threads;
	/*
	 * Batch leases bound active encoded working sets independently of the CPU
	 * budget. Keep at most two 32 MiB input buffers so one local reader can
	 * overlap its next read with decoding without retaining unbounded memory.
	 */
	futex_set(&budget->batches, PARALLEL_DECOMPRESS_MAX_BATCHES);
}

void decompression_use_shared_budget(struct decompression_shared_budget *budget)
{
	/* Borrowed from shared restore memory and valid for the restore lifetime. */
	decompress_shared_budget = budget;
}

bool compressed_restore_has_parallel_capacity(unsigned int requested_threads)
{
	unsigned int capacity;
	int err;

	if (requested_threads == 1)
		return false;
	if (decompress_shared_budget)
		capacity = decompress_shared_budget->thread_capacity;
	else {
		err = pthread_once(&decompress_budget_once, decompress_budget_init);
		if (err)
			return false;
		capacity = decompress_budget_capacity_cached;
	}

	return decompression_thread_limit(requested_threads, capacity) > 1;
}

static unsigned int shared_budget_acquire(futex_t *available, unsigned int requested)
{
	for (;;) {
		unsigned int current = futex_get(available);
		unsigned int granted;
		unsigned int previous;

		if (!current) {
			futex_wait_while_eq(available, 0);
			continue;
		}
		granted = min(requested, current);
		previous = atomic_cmpxchg(&available->raw, current, current - granted);
		if (previous == current)
			return granted;
	}
}

static bool shared_budget_try_acquire(futex_t *available)
{
	unsigned int current = futex_get(available);

	while (current) {
		unsigned int previous;

		previous = atomic_cmpxchg(&available->raw, current, current - 1);
		if (previous == current)
			return true;
		current = previous;
	}

	return false;
}

static void shared_budget_release(futex_t *available, unsigned int amount)
{
	atomic_add(amount, &available->raw);
	futex_wake(available);
}

static unsigned int decompress_budget_acquire(unsigned int requested)
{
	unsigned int granted;
	int err;

	if (decompress_shared_budget)
		return shared_budget_acquire(&decompress_shared_budget->threads, requested);

	err = pthread_once(&decompress_budget_once, decompress_budget_init);
	if (err) {
		pr_warn("Unable to initialize decompression CPU budget: %s\n", strerror(err));
		return 0;
	}

	err = pthread_mutex_lock(&decompress_budget_lock);
	if (err) {
		pr_warn("Unable to lock decompression CPU budget: %s\n", strerror(err));
		return 0;
	}

	while (!decompress_budget_available) {
		err = pthread_cond_wait(&decompress_budget_cond, &decompress_budget_lock);
		if (err) {
			pr_warn("Unable to wait for decompression CPU budget: %s\n", strerror(err));
			pthread_mutex_unlock(&decompress_budget_lock);
			return 0;
		}
	}

	granted = min(requested, decompress_budget_available);
	decompress_budget_available -= granted;
	pthread_mutex_unlock(&decompress_budget_lock);
	return granted;
}

static void decompress_budget_release(unsigned int nr_threads)
{
	int err;

	if (!nr_threads)
		return;
	if (decompress_shared_budget) {
		shared_budget_release(&decompress_shared_budget->threads, nr_threads);
		return;
	}

	err = pthread_mutex_lock(&decompress_budget_lock);
	if (err) {
		pr_err("Unable to lock decompression CPU budget for release: %s\n", strerror(err));
		BUG();
	}
	decompress_budget_available += nr_threads;
	pthread_cond_broadcast(&decompress_budget_cond);
	pthread_mutex_unlock(&decompress_budget_lock);
}

static void decompress_budget_trim_reservation(unsigned int *threads_held, unsigned int threads_to_keep)
{
	BUG_ON(threads_to_keep > *threads_held);
	decompress_budget_release(*threads_held - threads_to_keep);
	*threads_held = threads_to_keep;
}

void decompression_batch_acquire(void)
{
	int err;

	if (decompress_shared_budget) {
		shared_budget_acquire(&decompress_shared_budget->batches, 1);
		return;
	}
	err = pthread_mutex_lock(&decompress_batch_lock);
	if (err) {
		pr_err("Unable to lock decompression batch budget: %s\n", strerror(err));
		BUG();
	}
	while (!decompress_batches_available) {
		err = pthread_cond_wait(&decompress_batch_cond, &decompress_batch_lock);
		if (err) {
			pr_err("Unable to wait for decompression batch budget: %s\n", strerror(err));
			BUG();
		}
	}
	decompress_batches_available--;
	pthread_mutex_unlock(&decompress_batch_lock);
}

bool decompression_batch_try_acquire(void)
{
	bool acquired = false;
	int err;

	if (decompress_shared_budget)
		return shared_budget_try_acquire(&decompress_shared_budget->batches);

	err = pthread_mutex_lock(&decompress_batch_lock);
	if (err) {
		pr_warn("Unable to lock compressed-page batch budget: %s\n", strerror(err));
		return false;
	}
	if (decompress_batches_available) {
		decompress_batches_available--;
		acquired = true;
	}
	pthread_mutex_unlock(&decompress_batch_lock);

	return acquired;
}

void decompression_batch_release(void)
{
	int err;

	if (decompress_shared_budget) {
		shared_budget_release(&decompress_shared_budget->batches, 1);
		return;
	}
	err = pthread_mutex_lock(&decompress_batch_lock);
	if (err) {
		pr_err("Unable to lock decompression batch budget for release: %s\n", strerror(err));
		BUG();
	}
	decompress_batches_available++;
	pthread_cond_signal(&decompress_batch_cond);
	pthread_mutex_unlock(&decompress_batch_lock);
}

int compress_data(const char *input_data, size_t input_size,
		  char *compressed_data, size_t output_size,
		  int acceleration)
{
	int ret;

	if (!input_data || !compressed_data || !input_size ||
	    input_size > LZ4_MAX_INPUT_SIZE || output_size > INT_MAX) {
		pr_err("Invalid compression buffer sizes: input=%zu output=%zu\n",
		       input_size, output_size);
		return -1;
	}

	if (acceleration < 1)
		acceleration = 1;

	ret = LZ4_compress_fast(input_data, compressed_data, input_size,
				output_size, acceleration);
	if (ret <= 0) {
		pr_err("Failed to compress data: %d\n", ret);
		return -1;
	}

	return ret;
}

static int decompress_data_nolog(const char *compressed_data,
				 int compressed_size, int original_size,
				 char *decompressed_data)
{
	int ret;

	ret = LZ4_decompress_safe(compressed_data, decompressed_data,
				  compressed_size, original_size);
	return ret == original_size ? 0 : -1;
}

int decompress_data(const char *compressed_data, int compressed_size,
		    int original_size, char *decompressed_data)
{
	int ret;

	if (!compressed_data || !decompressed_data || compressed_size <= 0 ||
	    original_size <= 0) {
		pr_err("Invalid decompression buffer sizes: input=%d output=%d\n",
		       compressed_size, original_size);
		return -1;
	}

	ret = LZ4_decompress_safe(compressed_data, decompressed_data,
				  compressed_size, original_size);

	if (ret != original_size) {
		pr_err("Decompression failed: expected %d bytes, got %d\n",
		       original_size, ret);
		return -1;
	}

	return 0;
}

int compress_region(const char *src, unsigned int n_pages, char *dst,
		    size_t dst_cap, int acceleration)
{
	size_t region_bytes;
	unsigned int i;
	int ret;

	if (n_pages == 0 || n_pages > MAX_REGION_PAGES) {
		pr_err("compress_region: invalid n_pages %u\n", n_pages);
		return -1;
	}
	if (!src || !dst) {
		pr_err("compress_region: invalid buffer\n");
		return -1;
	}
	region_bytes = (size_t)n_pages * PAGE_SIZE;

	/* Cheap pre-pass: every page in the region zero-filled? */
	for (i = 0; i < n_pages; i++) {
		if (!page_is_all_zero(src + (size_t)i * PAGE_SIZE))
			break;
	}
	if (i == n_pages)
		return 0;

	if (dst_cap < region_bytes) {
		pr_err("compress_region: dst buffer (%zu) smaller than region (%zu)\n",
		       dst_cap, region_bytes);
		return -1;
	}

	if (acceleration < 1)
		acceleration = 1;

	ret = LZ4_compress_fast(src, dst, region_bytes, dst_cap, acceleration);
	if (ret <= 0 || (size_t)ret >= REGION_COMPRESSION_THRESHOLD(region_bytes)) {
		/*
		 * LZ4 can fail when dst_cap is below LZ4 worst-case bound
		 * (which the caller should size correctly), or when the
		 * compressed size hits the threshold and we'd rather store
		 * raw. Either way, fall back to raw.
		 */
		memcpy(dst, src, region_bytes);
		return region_bytes;
	}

	return ret;
}

int decompress_region(const char *src, int compressed_size,
		      unsigned int n_pages, char *dst)
{
	size_t region_bytes;

	if (n_pages == 0 || n_pages > MAX_REGION_PAGES) {
		pr_err("decompress_region: invalid n_pages %u\n", n_pages);
		return -1;
	}
	if (compressed_size < 0) {
		pr_err("decompress_region: negative compressed_size %d\n",
		       compressed_size);
		return -1;
	}
	if (!dst || (compressed_size && !src)) {
		pr_err("decompress_region: invalid buffer\n");
		return -1;
	}
	region_bytes = (size_t)n_pages * PAGE_SIZE;

	if ((size_t)compressed_size > region_bytes) {
		pr_err("decompress_region: compressed_size %d > region %zu\n",
		       compressed_size, region_bytes);
		return -1;
	}

	if (compressed_size == 0) {
		memset(dst, 0, region_bytes);
		return 0;
	}

	if ((size_t)compressed_size == region_bytes) {
		memcpy(dst, src, region_bytes);
		return 0;
	}

	if (decompress_data_nolog(src, compressed_size, region_bytes, dst)) {
		pr_err("Region decompression failed (compressed_size=%d, n_pages=%u)\n",
		       compressed_size, n_pages);
		return -1;
	}

	return 0;
}

/* Parallel decompression queue and reusable worker pool. */
struct decompress_queue {
	struct decompress_job *jobs;
	size_t nr_jobs;
	size_t job_chunk;
	/*
	 * Concurrent scheduling and result accesses use compiler atomics. Keep all
	 * three fields under that API because next_job needs size_t, while CRIU's
	 * atomic_t is int-sized.
	 */
	size_t next_job;
	int failed;
	int failed_block;
};

struct decompress_worker {
	pthread_t tid;
	struct decompression_pool *pool;
	unsigned int index;
};

/*
 * The lock protects the batch scheduler fields below. decompression_pool_start_batch()
 * publishes the caller-owned jobs as immutable batch metadata. Workers update
 * only the queue's atomic scheduling and result fields.
 * decompression_pool_finish_batch() waits for every selected worker before
 * releasing those jobs.
 */
struct decompression_pool {
	pthread_mutex_t lock;
	pthread_cond_t work_ready;
	pthread_cond_t work_done;
	struct decompress_worker *workers;
	struct decompress_queue queue;
	unsigned int nr_workers;
	unsigned int batch_workers;
	unsigned int pending_batch_workers;
	unsigned long batch_generation;
	bool batch_active;
	bool stop;
};

static int decompress_job_run(const struct decompress_job *job)
{
	size_t block_bytes;

	if (!job->pages || job->pages > MAX_REGION_PAGES)
		return -1;

	block_bytes = (size_t)job->pages * PAGE_SIZE;
	if (!job->compressed_size) {
		memset(job->dst, 0, block_bytes);
		return 0;
	}
	/* Raw blocks are handled inline by the pagemap reader. */
	if (job->compressed_size >= block_bytes)
		return -1;

	return decompress_data_nolog(job->src, job->compressed_size, block_bytes, job->dst);
}

static void decompress_queue_init(struct decompress_queue *queue, struct decompress_job *jobs, size_t nr_jobs,
				  unsigned int nr_threads)
{
	queue->jobs = jobs;
	queue->nr_jobs = nr_jobs;
	queue->job_chunk = nr_jobs / nr_threads / 4;
	if (!queue->job_chunk)
		queue->job_chunk = 1;
	if (queue->job_chunk > PARALLEL_DECOMPRESS_MAX_JOB_CHUNK)
		queue->job_chunk = PARALLEL_DECOMPRESS_MAX_JOB_CHUNK;
	queue->next_job = 0;
	queue->failed = 0;
	queue->failed_block = INT_MAX;
}

static bool decompress_queue_failed(const struct decompress_queue *queue)
{
	return __atomic_load_n(&queue->failed, __ATOMIC_ACQUIRE);
}

static bool decompress_queue_claim_chunk(struct decompress_queue *queue, size_t *first, size_t *end)
{
	if (decompress_queue_failed(queue))
		return false;

	/* This relaxed counter only assigns disjoint chunks; it publishes no data. */
	*first = __atomic_fetch_add(&queue->next_job, queue->job_chunk, __ATOMIC_RELAXED);
	if (*first >= queue->nr_jobs)
		return false;

	*end = *first + queue->job_chunk;
	if (*end > queue->nr_jobs)
		*end = queue->nr_jobs;
	return true;
}

static void decompress_queue_record_failure(struct decompress_queue *queue, int block_index)
{
	int earliest_block = __atomic_load_n(&queue->failed_block, __ATOMIC_RELAXED);

	/* Keep the lowest failing block index when several workers fail. */
	while (block_index < earliest_block) {
		if (__atomic_compare_exchange_n(&queue->failed_block, &earliest_block, block_index, false,
						__ATOMIC_RELAXED, __ATOMIC_RELAXED))
			break;
	}

	/* Publish cancellation only after failed_block has been updated. */
	__atomic_store_n(&queue->failed, 1, __ATOMIC_RELEASE);
}

static void decompress_queue_run(struct decompress_queue *queue)
{
	size_t first, end;

	while (decompress_queue_claim_chunk(queue, &first, &end)) {
		size_t i;

		for (i = first; i < end; i++) {
			struct decompress_job *job = &queue->jobs[i];

			if (!decompress_job_run(job))
				continue;

			decompress_queue_record_failure(queue, job->block_index);
			break;
		}
	}
}

static int decompress_jobs_serial(struct decompress_job *jobs, size_t nr_jobs)
{
	struct decompress_queue queue;

	decompress_queue_init(&queue, jobs, nr_jobs, 1);
	decompress_queue_run(&queue);
	if (!decompress_queue_failed(&queue))
		return 0;

	pr_err("Decompression failed at block %d\n", queue.failed_block);
	return -1;
}

static unsigned int decompress_batch_threads(size_t nr_jobs, size_t total_uncompressed, unsigned int requested_threads)
{
	size_t work_limit;
	unsigned int nr_threads;

	if (total_uncompressed < PARALLEL_RESTORE_MIN_BATCH_BYTES)
		return 1;

	nr_threads = decompression_cpu_limit(requested_threads);
	work_limit = nr_jobs;
	if (work_limit < nr_threads)
		nr_threads = (unsigned int)work_limit;
	work_limit = total_uncompressed / PARALLEL_DECOMPRESS_MIN_BYTES_PER_THREAD;
	if (work_limit < nr_threads)
		nr_threads = (unsigned int)work_limit;
	if (nr_threads < 2)
		return 1;

	return nr_threads;
}

static void decompression_worker_signal_set(sigset_t *set)
{
	/*
	 * CRIU's process-global signal handling belongs to the restore thread.
	 * Worker threads keep asynchronous signals blocked for their lifetime.
	 * Synchronous faults must remain deliverable.
	 */
	sigfillset(set);
	sigdelset(set, SIGABRT);
	sigdelset(set, SIGBUS);
	sigdelset(set, SIGFPE);
	sigdelset(set, SIGILL);
	sigdelset(set, SIGSEGV);
	sigdelset(set, SIGSYS);
	sigdelset(set, SIGTRAP);
}

static void *decompression_pool_worker(void *arg)
{
	struct decompress_worker *worker = arg;
	struct decompression_pool *pool = worker->pool;
	unsigned long seen_generation = 0;
	int err;

	err = pthread_mutex_lock(&pool->lock);
	if (err) {
		pr_err("Unable to lock decompression worker pool: %s\n", strerror(err));
		BUG();
	}

	for (;;) {
		struct decompress_queue *queue;

		/* Wait for a new batch that selected this worker. */
		while (!pool->stop) {
			if (seen_generation != pool->batch_generation && worker->index < pool->batch_workers)
				break;
			err = pthread_cond_wait(&pool->work_ready, &pool->lock);
			if (err) {
				pr_err("Unable to wait for decompression work: %s\n", strerror(err));
				BUG();
			}
		}
		if (pool->stop)
			break;

		seen_generation = pool->batch_generation;
		queue = &pool->queue;
		pthread_mutex_unlock(&pool->lock);

		decompress_queue_run(queue);

		err = pthread_mutex_lock(&pool->lock);
		if (err) {
			pr_err("Unable to lock completed decompression work: %s\n", strerror(err));
			BUG();
		}
		BUG_ON(!pool->pending_batch_workers);
		pool->pending_batch_workers--;
		if (!pool->pending_batch_workers)
			pthread_cond_signal(&pool->work_done);
	}

	pthread_mutex_unlock(&pool->lock);
	return NULL;
}

static void decompression_pool_spawn_workers(struct decompression_pool *pool, unsigned int nr_workers,
					     pthread_attr_t *attrp)
{
	unsigned int attempt;

	/* Successful workers are packed; a failed attempt does not consume a slot. */
	for (attempt = 0; attempt < nr_workers; attempt++) {
		struct decompress_worker *worker = &pool->workers[pool->nr_workers];
		int err;

		worker->pool = pool;
		worker->index = pool->nr_workers;
		err = pthread_create(&worker->tid, attrp, decompression_pool_worker, worker);
		if (err) {
			pr_warn("Unable to start decompression worker %u: %s\n", attempt, strerror(err));
			break;
		}
		pool->nr_workers++;
	}
}

static struct decompression_pool *decompression_pool_create(unsigned int nr_threads, bool *mask_restore_failed)
{
	struct decompression_pool *pool;
	pthread_attr_t attr;
	sigset_t set, old;
	unsigned int nr_workers;
	size_t stack_size = PARALLEL_DECOMPRESS_STACK_SIZE;
	int err;

	*mask_restore_failed = false;
	if (nr_threads <= 1)
		return NULL;
	nr_workers = nr_threads - 1;

	pool = xzalloc(sizeof(*pool));
	if (!pool)
		return NULL;
	pool->workers = xzalloc((size_t)nr_workers * sizeof(*pool->workers));
	if (!pool->workers)
		goto free_pool;

	/* Initialize every synchronization object before starting workers. */
	err = pthread_mutex_init(&pool->lock, NULL);
	if (err) {
		pr_warn("Unable to initialize decompression pool lock: %s\n", strerror(err));
		goto free_workers;
	}
	err = pthread_cond_init(&pool->work_ready, NULL);
	if (err) {
		pr_warn("Unable to initialize decompression work condition: %s\n", strerror(err));
		goto destroy_lock;
	}
	err = pthread_cond_init(&pool->work_done, NULL);
	if (err) {
		pr_warn("Unable to initialize decompression completion condition: %s\n", strerror(err));
		goto destroy_ready;
	}

	/* A bounded worker stack keeps large restore pools inexpensive. */
	err = pthread_attr_init(&attr);
	if (err) {
		pr_warn("Unable to initialize decompression worker attributes: %s\n", strerror(err));
		goto destroy_done;
	}
	if (stack_size < PTHREAD_STACK_MIN)
		stack_size = PTHREAD_STACK_MIN;
	err = pthread_attr_setstacksize(&attr, stack_size);
	if (err) {
		pr_warn("Unable to set decompression worker stack size: %s\n", strerror(err));
		goto destroy_attr;
	}

	/* Workers inherit blocked asynchronous signals from their creator. */
	decompression_worker_signal_set(&set);
	err = pthread_sigmask(SIG_BLOCK, &set, &old);
	if (err) {
		pr_warn("Unable to block signals for decompression workers: %s\n", strerror(err));
		goto destroy_attr;
	}

	decompression_pool_spawn_workers(pool, nr_workers, &attr);

	/* Restore the calling thread's mask after all workers have started. */
	err = pthread_sigmask(SIG_SETMASK, &old, NULL);
	if (err) {
		pr_err("Unable to restore signal mask after starting decompression workers: %s\n", strerror(err));
		*mask_restore_failed = true;
	}

destroy_attr:
	pthread_attr_destroy(&attr);

	if (pool->nr_workers)
		return pool;

destroy_done:
	pthread_cond_destroy(&pool->work_done);
destroy_ready:
	pthread_cond_destroy(&pool->work_ready);
destroy_lock:
	pthread_mutex_destroy(&pool->lock);
free_workers:
	xfree(pool->workers);
free_pool:
	xfree(pool);
	return NULL;
}

void decompression_pool_destroy(struct decompression_pool *pool)
{
	unsigned int w;
	int err;

	if (!pool)
		return;

	err = pthread_mutex_lock(&pool->lock);
	if (err) {
		pr_err("Unable to lock decompression pool for shutdown: %s\n", strerror(err));
		BUG();
	}
	BUG_ON(pool->batch_active || pool->pending_batch_workers);
	pool->stop = true;
	pthread_cond_broadcast(&pool->work_ready);
	pthread_mutex_unlock(&pool->lock);

	for (w = 0; w < pool->nr_workers; w++) {
		err = pthread_join(pool->workers[w].tid, NULL);
		if (err) {
			pr_err("Unable to join decompression worker %u: %s\n", w, strerror(err));
			BUG();
		}
	}

	pthread_cond_destroy(&pool->work_done);
	pthread_cond_destroy(&pool->work_ready);
	pthread_mutex_destroy(&pool->lock);
	xfree(pool->workers);
	xfree(pool);
}

/* Publish one immutable job array to the selected subset of pool workers. */
static void decompression_pool_start_batch(struct decompression_pool *pool, struct decompress_job *jobs,
					   size_t nr_jobs, unsigned int active_threads)
{
	int err;

	err = pthread_mutex_lock(&pool->lock);
	if (err) {
		pr_err("Unable to lock decompression pool for dispatch: %s\n", strerror(err));
		BUG();
	}
	BUG_ON(pool->batch_active || pool->pending_batch_workers);
	decompress_queue_init(&pool->queue, jobs, nr_jobs, active_threads);
	pool->batch_active = true;
	pool->batch_workers = active_threads - 1;
	pool->pending_batch_workers = pool->batch_workers;
	pool->batch_generation++;
	pthread_cond_broadcast(&pool->work_ready);
	pthread_mutex_unlock(&pool->lock);
}

/* Wait until workers have dropped every reference to the caller-owned jobs. */
static bool decompression_pool_finish_batch(struct decompression_pool *pool, int *failed_block)
{
	bool failed;
	int err;

	err = pthread_mutex_lock(&pool->lock);
	if (err) {
		pr_err("Unable to lock decompression pool for completion: %s\n", strerror(err));
		BUG();
	}
	while (pool->pending_batch_workers) {
		err = pthread_cond_wait(&pool->work_done, &pool->lock);
		if (err) {
			pr_err("Unable to wait for decompression completion: %s\n", strerror(err));
			BUG();
		}
	}

	failed = decompress_queue_failed(&pool->queue);
	*failed_block = pool->queue.failed_block;
	pool->queue.jobs = NULL;
	pool->queue.nr_jobs = 0;
	pool->batch_active = false;
	pool->batch_workers = 0;
	pthread_mutex_unlock(&pool->lock);

	return failed;
}

int decompress_jobs_parallel_pool_with_caller_work(
	struct decompression_pool **poolp, struct decompress_job *jobs,
	size_t nr_jobs, size_t total_uncompressed,
	unsigned int requested_threads,
	decompression_caller_work_fn caller_work, void *caller_work_arg)
{
	struct decompression_pool *pool;
	unsigned int active_threads, useful_threads, threads_held;
	bool mask_restore_failed = false;
	int failed_block = INT_MAX, ret = 0;

	if (!nr_jobs)
		return 0;
	if (!jobs || !poolp)
		return -1;

	/* Reserve restore-wide CPU slots after choosing this batch's useful width. */
	useful_threads = decompress_batch_threads(nr_jobs, total_uncompressed, requested_threads);
	threads_held = decompress_budget_acquire(useful_threads);
	if (!threads_held)
		return decompress_jobs_serial(jobs, nr_jobs);
	if (threads_held == 1) {
		ret = decompress_jobs_serial(jobs, nr_jobs);
		goto out_release_budget;
	}

	pool = *poolp;
	if (pool && threads_held > pool->nr_workers + 1) {
		decompression_pool_destroy(pool);
		pool = NULL;
		*poolp = NULL;
	}
	if (!pool) {
		pool = decompression_pool_create(threads_held, &mask_restore_failed);
		*poolp = pool;
	}
	if (mask_restore_failed) {
		decompression_pool_destroy(pool);
		*poolp = NULL;
		ret = -1;
		goto out_release_budget;
	}
	if (!pool) {
		pr_warn("Unable to start decompression workers, using serial decompression\n");
		decompress_budget_trim_reservation(&threads_held, 1);
		ret = decompress_jobs_serial(jobs, nr_jobs);
		goto out_release_budget;
	}

	/* A partially created pool may need fewer slots than were reserved. */
	active_threads = min(threads_held, pool->nr_workers + 1);
	decompress_budget_trim_reservation(&threads_held, active_threads);

	decompression_pool_start_batch(pool, jobs, nr_jobs, active_threads);
	if (caller_work)
		caller_work(caller_work_arg);
	/* After optional caller work, consume any jobs the pool has not claimed. */
	decompress_queue_run(&pool->queue);

	if (decompression_pool_finish_batch(pool, &failed_block)) {
		pr_err("Decompression failed at block %d\n", failed_block);
		ret = -1;
	}
out_release_budget:
	decompress_budget_release(threads_held);
	return ret;
}

int decompress_jobs_parallel_pool(struct decompression_pool **poolp,
				  struct decompress_job *jobs, size_t nr_jobs,
				  size_t total_uncompressed,
				  unsigned int requested_threads)
{
	return decompress_jobs_parallel_pool_with_caller_work(
		poolp, jobs, nr_jobs, total_uncompressed, requested_threads,
		NULL, NULL);
}
