#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <inttypes.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <lz4.h>

#include "page.h"
#include "pagemap.h"
#include "cr_options.h"
#include "util.h"
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
 * asyncd can restore several shmem or memfd objects concurrently. Each of
 * those requests may enter decompress_jobs_parallel_pool(), so limiting one
 * invocation to the available CPUs is not sufficient: independent calls can
 * otherwise multiply the worker count. Account for the calling thread as
 * well as workers using a shared budget in restore memory.
 */
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
	if (requested_threads == 1 || !decompress_shared_budget)
		return false;

	return decompression_thread_limit(requested_threads, decompress_shared_budget->thread_capacity) > 1;
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
	if (!decompress_shared_budget)
		return 0;
	return shared_budget_acquire(&decompress_shared_budget->threads, requested);
}

static void decompress_budget_release(unsigned int nr_threads)
{
	if (!nr_threads || !decompress_shared_budget)
		return;
	shared_budget_release(&decompress_shared_budget->threads, nr_threads);
}

static void decompress_budget_trim_reservation(unsigned int *threads_held, unsigned int threads_to_keep)
{
	BUG_ON(threads_to_keep > *threads_held);
	decompress_budget_release(*threads_held - threads_to_keep);
	*threads_held = threads_to_keep;
}

void decompression_batch_acquire(void)
{
	if (!decompress_shared_budget)
		return;
	shared_budget_acquire(&decompress_shared_budget->batches, 1);
}

bool decompression_batch_try_acquire(void)
{
	if (!decompress_shared_budget)
		return true;
	return shared_budget_try_acquire(&decompress_shared_budget->batches);
}

void decompression_batch_release(void)
{
	if (!decompress_shared_budget)
		return;
	shared_budget_release(&decompress_shared_budget->batches, 1);
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

int compress_block(const char *src, unsigned int n_pages, char *dst,
		   size_t dst_cap, int acceleration)
{
	size_t block_bytes;
	unsigned int i;
	int ret;

	if (n_pages == 0 || n_pages > MAX_BLOCK_PAGES) {
		pr_err("compress_block: invalid n_pages %u\n", n_pages);
		return -1;
	}
	if (!src || !dst) {
		pr_err("compress_block: invalid buffer\n");
		return -1;
	}
	block_bytes = (size_t)n_pages * PAGE_SIZE;

	/* Cheap pre-pass: every page in the block zero-filled? */
	for (i = 0; i < n_pages; i++) {
		if (!page_is_all_zero(src + (size_t)i * PAGE_SIZE))
			break;
	}
	if (i == n_pages)
		return 0;

	if (dst_cap < block_bytes) {
		pr_err("compress_block: dst buffer (%zu) smaller than block (%zu)\n",
		       dst_cap, block_bytes);
		return -1;
	}

	if (acceleration < 1)
		acceleration = 1;

	ret = LZ4_compress_fast(src, dst, block_bytes, dst_cap, acceleration);
	if (ret <= 0 || (size_t)ret >= BLOCK_COMPRESSION_THRESHOLD(block_bytes)) {
		/*
		 * LZ4 can fail when dst_cap is below LZ4 worst-case bound
		 * (which the caller should size correctly), or when the
		 * compressed size hits the threshold and we'd rather store
		 * raw. Either way, fall back to raw.
		 */
		memcpy(dst, src, block_bytes);
		return block_bytes;
	}

	return ret;
}

int decompress_block(const char *src, int compressed_size,
		     unsigned int n_pages, char *dst)
{
	size_t block_bytes;

	if (n_pages == 0 || n_pages > MAX_BLOCK_PAGES) {
		pr_err("decompress_block: invalid n_pages %u\n", n_pages);
		return -1;
	}
	if (compressed_size < 0) {
		pr_err("decompress_block: negative compressed_size %d\n",
		       compressed_size);
		return -1;
	}
	if (!dst || (compressed_size && !src)) {
		pr_err("decompress_block: invalid buffer\n");
		return -1;
	}
	block_bytes = (size_t)n_pages * PAGE_SIZE;

	if ((size_t)compressed_size > block_bytes) {
		pr_err("decompress_block: compressed_size %d > block %zu\n",
		       compressed_size, block_bytes);
		return -1;
	}

	if (compressed_size == 0) {
		memset(dst, 0, block_bytes);
		return 0;
	}

	if ((size_t)compressed_size == block_bytes) {
		memcpy(dst, src, block_bytes);
		return 0;
	}

	if (decompress_data_nolog(src, compressed_size, block_bytes, dst)) {
		pr_err("Block decompression failed (compressed_size=%d, n_pages=%u)\n",
		       compressed_size, n_pages);
		return -1;
	}

	return 0;
}

/*
 * A decompression batch starts when a pagemap reader hands the pool a list of
 * independent jobs. The pool borrows that list and its buffers; the API caller
 * keeps them valid until every participant has finished.
 *
 * For a parallel batch, N CPU-budget slots cover these participants:
 *
 *             N slots = 1 caller + (N - 1) selected pool workers
 *
 * Pool pthreads live longer than a batch, but the budget reservation ends
 * with each call. Between calls, workers sleep without holding budget slots,
 * so a later batch can reuse them without another pthread_create().
 *
 * One batch tells the following story:
 *
 *              caller                               pool workers
 *              ------                               ------------
 * start:       publish jobs and broadcast --------> test generation/index
 * overlap:     optional work                        claim/decode chunks
 *              (for example, prefetch next payload)
 * help:        claim/decode available chunks        claim/decode chunks
 * finish:      wait for selected workers <--------- report completion
 * return:      reuse jobs and buffers               sleep
 *
 * decompression_pool_start_batch() publishes immutable job metadata under
 * pool->lock and wakes the pool. The lock protects publication, worker
 * selection, completion, and shutdown; it is not held while jobs run. The
 * caller and selected workers then atomically claim chunks from the queue.
 * Jobs write to disjoint destinations, so the chunks need no further locking.
 * decompression_pool_finish_batch() waits until every selected worker has
 * dropped its reference before the caller may reuse the jobs or their buffers.
 *
 * batch_generation gives each dispatch an identity. After a wake-up, a worker
 * may leave the wait loop only if the generation is new and its stable index
 * is in the selected prefix.
 *
 * Failure is a request to stop claiming new chunks, not an immediate stop.
 * Already claimed jobs may finish. failed_block records the lowest observed
 * failure and is consumed only after all participants stop using the queue.
 */
struct decompress_queue {
	struct decompress_job *jobs;
	size_t nr_jobs;
	size_t job_chunk;
	/*
	 * Concurrent scheduling and failure reporting use compiler-provided
	 * atomics. Keep one API for all three fields because next_job needs size_t,
	 * while CRIU's atomic_t is int-sized.
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

struct decompression_pool {
	pthread_mutex_t lock;
	pthread_cond_t work_ready;
	pthread_cond_t work_done;
	struct decompress_worker *workers;
	struct decompress_queue queue;
	/* Persistent pthreads owned by this pool. */
	unsigned int nr_workers;
	/* Selected workers for this batch; the caller is not counted. */
	unsigned int batch_workers;
	/* Selected workers which may still reference queue.jobs. */
	unsigned int pending_batch_workers;
	/* A new identity for every published batch. */
	unsigned long batch_generation;
	/* True while queue.jobs is borrowed from the caller. */
	bool batch_active;
	/* Ask sleeping workers to leave their loop during pool destruction. */
	bool stop;
};

static int decompress_job_run(const struct decompress_job *job)
{
	size_t block_bytes;

	if (!job->pages || job->pages > MAX_BLOCK_PAGES)
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

static void decompress_queue_init(struct decompress_queue *queue,
				  struct decompress_job *jobs,
				  size_t nr_jobs,
				  unsigned int nr_threads)
{
	queue->jobs = jobs;
	queue->nr_jobs = nr_jobs;
	/*
	 * Leave several claims per participant to balance uneven jobs. The cap
	 * limits the work already claimed when another participant fails.
	 */
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
	/* Cancellation is only a hint; read the result after all work stops. */
	return __atomic_load_n(&queue->failed, __ATOMIC_RELAXED);
}

static int decompress_queue_failed_block(const struct decompress_queue *queue)
{
	return __atomic_load_n(&queue->failed_block, __ATOMIC_RELAXED);
}

static bool decompress_queue_claim_chunk(struct decompress_queue *queue,
					 size_t *first,
					 size_t *end)
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

	/* Stop useful scheduling; already claimed disjoint chunks may finish. */
	__atomic_store_n(&queue->failed, 1, __ATOMIC_RELAXED);
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

	pr_err("Decompression failed at block %d\n", decompress_queue_failed_block(&queue));
	return -1;
}

static unsigned int decompress_batch_threads(size_t nr_jobs,
					     size_t total_uncompressed,
					     unsigned int requested_threads)
{
	size_t work_limit;
	unsigned int nr_threads;

	/*
	 * Add participants only while each has a job and at least 512 KiB of
	 * decoded work. Smaller batches stay with the caller.
	 */
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

		/*
		 * A wake-up alone is not work. The generation prevents a worker
		 * from repeating a batch, while its index selects the useful prefix.
		 */
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

static void decompression_pool_spawn_workers(struct decompression_pool *pool,
					     unsigned int nr_workers,
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
	/* The caller uses one slot, so create only nr_threads - 1 workers. */
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
static void decompression_pool_start_batch(struct decompression_pool *pool,
					   struct decompress_job *jobs,
					   size_t nr_jobs,
					   unsigned int active_threads)
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

	/*
	 * Each worker records failure before taking this lock to drop its pending
	 * count, and the caller finishes its queue run before entering here.
	 * Waiting for all pending workers therefore publishes the minimum.
	 */
	failed = decompress_queue_failed(&pool->queue);
	*failed_block = decompress_queue_failed_block(&pool->queue);
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
	/*
	 * The pool survives a batch, but its CPU-budget reservation does not. Reuse a
	 * large enough pool; replace it only when this batch needs more workers.
	 */
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

	/*
	 * Publishing the batch lets workers decode while the caller performs
	 * optional work. The caller then helps drain the queue and waits until no
	 * worker can reference it.
	 */
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

void encoded_read_ctx_begin_work(struct encoded_read_ctx *ctx)
{
	BUG_ON(ctx->batch_acquired);
	decompression_batch_acquire();
	ctx->batch_acquired = true;
}

void encoded_read_ctx_end_work(struct encoded_read_ctx *ctx)
{
	if (!ctx || !ctx->batch_acquired)
		return;

	xfree(ctx->scratch);
	ctx->scratch = NULL;
	ctx->scratch_cap = 0;
	xfree(ctx->compressed);
	ctx->compressed = NULL;
	ctx->compressed_cap = 0;
	xfree(ctx->prefetch_buffer);
	ctx->prefetch_buffer = NULL;
	ctx->prefetch_cap = 0;
	ctx->prefetched_token = NULL;
	memset(&ctx->prefetch, 0, sizeof(ctx->prefetch));
	xfree(ctx->jobs);
	ctx->jobs = NULL;
	ctx->jobs_cap = 0;
	if (ctx->prefetch_batch_acquired) {
		ctx->prefetch_batch_acquired = false;
		decompression_batch_release();
	}
	ctx->batch_acquired = false;
	decompression_batch_release();
}

void encoded_read_ctx_fini(struct encoded_read_ctx *ctx)
{
	if (!ctx)
		return;
	encoded_read_ctx_end_work(ctx);
	decompression_pool_destroy(ctx->pool);
}

void encoded_prefetch_read(void *arg)
{
	struct encoded_prefetch *prefetch = arg;

	while (prefetch->done < prefetch->count) {
		ssize_t ret;

		ret = pread(prefetch->fd, prefetch->buffer + prefetch->done,
			    prefetch->count - prefetch->done,
			    prefetch->offset + (off_t)prefetch->done);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			prefetch->saved_errno = errno;
			break;
		}
		if (!ret)
			break;
		prefetch->done += ret;
	}
	prefetch->complete = true;
}

void encoded_prefetch_disable(struct encoded_read_ctx *ctx)
{
	ctx->prefetched_token = NULL;
	memset(&ctx->prefetch, 0, sizeof(ctx->prefetch));
	xfree(ctx->prefetch_buffer);
	ctx->prefetch_buffer = NULL;
	ctx->prefetch_cap = 0;
	if (ctx->prefetch_batch_acquired) {
		ctx->prefetch_batch_acquired = false;
		decompression_batch_release();
	}
}

bool encoded_prefetch_prepare(struct encoded_read_ctx *ctx, int fd,
			      off_t offset, size_t count)
{
	void *new_buffer;

	BUG_ON(ctx->prefetched_token || ctx->prefetch.complete || !count);
	if (!ctx->prefetch_batch_acquired) {
		if (!decompression_batch_try_acquire())
			return false;
		ctx->prefetch_batch_acquired = true;
	}
	if (ctx->prefetch_cap < count) {
		new_buffer = xrealloc(ctx->prefetch_buffer, count);
		if (!new_buffer) {
			encoded_prefetch_disable(ctx);
			return false;
		}
		ctx->prefetch_buffer = new_buffer;
		ctx->prefetch_cap = count;
	}

	ctx->prefetch.buffer = ctx->prefetch_buffer;
	ctx->prefetch.count = count;
	ctx->prefetch.done = 0;
	ctx->prefetch.offset = offset;
	ctx->prefetch.fd = fd;
	ctx->prefetch.saved_errno = 0;
	return true;
}

void encoded_prefetch_publish(struct encoded_read_ctx *ctx,
			      const void *token)
{
	void *buffer;
	size_t capacity;

	BUG_ON(!ctx->prefetch.complete);
	buffer = ctx->compressed;
	capacity = ctx->compressed_cap;
	ctx->compressed = ctx->prefetch_buffer;
	ctx->compressed_cap = ctx->prefetch_cap;
	ctx->prefetch_buffer = buffer;
	ctx->prefetch_cap = capacity;
	ctx->prefetched_token = token;
}

int encoded_prefetch_take(struct encoded_read_ctx *ctx,
			  const void *token, size_t expected_count)
{
	if (!ctx->prefetched_token)
		return 0;
	if (ctx->prefetched_token != token) {
		pr_err("Encoded prefetch does not match the next request\n");
		return -1;
	}
	ctx->prefetched_token = NULL;
	ctx->prefetch.complete = false;
	if (ctx->prefetch.count != expected_count) {
		pr_err("Encoded prefetch size changed before use\n");
		return -1;
	}

	if (ctx->prefetch.saved_errno) {
		errno = ctx->prefetch.saved_errno;
		pr_perror("Can't read %zu encoded bytes at offset %lld",
			  ctx->prefetch.count, (long long)ctx->prefetch.offset);
		return -1;
	}
	if (ctx->prefetch.done != ctx->prefetch.count) {
		pr_err("Short encoded read %zu/%zu at offset %lld\n",
		       ctx->prefetch.done, ctx->prefetch.count,
		       (long long)ctx->prefetch.offset);
		return -1;
	}

	return 1;
}

struct encoded_read_ctx *encoded_read_ctx_alloc(void)
{
	return xzalloc(sizeof(struct encoded_read_ctx));
}

void encoded_read_ctx_destroy(struct encoded_read_ctx *ctx)
{
	if (ctx) {
		encoded_read_ctx_fini(ctx);
		xfree(ctx);
	}
}

int validate_direct_compressed_iov(const struct page_read_iov *piov)
{
	uint64_t payload_bytes = 0;
	uint64_t output_bytes = 0;
	uint64_t iov_bytes = 0;
	size_t i;

	if (piov->storage != VMA_IO_PACKED_RAW &&
	    piov->storage != VMA_IO_ZERO)
		return -1;
	if (!piov->b_layout.nr_blocks || !piov->b_layout.sizes) {
		pr_err("Direct compressed I/O job has no block metadata\n");
		return -1;
	}
	if (piov->b_layout.pages_per_block && !piov->block_pages) {
		pr_err("Direct block I/O job has no block-page metadata\n");
		return -1;
	}

	for (i = 0; i < piov->b_layout.nr_blocks; i++) {
		unsigned int block_pages = piov->b_layout.pages_per_block ?
						piov->block_pages[i] : 1;
		uint64_t block_bytes;
		uint32_t compressed_size = piov->b_layout.sizes[i];

		if (!block_pages ||
		    (piov->b_layout.pages_per_block && block_pages > piov->b_layout.pages_per_block)) {
			pr_err("Invalid page count %u for direct block %zu\n",
			       block_pages, i);
			return -1;
		}
		block_bytes = (uint64_t)block_pages * PAGE_SIZE;
		if (piov->storage == VMA_IO_PACKED_RAW &&
		    compressed_size != block_bytes) {
			pr_err("Packed-raw block %zu has size %u, expected %" PRIu64 "\n",
			       i, compressed_size, block_bytes);
			return -1;
		}
		if (piov->storage == VMA_IO_ZERO && compressed_size) {
			pr_err("Zero block %zu has payload size %u\n", i,
			       compressed_size);
			return -1;
		}
		if (payload_bytes > UINT64_MAX - compressed_size ||
		    output_bytes > UINT64_MAX - block_bytes) {
			pr_err("Direct compressed I/O size overflows\n");
			return -1;
		}
		payload_bytes += compressed_size;
		output_bytes += block_bytes;
	}

	for (i = 0; i < piov->nr; i++) {
		if (iov_bytes > UINT64_MAX - piov->to[i].iov_len) {
			pr_err("Direct compressed destination size overflows\n");
			return -1;
		}
		iov_bytes += piov->to[i].iov_len;
	}

	if (payload_bytes != piov->b_layout.total_bytes ||
	    output_bytes != iov_bytes || piov->end < piov->from ||
	    payload_bytes != (uint64_t)(piov->end - piov->from) ||
	    piov->n_pages > UINT64_MAX / PAGE_SIZE ||
	    output_bytes != (uint64_t)piov->n_pages * PAGE_SIZE) {
		pr_err("Inconsistent direct compressed I/O sizes: payload=%" PRIu64
		       " metadata=%" PRIu64 " output=%" PRIu64 " iov=%" PRIu64
		       " range=%jd\n", payload_bytes,
		       piov->b_layout.total_bytes, output_bytes, iov_bytes,
		       (intmax_t)(piov->end - piov->from));
		return -1;
	}

	return 0;
}

static int transfer_async_block(const struct page_read_iov *piov,
				unsigned int *iov_index, size_t *iov_offset,
				const char *src, size_t bytes)
{
	while (bytes) {
		char *dst;
		size_t chunk;

		while (*iov_index < piov->nr &&
		       *iov_offset >= piov->to[*iov_index].iov_len) {
			*iov_offset -= piov->to[*iov_index].iov_len;
			(*iov_index)++;
		}
		if (*iov_index >= piov->nr) {
			pr_err("Async decompression ran out of destination iovecs\n");
			return -1;
		}

		dst = (char *)piov->to[*iov_index].iov_base + *iov_offset;
		chunk = piov->to[*iov_index].iov_len - *iov_offset;
		if (chunk > bytes)
			chunk = bytes;

		if (src) {
			memcpy(dst, src, chunk);
			src += chunk;
		} else {
			memset(dst, 0, chunk);
		}
		*iov_offset += chunk;
		bytes -= chunk;
	}

	return 0;
}

static int process_encoded_async_read(int fd, struct page_read_iov *piov,
				      struct encoded_read_ctx *ctx,
				      bool payload_ready,
				      struct encoded_prefetch *prefetch)
{
	struct decompress_job *jobs;
	char *compressed;
	char *scratch;
	size_t scratch_cap;
	size_t compressed_offset = 0;
	size_t total_compressed = piov->b_layout.total_bytes;
	size_t jobs_uncompressed = 0;
	size_t output_bytes = 0;
	size_t expected_output;
	size_t nr_jobs = 0;
	unsigned int iov_index = 0;
	size_t iov_offset = 0;
	bool parallel_zero = false;
	size_t i;
	int ret = -1;

	/*
	 * Materialize one encoded read into its destination iovecs. The caller
	 * holds the batch lease and serializes this parent-chain context; all
	 * reusable buffers remain context-owned until worker completion.
	 */
	if (!ctx || !ctx->batch_acquired) {
		pr_err("Encoded async I/O job has no active shared read context\n");
		return -1;
	}
	parallel_zero = compressed_restore_has_parallel_capacity(opts.decompress_threads);
	if (!piov->b_layout.nr_blocks || !piov->b_layout.sizes) {
		pr_err("Encoded async I/O job has no block metadata\n");
		return -1;
	}
	if (piov->b_layout.nr_blocks > (size_t)INT_MAX ||
	    piov->b_layout.nr_blocks > SIZE_MAX / sizeof(*jobs)) {
		pr_err("Encoded async I/O job has too many blocks: %zu\n",
		       piov->b_layout.nr_blocks);
		return -1;
	}
	if (piov->b_layout.pages_per_block && !piov->block_pages) {
		pr_err("Encoded block I/O job has no block-page metadata\n");
		return -1;
	}
	if ((uint64_t)total_compressed != piov->b_layout.total_bytes) {
		pr_err("Encoded async I/O size does not fit in size_t\n");
		return -1;
	}
	if (piov->n_pages > SIZE_MAX / PAGE_SIZE) {
		pr_err("Encoded async I/O page count does not fit in size_t\n");
		return -1;
	}
	expected_output = (size_t)piov->n_pages * (size_t)PAGE_SIZE;

	/*
	 * Resize reusable job and payload buffers before workers start. A ready
	 * payload was validated and installed by encoded_prefetch_take().
	 */
	if (ctx->jobs_cap < piov->b_layout.nr_blocks) {
		void *new_jobs = xrealloc(ctx->jobs,
					  piov->b_layout.nr_blocks * sizeof(*jobs));

		if (!new_jobs)
			goto out;
		ctx->jobs = new_jobs;
		ctx->jobs_cap = piov->b_layout.nr_blocks;
	}
	jobs = ctx->jobs;

	if (total_compressed) {
		if (ctx->compressed_cap < total_compressed) {
			void *new_compressed;

			if (payload_ready) {
				pr_err("Prefetched encoded payload exceeds its buffer\n");
				goto out;
			}
			new_compressed = xrealloc(ctx->compressed,
						  total_compressed);

			if (!new_compressed)
				goto out;
			ctx->compressed = new_compressed;
			ctx->compressed_cap = total_compressed;
		}
		compressed = ctx->compressed;
		if (!payload_ready &&
		    pread_full(fd, compressed, total_compressed, piov->from))
			goto out;
	} else
		compressed = NULL;
	scratch = ctx->scratch;
	scratch_cap = ctx->scratch_cap;

	/*
	 * Advance encoded and destination cursors together. Raw blocks and zero
	 * blocks without an eligible contiguous destination complete inline;
	 * contiguous zero and LZ4 blocks become disjoint jobs. Split LZ4 blocks
	 * use scratch because each job needs one contiguous destination.
	 */
	for (i = 0; i < piov->b_layout.nr_blocks; i++) {
		uint32_t compressed_size = piov->b_layout.sizes[i];
		unsigned int block_pages = 1;
		size_t block_bytes;
		size_t bound = PAGE_COMPRESSED_SIZE_BOUND;
		char *direct_dst = NULL;

		if (piov->b_layout.pages_per_block)
			block_pages = piov->block_pages[i];
		if (!block_pages ||
		    (piov->b_layout.pages_per_block && block_pages > piov->b_layout.pages_per_block)) {
			pr_err("Async: invalid page count %u for block %zu\n",
			       block_pages, i);
			goto out;
		}
		block_bytes = (size_t)block_pages * PAGE_SIZE;
		if (piov->b_layout.pages_per_block)
			bound = BLOCK_COMPRESSED_SIZE_BOUND(block_pages);
		if (compressed_size > bound ||
		    compressed_size > total_compressed - compressed_offset) {
			pr_err("Async: invalid compressed size %u for block %zu\n",
			       compressed_size, i);
			goto out;
		}
		if (output_bytes > SIZE_MAX - block_bytes) {
			pr_err("Async decompressed size overflows\n");
			goto out;
		}
		output_bytes += block_bytes;

		while (iov_index < piov->nr && iov_offset >= piov->to[iov_index].iov_len) {
			iov_offset -= piov->to[iov_index].iov_len;
			iov_index++;
		}
		if (iov_index >= piov->nr) {
			pr_err("Async: ran out of iovecs at block %zu\n", i);
			goto out;
		}
		if (block_bytes <= piov->to[iov_index].iov_len - iov_offset)
			direct_dst = (char *)piov->to[iov_index].iov_base + iov_offset;

		if (!compressed_size && (!direct_dst || !parallel_zero)) {
			if (transfer_async_block(piov, &iov_index, &iov_offset,
						 NULL, block_bytes))
				goto out;
		} else if (compressed_size == block_bytes) {
			if (transfer_async_block(piov, &iov_index, &iov_offset,
						 compressed + compressed_offset,
						 block_bytes))
				goto out;
		} else if (compressed_size >= block_bytes) {
			pr_err("Async: LZ4 block %zu has invalid size %u for %zu bytes\n",
			       i, compressed_size, block_bytes);
			goto out;
		} else if (direct_dst) {
			struct decompress_job *job = &jobs[nr_jobs++];

			job->src = compressed_size ? compressed + compressed_offset : NULL;
			job->dst = direct_dst;
			job->compressed_size = compressed_size;
			job->pages = block_pages;
			job->block_index = i;
			if (jobs_uncompressed > SIZE_MAX - block_bytes) {
				pr_err("Parallel decompression size overflows\n");
				goto out;
			}
			jobs_uncompressed += block_bytes;
			iov_offset += block_bytes;
		} else {
			void *new_scratch;

			if (scratch_cap < block_bytes) {
				new_scratch = xrealloc(scratch, block_bytes);
				if (!new_scratch)
					goto out;
				scratch = new_scratch;
				scratch_cap = block_bytes;
				ctx->scratch = scratch;
				ctx->scratch_cap = scratch_cap;
			}
			if (decompress_block(compressed + compressed_offset,
					     compressed_size, block_pages,
					     scratch)) {
				pr_err("Async decompression failed at split block %zu\n", i);
				goto out;
			}
			if (transfer_async_block(piov, &iov_index, &iov_offset,
						 scratch, block_bytes))
				goto out;
		}

		compressed_offset += compressed_size;
	}

	/* Require exact, single consumption of the payload and destination. */
	while (iov_index < piov->nr && iov_offset >= piov->to[iov_index].iov_len) {
		iov_offset -= piov->to[iov_index].iov_len;
		iov_index++;
	}
	if (compressed_offset != total_compressed || iov_index != piov->nr ||
	    iov_offset || output_bytes != expected_output) {
		pr_err("Inconsistent encoded async I/O sizes: payload=%zu/%zu output=%zu/%zu\n",
		       compressed_offset, total_compressed, output_bytes,
		       expected_output);
		goto out;
	}

	/*
	 * The pool call drains all workers before returning. Optional caller work
	 * fills the separate prefetch buffer without shortening current payload,
	 * job, or destination lifetimes.
	 */
	if (decompress_jobs_parallel_pool_with_caller_work(
		    &ctx->pool, jobs, nr_jobs, jobs_uncompressed,
		    opts.decompress_threads,
		    prefetch ? encoded_prefetch_read : NULL, prefetch))
		goto out;

	ret = 0;
out:
	return ret;
}

static bool encoded_prefetch_eligible(const struct page_read *pr,
				      const struct page_read_iov *current,
				      const struct page_read_iov *next)
{
	size_t next_size = next->b_layout.total_bytes;

	if (opts.stream || pr->use_direct || next->storage != VMA_IO_ENCODED)
		return false;
	if (!compressed_restore_has_parallel_capacity(opts.decompress_threads))
		return false;
	if (current->n_pages < PARALLEL_RESTORE_MIN_BATCH_BYTES / PAGE_SIZE ||
	    next->n_pages < PARALLEL_RESTORE_MIN_BATCH_BYTES / PAGE_SIZE)
		return false;
	if (!next_size || next_size > ASYNC_BATCH_MAX_BYTES ||
	    (uint64_t)next_size != next->b_layout.total_bytes ||
	    next->end < next->from)
		return false;
	if ((uint64_t)(next->end - next->from) !=
	    next->b_layout.total_bytes)
		return false;

	return true;
}

int encoded_stream_read_batch(int fd, void *buf, const uint32_t *block_sizes,
			      unsigned long batch_pages, size_t batch_payload,
			      size_t nr_jobs, struct encoded_read_ctx *ctx,
			      unsigned long first_page_idx)
{
	size_t payload_offset = 0;
	size_t jobs_uncompressed = 0;
	size_t nr_jobs_built = 0;
	size_t i;
	ssize_t bytes;

	/* An all-zero batch has no encoded working set to allocate or acquire. */
	if (!batch_payload && !nr_jobs) {
		for (i = 0; i < batch_pages; i++) {
			if (block_sizes[i]) {
				pr_err("Compressed streaming batch metadata mismatch at page %lu\n", first_page_idx + i);
				return -1;
			}
			memset((char *)buf + i * PAGE_SIZE, 0, PAGE_SIZE);
		}
		return 0;
	}
	if (!ctx) {
		pr_err("Compressed streaming batch has no encoded-read context\n");
		return -1;
	}

	if (!ctx->batch_acquired)
		encoded_read_ctx_begin_work(ctx);
	if (ctx->compressed_cap < batch_payload) {
		void *new_compressed =
			xrealloc(ctx->compressed, batch_payload);

		if (!new_compressed)
			return -1;
		ctx->compressed = new_compressed;
		ctx->compressed_cap = batch_payload;
	}
	if (ctx->jobs_cap < nr_jobs) {
		void *new_jobs = xrealloc(ctx->jobs,
					  nr_jobs * sizeof(*ctx->jobs));

		if (!new_jobs)
			return -1;
		ctx->jobs = new_jobs;
		ctx->jobs_cap = nr_jobs;
	}

	if (batch_payload) {
		bytes = read_all(fd, ctx->compressed, batch_payload);
		if (bytes < 0) {
			pr_perror("Can't read compressed streaming batch");
			return -1;
		}
		if ((size_t)bytes != batch_payload) {
			pr_err("Reached EOF reading compressed streaming batch: %zd of %zu bytes\n",
			       bytes, batch_payload);
			return -1;
		}
	}

	for (i = 0; i < batch_pages; i++) {
		uint32_t cs = block_sizes[i];
		char *dst = (char *)buf + i * PAGE_SIZE;

		if (!cs) {
			memset(dst, 0, PAGE_SIZE);
		} else if (cs == PAGE_SIZE) {
			memcpy(dst, ctx->compressed + payload_offset, PAGE_SIZE);
		} else {
			struct decompress_job *job = &ctx->jobs[nr_jobs_built++];

			job->src = ctx->compressed + payload_offset;
			job->dst = dst;
			job->compressed_size = cs;
			job->pages = 1;
			job->block_index = i;
			jobs_uncompressed += PAGE_SIZE;
		}
		payload_offset += cs;
	}

	if (payload_offset != batch_payload || nr_jobs_built != nr_jobs) {
		pr_err("Compressed streaming batch metadata mismatch: %zu != %zu\n",
		       payload_offset, batch_payload);
		return -1;
	}
	if (nr_jobs &&
	    decompress_jobs_parallel_pool(&ctx->pool, ctx->jobs, nr_jobs,
					  jobs_uncompressed,
					  opts.decompress_threads)) {
		pr_err("Unable to decompress streaming batch at page %lu\n",
		       first_page_idx);
		return -1;
	}

	return 0;
}

int encoded_async_read_batch(int fd, struct page_read_iov *piov,
			     struct page_read_iov *next, bool is_last,
			     struct encoded_read_ctx *ctx,
			     const struct page_read *pr)
{
	bool prefetch_prepared = false;
	int payload_ready;
	int ret;

	if (!ctx) {
		pr_err("Encoded async I/O job has no shared read context\n");
		return -1;
	}
	if (!ctx->batch_acquired)
		encoded_read_ctx_begin_work(ctx);

	payload_ready = encoded_prefetch_take(ctx, piov, piov->b_layout.total_bytes);
	if (payload_ready < 0)
		return -1;
	if (!is_last && next && encoded_prefetch_eligible(pr, piov, next)) {
		prefetch_prepared = encoded_prefetch_prepare(
			ctx, fd, next->from,
			(size_t)next->b_layout.total_bytes);
	} else if (ctx->prefetch_batch_acquired) {
		encoded_prefetch_disable(ctx);
	}

	ret = process_encoded_async_read(
		fd, piov, ctx, payload_ready > 0,
		prefetch_prepared ? &ctx->prefetch : NULL);
	if (prefetch_prepared) {
		if (ret < 0 || !ctx->prefetch.complete)
			encoded_prefetch_disable(ctx);
		else
			encoded_prefetch_publish(ctx, next);
	}
	return ret;
}
