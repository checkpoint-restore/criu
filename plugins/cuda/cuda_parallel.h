/* Included by cuda_plugin_driver.c, so serial and parallel restore use exactly
 * the same state transition function. All functions except the API worker run
 * on the master tracer thread. No ptrace/wait calls in an API worker.
 */
struct cuda_parallel_operation {
	struct cuda_operation_work work;
	struct cuda_resume_operation op;
	struct criu_thread_context ctx;
	pthread_t worker;
	atomic_bool aborted;
	bool started;
	bool joined;
	bool stopped;
	bool exited;
	bool complete;
	struct timespec start;
};

static struct {
	struct cuda_parallel_operation *ops;
	unsigned int count;
	bool root_done;
} cuda_batch;

static double cuda_parallel_elapsed(const struct timespec *start)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return now.tv_sec - start->tv_sec + (now.tv_nsec - start->tv_nsec) / 1e9;
}

static int cuda_driver_resume_devices_begin(void)
{
	if (cuda_plugin_parallel == 1)
		return -ENOTSUP;
	if (cuda_batch.ops)
		return -EBUSY;
	cuda_batch.ops = calloc(cuda_plugin_parallel, sizeof(*cuda_batch.ops));
	if (!cuda_batch.ops)
		return -ENOMEM;
	cuda_batch.count = 0;
	cuda_batch.root_done = false;
	/* Do not race the initialized flag or cuInit. The first actual CUDA PID
	 * is also restored serially before we overlap the remaining processes.
	 */
	if (cuda_driver_init())
		return -1; /* core invokes ABORT, including for failed BEGIN */
	pr_info("CUDA parallel batch begin limit=%u (first CUDA pid serial)\n", cuda_plugin_parallel);
	return 0;
}

/* Complete a wave, checking every TID on every pass. Blocking on one TID can
 * deadlock when a different worker faults while the first is in the driver.
 * SIGCHLD ownership is unchanged and unrelated children are never reaped.
 */
static int cuda_parallel_wait(void)
{
	const struct timespec interval = { .tv_nsec = 1000000 };
	unsigned int pending, i;

	do {
		pending = 0;
		for (i = 0; i < cuda_batch.count; i++) {
			struct cuda_parallel_operation *op = &cuda_batch.ops[i];
			int status;
			pid_t w;

			if (op->complete)
				continue;
			pending++;
			w = waitpid(op->work.restore_tid, &status, __WALL | WNOHANG);
			if (w < 0 && errno == EINTR)
				continue;
			if (w < 0) {
				pr_perror("Cannot wait for parallel CUDA restore tid %d", op->work.restore_tid);
				return -1;
			}
			if (w) {
				op->stopped = WIFSTOPPED(status);
				op->exited = WIFEXITED(status) || WIFSIGNALED(status);
				if (!op->stopped || WSTOPSIG(status) != SIGSTOP ||
				    ((unsigned int)status >> 16) || !atomic_load(&op->work.done)) {
					log_restore_thread_status(op->work.pid, op->work.restore_tid, status);
					kill_traced_event_child(op->work.restore_tid, status);
					return -1;
				}
				pthread_join(op->worker, NULL);
				op->joined = true;
				if (criu_restore_thread_context(&op->ctx) || op->work.exit_code)
					return -1;
				op->complete = true;
				pr_info("CUDA parallel done pid=%d tid=%d elapsed=%.6f\n",
					op->work.pid, op->work.restore_tid, cuda_parallel_elapsed(&op->start));
				pending--;
			} else if (atomic_load(&op->work.stop_failed) || alarm_timeouted() ||
				   (cuda_plugin_timeout && cuda_parallel_elapsed(&op->start) >= cuda_plugin_timeout)) {
				pr_err("CUDA parallel stop/timeout failure pid=%d tid=%d elapsed=%.6f\n",
				       op->work.pid, op->work.restore_tid, cuda_parallel_elapsed(&op->start));
				return -1;
			}
		}
		if (pending)
			nanosleep(&interval, NULL);
	} while (pending);
	cuda_batch.count = 0;
	return 0;
}

static int cuda_parallel_queue(int pid, const struct cuda_device_map *map)
{
	struct cuda_parallel_operation *op;
	enum cuda_restore_tid_result found;
	int tid, ret;
	unsigned int i;

	if (!cuda_batch.ops || !cuda_pid_usable(pid))
		return -1;
	found = get_cuda_restore_tid(pid, &tid);
	if (found == CUDA_RESTORE_TID_NOT_FOUND)
		return -ENOTSUP;
	if (found != CUDA_RESTORE_TID_FOUND)
		return -1;
	if (!cuda_batch.root_done) {
		pr_info("CUDA parallel serial-first pid=%d tid=%d\n", pid, tid);
		ret = resume_device(pid, CUDA_TASK_CHECKPOINTED, CUDA_TASK_RUNNING, map);
		if (!ret)
			cuda_batch.root_done = true;
		return ret;
	}
	if (cuda_batch.count == cuda_plugin_parallel && cuda_parallel_wait())
		return -1;
	for (i = 0; i < cuda_batch.count; i++) {
		if (cuda_batch.ops[i].work.restore_tid == tid || cuda_batch.ops[i].work.pid == pid) {
			pr_err("Duplicate CUDA restore pid/tid in batch: %d/%d\n", pid, tid);
			return -1;
		}
	}
	op = &cuda_batch.ops[cuda_batch.count++];
	memset(op, 0, sizeof(*op));
	atomic_init(&op->aborted, false);
	atomic_init(&op->work.done, false);
	atomic_init(&op->work.stop_failed, false);
	op->op = (struct cuda_resume_operation) {
		.pid = pid, .current = CUDA_TASK_CHECKPOINTED, .initial = CUDA_TASK_RUNNING,
		.map = map, .aborted = &op->aborted,
	};
	op->work.run = restore_device;
	op->work.arg = &op->op;
	op->work.pid = pid;
	op->work.restore_tid = tid;
	op->work.exit_code = -1;
	clock_gettime(CLOCK_MONOTONIC, &op->start);
	ret = criu_resume_thread_context(tid, &op->ctx);
	if (ret)
		return ret;
	ret = pthread_create(&op->worker, NULL, cuda_operation_worker, &op->work);
	if (ret) {
		errno = ret;
		pr_perror("Cannot create parallel CUDA worker pid=%d", pid);
		return -1;
	}
	op->started = true;
	pr_info("CUDA parallel start pid=%d tid=%d slot=%u limit=%u\n",
		pid, tid, cuda_batch.count, cuda_plugin_parallel);
	return 0;
}

static int cuda_driver_resume_devices_finish(void)
{
	if (!cuda_batch.ops)
		return -ENOTSUP;
	if (cuda_parallel_wait())
		return -1;
	free(cuda_batch.ops);
	cuda_batch.ops = NULL;
	pr_info("CUDA parallel batch finish (all workers joined; all restore tids stopped)\n");
	return 0;
}

static int cuda_driver_resume_devices_abort(void)
{
	unsigned int i;

	if (!cuda_batch.ops)
		return -ENOTSUP;
	/* Publish abort before killing any target, then kill every outstanding
	 * target before joining any API worker. This also handles partial starts.
	 * Completed operations are already joined/stopped; core kills them later.
	 */
	for (i = 0; i < cuda_batch.count; i++)
		atomic_store(&cuda_batch.ops[i].aborted, true);
	for (i = 0; i < cuda_batch.count; i++) {
		struct cuda_parallel_operation *op = &cuda_batch.ops[i];

		if (op->complete)
			continue;
		mark_cuda_pid_failed(op->work.pid);
		if (op->stopped && op->ctx.active)
			criu_restore_thread_context(&op->ctx);
		if (kill(op->work.pid, SIGKILL) < 0 && errno != ESRCH)
			pr_perror("Unable to kill parallel CUDA target %d", op->work.pid);
	}
	for (i = 0; i < cuda_batch.count; i++) {
		struct cuda_parallel_operation *op = &cuda_batch.ops[i];
		int status;
		pid_t w;

		if (op->complete)
			continue;
		/* Consume only this TID's events. SIGKILL is pending throughout; CONT
		 * suppresses intermediate ptrace stops, never delivers a second signal.
		 */
		while (!op->exited) {
			w = waitpid(op->work.restore_tid, &status, __WALL);
			if (w < 0 && errno == EINTR)
				continue;
			if (w < 0)
				break;
			if (WIFEXITED(status) || WIFSIGNALED(status)) {
				op->exited = true;
				break;
			}
			kill_traced_event_child(op->work.restore_tid, status);
			ptrace(PTRACE_CONT, op->work.restore_tid, NULL, 0);
		}
		/* Never cancel a thread inside libcuda or release its work early. A
		 * driver that cannot return even after target death can stall this join;
		 * the outer restore supervisor must then kill the entire restore job.
		 */
		if (op->started && !op->joined) {
			pthread_join(op->worker, NULL);
			op->joined = true;
		}
	}
	free(cuda_batch.ops);
	memset(&cuda_batch, 0, sizeof(cuda_batch));
	pr_info("CUDA parallel batch abort drained (all started workers joined)\n");
	return 0;
}
