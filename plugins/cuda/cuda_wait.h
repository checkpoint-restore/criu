#ifndef CUDA_WAIT_H
#define CUDA_WAIT_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

struct cuda_wait {
	const char *operation;
	int pid;
	int tid;
	int *thread_status;
	int64_t deadline_ms;
	unsigned int timeout_seconds;
	/* Cleanup must still reap helpers and stop resumed threads after timeout. */
	bool ignore_criu_timeout;
};

/* Block SIGCHLD in the caller while waiting. A monitored ptrace event is
 * consumed and saved in thread_status so cleanup does not wait for it again.
 */
int cuda_wait_init(struct cuda_wait *wait, const char *operation, int pid, int tid,
		   int *thread_status, unsigned int timeout_seconds);
int cuda_wait_check_thread(struct cuda_wait *wait);
int cuda_wait_fd(struct cuda_wait *wait, int fd);
int cuda_wait_child(struct cuda_wait *wait, pid_t child, int flags, int *status);

#endif /* CUDA_WAIT_H */
