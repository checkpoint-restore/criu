#ifndef CUDA_WAIT_H
#define CUDA_WAIT_H

#include <stdbool.h>
#include <stdint.h>
#include <signal.h>
#include <sys/types.h>

/* Cleanup waits remain bounded when helper requests have no deadline. */
#define CUDA_HELPER_CLEANUP_TIMEOUT 1
#define CUDA_RESTORE_THREAD_STOP_TIMEOUT 10

/* One active event wait per tracer process; do not nest these scopes. */
struct cuda_event_wait {
	int fd;
	sigset_t saved_mask;
	struct sigaction saved_action;
	bool consumed;
};

int cuda_event_wait_init(struct cuda_event_wait *events);
int cuda_event_wait_close(struct cuda_event_wait *events);
/* 1: fd ready, 0: SIGCHLD/timeout/interruption, negative: error. */
int cuda_event_wait(struct cuda_event_wait *events, int fd, int timeout_ms);

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

/*
 * A zero timeout disables the deadline. Waits save and restore SIGCHLD state.
 * A monitored ptrace event is consumed and saved in thread_status
 * so cleanup does not wait for it again.
 */
int cuda_wait_init(struct cuda_wait *wait, const char *operation, int pid, int tid,
		   int *thread_status, unsigned int timeout_seconds);
int cuda_wait_check_thread(struct cuda_wait *wait);
int cuda_wait_fd(struct cuda_wait *wait, int fd);
int cuda_wait_child(struct cuda_wait *wait, pid_t child, int flags, int *status);

#endif /* CUDA_WAIT_H */
