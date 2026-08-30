#ifndef CUDA_DRIVER_WORKER_H
#define CUDA_DRIVER_WORKER_H

#include "cuda_checkpoint.h"

enum cuda_driver_operation {
	CUDA_DRIVER_PROBE,
	CUDA_DRIVER_INIT,
	CUDA_DRIVER_LOCK,
	CUDA_DRIVER_CHECKPOINT,
	CUDA_DRIVER_RESTORE,
	CUDA_DRIVER_UNLOCK,
	CUDA_DRIVER_GET_STATE,
	CUDA_DRIVER_GET_TID,
};

struct cuda_driver_request {
	enum cuda_driver_operation op;
	int pid;
	unsigned int timeout_ms;
	const CUcheckpointGpuPair *pairs;
	unsigned int pair_count;
};

struct cuda_driver_reply {
	/* Library loading and ABI validation errors are separate from CUresult. */
	int error;
	CUresult result;
	int value;
};

/* A negative return is a transport, timeout, or target-thread failure. On a
 * consumed ptrace event, thread_status contains its waitpid status; otherwise
 * it is -1. Pass monitored_tid = 0 outside a resumed CUDA restore thread;
 * thread_status may be NULL when the caller does not need the event.
 */
int cuda_driver_worker_call(const struct cuda_driver_request *request,
			    struct cuda_driver_reply *reply, int monitored_tid,
			    int *thread_status);
int cuda_driver_worker_fini(void);

#endif /* CUDA_DRIVER_WORKER_H */
