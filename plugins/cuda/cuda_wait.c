#include "criu-log.h"
#include "cuda_wait.h"
#include "seize.h"

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <time.h>

#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif
#define LOG_PREFIX "cuda_plugin: "

#define CUDA_WAIT_POLL_MS 10

static int monotonic_ms(int64_t *value)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now)) {
		pr_perror("Cannot read CUDA operation clock");
		return -errno;
	}
	*value = (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
	return 0;
}

int cuda_wait_init(struct cuda_wait *wait, const char *operation, int pid, int tid,
		   int *thread_status, unsigned int timeout_seconds)
{
	int ret;

	*wait = (struct cuda_wait){
		.operation = operation,
		.pid = pid,
		.tid = tid,
		.thread_status = thread_status,
		.timeout_seconds = timeout_seconds,
	};
	if (thread_status)
		*thread_status = -1;
	if (!timeout_seconds)
		return 0;
	ret = monotonic_ms(&wait->deadline_ms);
	if (!ret)
		wait->deadline_ms += (int64_t)timeout_seconds * 1000;
	return ret;
}

int cuda_wait_check_thread(struct cuda_wait *wait)
{
	siginfo_t info;
	int status;
	pid_t pid;

	if (!wait->tid)
		return 0;
	pid = waitpid(wait->tid, &status, __WALL | WNOHANG);
	if (!pid)
		return 0;
	if (pid < 0) {
		pr_perror("Cannot inspect CUDA restore tid %d during %s(%d)", wait->tid,
			  wait->operation, wait->pid);
		return -errno;
	}
	*wait->thread_status = status;
	if (WIFSTOPPED(status)) {
		pr_err("%s(%d): CUDA restore tid %d stopped by signal %d (%s)\n",
		       wait->operation, wait->pid, wait->tid, WSTOPSIG(status), strsignal(WSTOPSIG(status)));
		if (ptrace(PTRACE_GETSIGINFO, wait->tid, NULL, &info)) {
			pr_perror("Cannot read signal information for CUDA restore tid %d", wait->tid);
		} else if (info.si_signo == SIGSEGV || info.si_signo == SIGBUS) {
			/*
			 * Avoid "%p": glibc renders a NULL pointer as "(nil)"
			 * but musl (e.g. on Alpine) does not, which made this
			 * message libc-dependent. Format the address as a
			 * plain hex integer instead, which is consistent
			 * across libcs.
			 */
			pr_err("CUDA restore tid %d fault: code %d, address %#lx\n", wait->tid, info.si_code,
			       (unsigned long)info.si_addr);
		}
	} else if (WIFSIGNALED(status)) {
		pr_err("%s(%d): CUDA restore tid %d terminated by signal %d\n",
		       wait->operation, wait->pid, wait->tid, WTERMSIG(status));
	} else if (WIFEXITED(status)) {
		pr_err("%s(%d): CUDA restore tid %d exited with status %d\n",
		       wait->operation, wait->pid, wait->tid, WEXITSTATUS(status));
	} else {
		pr_err("%s(%d): unexpected wait status %#x for CUDA restore tid %d\n",
		       wait->operation, wait->pid, status, wait->tid);
	}
	return -ECHILD;
}

static int remaining_ms(struct cuda_wait *wait)
{
	int64_t now, remaining;
	int ret;

	if (!wait->ignore_criu_timeout && alarm_timeouted()) {
		pr_err("%s(%d) interrupted by CRIU's freezing timeout\n", wait->operation, wait->pid);
		return -ETIMEDOUT;
	}
	if (!wait->timeout_seconds)
		return INT_MAX;
	ret = monotonic_ms(&now);
	if (ret)
		return ret;
	remaining = wait->deadline_ms - now;
	if (remaining <= 0) {
		pr_err("%s(%d) timed out after %u seconds\n", wait->operation, wait->pid, wait->timeout_seconds);
		return -ETIMEDOUT;
	}
	return remaining > INT_MAX ? INT_MAX : (int)remaining;
}

/* PTRACE_INTERRUPT is asynchronous, so the caller must wait for a stop.
 * Use a timed SIGCHLD wait to avoid an unbounded waitpid() or polling.
 * Keeping SIGCHLD blocked between waitpid(WNOHANG) and this wait ensures
 * that a notification arriving in that gap remains pending.
 */
int cuda_wait_signal(struct cuda_wait *wait, const sigset_t *signals)
{
	struct timespec timeout;
	int delay;

	for (;;) {
		delay = remaining_ms(wait);
		if (delay < 0)
			return delay;
		timeout.tv_sec = delay / 1000;
		timeout.tv_nsec = (delay % 1000) * 1000000;
		if (sigtimedwait(signals, NULL, &timeout) >= 0)
			return 0;
		if (errno == EINTR || errno == EAGAIN)
			continue;
		pr_perror("Cannot wait for signal during %s(%d)", wait->operation, wait->pid);
		return -errno;
	}
}

int cuda_wait_fd(struct cuda_wait *wait, int fd)
{
	struct pollfd pollfd = { .fd = fd, .events = POLLIN };
	int ret, delay;

	for (;;) {
		ret = cuda_wait_check_thread(wait);
		if (ret)
			return ret;
		delay = remaining_ms(wait);
		if (delay < 0)
			return delay;
		if (wait->tid && delay > CUDA_WAIT_POLL_MS)
			delay = CUDA_WAIT_POLL_MS;
		ret = poll(&pollfd, 1, delay);
		if (ret < 0) {
			/* CRIU's alarm or an unrelated child can interrupt this poll. */
			if (errno == EINTR)
				continue;
			pr_perror("Cannot wait for %s(%d)", wait->operation, wait->pid);
			return -errno;
		}
		if (!ret)
			continue;
		if (pollfd.revents & (POLLIN | POLLHUP | POLLERR))
			return cuda_wait_check_thread(wait);
		pr_err("Invalid poll events %#x during %s(%d)\n", pollfd.revents, wait->operation, wait->pid);
		return -EIO;
	}
}

int cuda_wait_child(struct cuda_wait *wait, pid_t child, int flags, int *status)
{
	int ret, delay;
	pid_t pid;

	for (;;) {
		ret = cuda_wait_check_thread(wait);
		if (ret)
			return ret;
		pid = waitpid(child, status, flags | WNOHANG);
		if (pid == child)
			return 0;
		if (pid < 0) {
			pr_perror("Cannot wait for child %d during %s(%d)", child, wait->operation, wait->pid);
			return -errno;
		}
		delay = remaining_ms(wait);
		if (delay < 0)
			return delay;
		if (delay > CUDA_WAIT_POLL_MS)
			delay = CUDA_WAIT_POLL_MS;
		poll(NULL, 0, delay);
	}
}
