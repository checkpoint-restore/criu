#include "criu-log.h"
#include "cuda_wait.h"
#include "seize.h"

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <time.h>

#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif
#define LOG_PREFIX "cuda_plugin: "

/*
 * CUDA operations use one tracer at a time. The SIGCHLD handler may run
 * in a library thread. Require lock-free atomics so the handler cannot
 * acquire an internal lock already held by the interrupted thread.
 *
 * Keep the tracer TID after restoring SIGCHLD's action. A forwarding
 * handler already running in a library thread may still need it to
 * notify the original handler. The tracer lives until CRIU exits.
 */
_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "SIGCHLD forwarding requires lock-free atomics");
static atomic_int event_tracer_tid;

static void forward_sigchld(int sig, siginfo_t *info, void *context)
{
	int saved_errno = errno;
	pid_t tid = atomic_load_explicit(&event_tracer_tid, memory_order_relaxed);

	(void)sig;
	(void)info;
	(void)context;

	/* Existing library threads may have SIGCHLD unblocked. */
	if (tid > 0)
		syscall(SYS_tgkill, getpid(), tid, SIGCHLD);

	errno = saved_errno;
}

int cuda_event_wait_init(struct cuda_event_wait *events)
{
	sigset_t mask;
	struct sigaction action;
	int exit_code;

	*events = (struct cuda_event_wait){ .fd = -1 };

	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &mask, &events->saved_mask))
		return -errno;

	if (sigaction(SIGCHLD, NULL, &events->saved_action)) {
		exit_code = -errno;
		goto restore_mask;
	}

	action = events->saved_action;
	action.sa_flags &= ~(SA_NOCLDSTOP | SA_NOCLDWAIT | SA_RESETHAND);
	action.sa_flags |= SA_SIGINFO;
	action.sa_sigaction = forward_sigchld;
	atomic_store_explicit(&event_tracer_tid, syscall(SYS_gettid), memory_order_relaxed);
	if (sigaction(SIGCHLD, &action, NULL)) {
		exit_code = -errno;
		goto restore_mask;
	}

	events->fd = signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK);
	if (events->fd >= 0)
		return 0;

	exit_code = -errno;
	sigaction(SIGCHLD, &events->saved_action, NULL);

restore_mask:
	sigprocmask(SIG_SETMASK, &events->saved_mask, NULL);

	return exit_code;
}

int cuda_event_wait_close(struct cuda_event_wait *events)
{
	int exit_code = 0;

	if (close(events->fd))
		exit_code = -1;
	if (sigaction(SIGCHLD, &events->saved_action, NULL))
		exit_code = -1;

	/* Re-notify the original handler so it can reap unrelated children. */
	if (events->consumed && raise(SIGCHLD))
		exit_code = -1;
	if (sigprocmask(SIG_SETMASK, &events->saved_mask, NULL))
		exit_code = -1;

	return exit_code;
}

int cuda_event_wait(struct cuda_event_wait *events, int fd, int timeout_ms)
{
	struct pollfd fds[2] = {
		{ .fd = events->fd, .events = POLLIN },
		{ .fd = fd, .events = POLLIN },
	};
	struct signalfd_siginfo info;
	int ret;

	ret = poll(fds, 2, timeout_ms);
	if (ret < 0)
		return errno == EINTR ? 0 : -errno;
	if (!ret)
		return 0;

	if (fds[0].revents & POLLIN) {
		ssize_t n;

		do {
			n = read(events->fd, &info, sizeof(info));
			if (n == sizeof(info))
				events->consumed = true;
		} while (n == sizeof(info) || (n < 0 && errno == EINTR));

		if (n < 0 && errno != EAGAIN)
			return -errno;
		if (n >= 0)
			return -EIO;
	}

	if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL))
		return -EIO;
	if (fds[1].revents & POLLNVAL)
		return -EBADF;

	return !!(fds[1].revents & (POLLIN | POLLHUP | POLLERR));
}

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

int cuda_wait_fd(struct cuda_wait *wait, int fd)
{
	struct cuda_event_wait events;
	int ret, exit_code, delay;

	exit_code = cuda_event_wait_init(&events);
	if (exit_code)
		return exit_code;

	for (;;) {
		exit_code = cuda_wait_check_thread(wait);
		if (exit_code)
			goto out;

		delay = remaining_ms(wait);
		if (delay < 0) {
			exit_code = delay;
			goto out;
		}

		ret = cuda_event_wait(&events, fd, delay);
		if (ret < 0) {
			exit_code = ret;
			goto out;
		}
		if (ret) {
			exit_code = cuda_wait_check_thread(wait);
			goto out;
		}
	}

out:
	if (cuda_event_wait_close(&events) && !exit_code)
		exit_code = -1;

	return exit_code;
}

int cuda_wait_child(struct cuda_wait *wait, pid_t child, int flags, int *status)
{
	struct cuda_event_wait events;
	int ret, exit_code, delay;
	pid_t pid;

	exit_code = cuda_event_wait_init(&events);
	if (exit_code)
		return exit_code;

	for (;;) {
		exit_code = cuda_wait_check_thread(wait);
		if (exit_code)
			goto out;

		pid = waitpid(child, status, flags | WNOHANG);
		if (pid == child) {
			exit_code = 0;
			goto out;
		}
		if (pid < 0) {
			if (errno == EINTR)
				continue;

			pr_perror("Cannot wait for child %d during %s(%d)", child, wait->operation, wait->pid);
			exit_code = -errno;
			goto out;
		}

		delay = remaining_ms(wait);
		if (delay < 0) {
			exit_code = delay;
			goto out;
		}

		ret = cuda_event_wait(&events, -1, delay);
		if (ret < 0) {
			exit_code = ret;
			goto out;
		}
	}

out:
	if (cuda_event_wait_close(&events) && !exit_code)
		exit_code = -1;

	return exit_code;
}
