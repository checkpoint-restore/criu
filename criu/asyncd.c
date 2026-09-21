#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sched.h>

#include "namespaces.h"
#include "fdstore.h"
#include "log.h"
#include "util.h"
#include "rst_info.h"
#include "asyncd.h"
#include "common/compiler.h"

static void *asyncd_thread(void *arg)
{
	int sk = (long)arg;

	while (1) {
		struct unsc_msg um;
		char msg[MAX_UNSFD_MSG_SIZE];
		uns_call_t call;
		int flags, fd, ret;
		pid_t pid;

		unsc_msg_init_nocreds(&um, &call, &flags, msg, sizeof(msg), 0);
		ret = recvmsg(sk, &um.h, 0);
		if (ret == 0)
			break;
		if (ret < 0) {
			pr_perror("async: recv req error");
			syscall(SYS_exit_group, 1);
		}

		unsc_msg_pid_fd(&um, &pid, &fd);
		pr_debug("async: daemon calls %p (%d, %d, %x)\n", call, pid, fd, flags);

		/*
		 * Caller has sent us bare address of the routine it
		 * wants to call. Since the caller is fork()-ed from the
		 * same process as the daemon is, the latter has exactly
		 * the same code at exactly the same address as the
		 * former guy has. So go ahead and just call one!
		 */

		ret = call(msg, fd, pid);

		if (fd >= 0)
			close(fd);

		if (ret < 0) {
			pr_err("async: Async call failed. Exiting\n");
			syscall(SYS_exit_group, 1);
		}
	}
	return (void *)0;
}

/*
 * The daemon is forked before the number of restore jobs is known, so it
 * cannot size its fill pool from the job count. Size it to the number of
 * available CPUs instead, capped at ASYNC_THREAD_NR_MAX. Content fill is the
 * bottleneck, so matching the pool to the available cores is a good default.
 */
#define ASYNC_THREAD_NR_MAX 16

static int asyncd(int sk)
{
	pthread_t threads[ASYNC_THREAD_NR_MAX];
	int nr_threads = min_t(int, get_avail_cpus(), ASYNC_THREAD_NR_MAX);
	int i;

	if (nr_threads < 1)
		nr_threads = 1;

	for (i = 0; i < nr_threads; i++) {
		if (pthread_create(&threads[i], NULL, asyncd_thread, (void *)(long)sk)) {
			pr_perror("async: pthread_create");
			return 1;
		}
	}

	pr_info("async: Daemon started with %d threads\n", nr_threads);
	for (i = 0; i < nr_threads; i++) {
		if (pthread_join(threads[i], NULL)) {
			pr_perror("async: pthread_join");
			return 1;
		}
	}

	return 0;
}

int __async_call(const char *func_name, uns_call_t call, int flags, void *arg, size_t arg_size, int fd)
{
	int ret, sk = -1;
	struct unsc_msg um;

	if (unlikely(arg_size > MAX_UNSFD_MSG_SIZE)) {
		pr_err("async: message size exceeded\n");
		return -1;
	}

	sk = fdstore_get(task_entries->asyncd_sk_id);
	if (sk < 0) {
		pr_err("async: cannot get ASYNCD_SK fd\n");
		return -1;
	}
	pr_debug("async: calling %s (%d, %x)\n", func_name, fd, flags);

	unsc_msg_init_nocreds(&um, &call, &flags, arg, arg_size, fd);
	ret = sendmsg(sk, &um.h, 0);
	if (ret <= 0) {
		pr_perror("async: send req error");
		ret = -1;
		goto out;
	}

	ret = 0;
out:
	close_safe(&sk);
	return ret;
}

static int asyncd_pid;
int start_asyncd(void)
{
	int sk, id;

	sk = start_unix_cred_daemon(&asyncd_pid, asyncd, false);
	if (sk < 0) {
		pr_err("failed to start asyncd\n");
		return -1;
	}

	id = fdstore_add(sk);
	close(sk);
	if (id < 0) {
		if (waitpid(asyncd_pid, NULL, 0) < 0)
			pr_perror("async: waitpid");
		asyncd_pid = 0;

		return -1;
	}

	task_entries->asyncd_sk_id = id;

	return 0;
}

int stop_asyncd(void)
{
	int exit_code = -1;
	int sk = -1, status = -1;
	sigset_t blockmask, oldmask;

	/* No daemon was started (e.g. stream restore, or already stopped). */
	if (asyncd_pid == 0)
		return 0;

	/*
	 * Don't let the sigchld_handler() mess with us
	 * calling waitpid() on the exited daemon. The
	 * same is done in cr_system().
	 */

	sigemptyset(&blockmask);
	sigaddset(&blockmask, SIGCHLD);
	sigprocmask(SIG_BLOCK, &blockmask, &oldmask);

	sk = fdstore_get(task_entries->asyncd_sk_id);
	if (sk < 0) {
		pr_err("async: cannot get ASYNCD_SK fd\n");
		goto out;
	}
	if (shutdown(sk, SHUT_WR)) {
		pr_perror("async: shutdown");
		goto out;
	}
	if (waitpid(asyncd_pid, &status, 0) < 0) {
		pr_perror("async: waitpid");
		goto out;
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		pr_err("async: daemon exited abnormally (status %#x)\n", status);
		goto out;
	}

	pr_info("async: daemon stopped\n");
	exit_code = 0;
out:
	close_safe(&sk);
	asyncd_pid = 0;
	sigprocmask(SIG_SETMASK, &oldmask, NULL);

	return exit_code;
}
