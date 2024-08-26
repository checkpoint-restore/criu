#include <sched.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <fcntl.h>

#include "zdtmtst.h"
#include "lock.h"

const char *test_doc = "Check C/R of pidfds that point to threads\n";
const char *test_author = "Bhavik Sachdev <b.sachdev1904@gmail.com>";

/* see also: https://codebrowser.dev/glibc/glibc/sysdeps/unix/sysv/linux/tst-clone3.c.html */

#ifndef PIDFD_THREAD
#define PIDFD_THREAD	O_EXCL
#endif

#ifndef PIDFD_SIGNAL_THREAD
#define PIDFD_SIGNAL_THREAD		(1UL << 0)
#endif

#ifndef PID_FS_MAGIC
#define PID_FS_MAGIC 0x50494446
#endif

static long get_fs_type(int lfd)
{
	struct statfs fst;

	if (fstatfs(lfd, &fst)) {
		return -1;
	}
	return fst.f_type;
}

static int pidfd_open(pid_t pid, unsigned int flags)
{
	return syscall(__NR_pidfd_open, pid, flags);
}

static int pidfd_send_signal(int pidfd, int sig, siginfo_t* info, unsigned int flags)
{
	return syscall(__NR_pidfd_send_signal, pidfd, sig, info, flags);
}

static int thread_func(void *a)
{
	test_waitsig();
	return 0;
}

#define CTID_INIT_VAL 1

int main(int argc, char* argv[])
{
	char st[64 * 1024] __attribute__ ((aligned));
	pid_t tid;
	int pidfd, test_pidfd;
	futex_t exited;

	int clone_flags = CLONE_THREAD;
	clone_flags |= CLONE_VM | CLONE_SIGHAND;
	clone_flags |= CLONE_CHILD_CLEARTID;

	test_init(argc, argv);

	test_pidfd = pidfd_open(getpid(), 0);
	if (test_pidfd < 0) {
		pr_perror("pidfd_open() failed");
		return 1;
	}

	/* PIDFD_THREAD, PIDFD_SIGNAL_THREAD are supported only with pidfs */
	if (get_fs_type(test_pidfd) != PID_FS_MAGIC) {
		test_daemon();
		test_waitsig();
		skip("pidfs not supported.");
		close(test_pidfd);
		return 0;
	}
	close(test_pidfd);

	futex_set(&exited, CTID_INIT_VAL);

	tid = clone(thread_func, st + sizeof(st), clone_flags, NULL, NULL, NULL, &(exited.raw));
	if (tid == -1) {
	    pr_perror("clone() failed");
	    return 1;
	}

	test_msg("Successfully created a thread with tid: %d\n", tid);
	pidfd = pidfd_open(tid, PIDFD_THREAD);
	if (pidfd < 0) {
	    pr_perror("pidfd_open() failed");
	    return 1;
	}

	test_daemon();
	test_waitsig();

	if (pidfd_send_signal(pidfd, SIGTERM, NULL, PIDFD_SIGNAL_THREAD)) {
	    pr_perror("pidfd_send_signal() failed");
	    fail();
	    close(pidfd);
	    return 1;
	}

	test_msg("Waiting for thread to exit\n");
	futex_wait_until(&exited, 0);

	pass();
	close(pidfd);
	return 0;
}
