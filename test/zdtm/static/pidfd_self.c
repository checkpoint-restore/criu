#include <sys/syscall.h>
#include <signal.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc = "Check pidfd /proc/self/fdinfo/<pidfd> entry remains consistent after checkpoint/restore\n";
const char *test_author = "Bhavik Sachdev <b.sachdev1904@gmail.com>";

struct pidfd_status {
	unsigned int flags;
	pid_t pid;
};

static int pidfd_open(pid_t pid, unsigned int flags)
{
	return syscall(__NR_pidfd_open, pid, flags);
}

static int pidfd_send_signal(int pidfd, int sig, siginfo_t* info, unsigned int flags)
{
	return syscall(__NR_pidfd_send_signal, pidfd, sig, info, flags);
}

static void show_pidfd(char *prefix, struct pidfd_status *s)
{
	test_msg("\n\t%s\n\tflags: 0%o\n\tpid: %d\n", prefix, s->flags, s->pid);
}

static int parse_self_fdinfo(int pidfd, struct pidfd_status *s)
{
	char buf[256];
	int ret = -1;
	FILE *f;

	sprintf(buf, "/proc/self/fdinfo/%d", pidfd);
	f = fopen(buf, "r");
	if (!f) {
		perror("Can't open /proc/self/fdinfo/ to parse");
		return -1;
	}

	memset(s, 0, sizeof(*s));

	/*
	* flags:  file access mode (octal) 02000002 => [O_RDWR | O_CLOEXEC]
	* pid:    the pid to which we have pidfd open
	*/
	while (fgets(buf, sizeof(buf), f)) {
		if (!fgets(buf, sizeof(buf), f))
			goto parse_err;

		if (sscanf(buf, "flags: 0%o", &s->flags) != 1) {
			goto parse_err;
		}

		if (!fgets(buf, sizeof(buf), f))
			goto parse_err;
		if (!fgets(buf, sizeof(buf), f))
			goto parse_err;

		if (!fgets(buf, sizeof(buf), f))
			goto parse_err;

		if (sscanf(buf, "Pid: %d", &s->pid) != 1)
			goto parse_err;
		ret = 0;
		break;
	}

	if (ret)
		goto parse_err;
err:
	fclose(f);
	return ret;

parse_err:
	pr_perror("Format error");
	goto err;
}

static int check_pidfd(int fd, struct pidfd_status *old)
{
	struct pidfd_status new;

	if (parse_self_fdinfo(fd, &new))
		return -1;

	show_pidfd("restored", &new);

	if (old->flags != new.flags || old->pid != new.pid)
		return -1;

	return 0;
}

int main(int argc, char* argv[])
{
	struct pidfd_status old;
	int pidfd, ret;

	test_init(argc, argv);

	pidfd = pidfd_open(getpid(), 0);
	if (pidfd < 0) {
		pr_perror("pidfd_open failed");
		return 1;
	}

	parse_self_fdinfo(pidfd, &old);

	show_pidfd("old", &old);

	if (pidfd_send_signal(pidfd, 0, NULL, 0)) {
		pr_perror("Could not send signal");
		return 1;
	}

	test_daemon();
	test_waitsig();

	ret = check_pidfd(pidfd, &old);
	if (ret) {
		fail();
		goto err;
	}

	if (pidfd_send_signal(pidfd, 0, NULL, 0)) {
		pr_perror("Could not send signal");
		fail();
		goto err;
	}

	pass();
	close(pidfd);
	return 0;
err:
	close(pidfd);
	return 1;
}
