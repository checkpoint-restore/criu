#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <linux/limits.h>

#include "zdtmtst.h"

const char *test_doc	= "Check bind-mounts with unix socket";
const char *test_author	= "Cyrill Gorcunov <gorcunov@virtuozzo.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

int main(int argc, char **argv)
{
	char path_unix[PATH_MAX], path_bind[PATH_MAX];
	char unix_name[] = "criu-log";
	char bind_name[] = "criu-bind-log";
	int sk = -1, skc = -1, ret = 1, fd;
	struct sockaddr_un addr;
	unsigned int addrlen;
	task_waiter_t t;
	struct stat st;
	int status;
	pid_t pid;

	char buf[] = "123456";
	char rbuf[sizeof(buf)];

	test_init(argc, argv);
	task_waiter_init(&t);

	mkdir(dirname, 0700);
	if (mount("none", dirname, "tmpfs", 0, NULL)) {
		pr_perror("Unable to mount %s", dirname);
		return 1;
	}

	ssprintf(path_bind, "%s/%s", dirname, bind_name);
	ssprintf(path_unix, "%s/%s", dirname, unix_name);

	unlink(path_bind);
	unlink(path_unix);

	fd = open(path_bind, O_RDONLY | O_CREAT);
	if (fd < 0) {
		pr_perror("Can't open %s", path_bind);
		return 1;
	}
	close(fd);

	addr.sun_family = AF_UNIX;
	sstrncpy(addr.sun_path, path_unix);
	addrlen = sizeof(addr.sun_family) + strlen(path_unix);

	sk = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sk < 0) {
		pr_perror("Can't create socket %s", path_unix);
		return 1;
	}

	ret = bind(sk, (struct sockaddr *)&addr, addrlen);
	if (ret) {
		pr_perror("Can't bind socket %s", path_unix);
		return 1;
	}

	if (stat(path_unix, &st) == 0) {
		test_msg("path %s st.st_ino %#lx st.st_mode 0%o (sock %d)\n",
			 path_unix, (unsigned long)st.st_ino,
			 (int)st.st_mode, !!S_ISSOCK(st.st_mode));
	} else {
		pr_perror("Can't stat on %s", path_unix);
		return 1;
	}

	if (mount(path_unix, path_bind, NULL, MS_BIND | MS_REC, NULL)) {
		pr_perror("Unable to bindmount %s -> %s", path_unix, path_bind);
		return 1;
	}

	if (stat(path_unix, &st) == 0) {
		test_msg("path %s st.st_dev %#x st.st_rdev %#x st.st_ino %#lx st.st_mode 0%o (sock %d)\n",
			 path_unix, (int)st.st_dev, (int)st.st_rdev, (unsigned long)st.st_ino,
			 (int)st.st_mode, !!S_ISSOCK(st.st_mode));
	} else {
		pr_perror("Can't stat on %s", path_unix);
		return 1;
	}

	if (stat(path_bind, &st) == 0) {
		test_msg("path %s st.st_dev %#x st.st_rdev %#x st.st_ino %#lx st.st_mode 0%o (sock %d)\n",
			 path_bind, (int)st.st_dev, (int)st.st_rdev, (unsigned long)st.st_ino,
			 (int)st.st_mode, !!S_ISSOCK(st.st_mode));
	} else {
		pr_perror("Can't stat on %s", path_bind);
		return 1;
	}

	pid = test_fork();
	if (pid < 0) {
		pr_perror("Can't fork");
		return 1;
	} else if (pid == 0) {
		skc = socket(AF_UNIX, SOCK_DGRAM, 0);
		if (skc < 0) {
			pr_perror("Can't create client socket");
			_exit(1);
		}

		addr.sun_family = AF_UNIX;
		sstrncpy(addr.sun_path, path_bind);
		addrlen = sizeof(addr.sun_family) + strlen(path_bind);

		ret = connect(skc, (struct sockaddr *)&addr, addrlen);
		if (ret) {
			pr_perror("Can't connect\n");
			_exit(1);
		} else
			test_msg("Connected to %s", addr.sun_path);

		task_waiter_complete(&t, 1);
		task_waiter_wait4(&t, 2);

		ret = sendto(skc, buf, sizeof(buf), 0, (struct sockaddr *)&addr, addrlen);
		if (ret != (int)sizeof(buf)) {
			pr_perror("Can't send data on client");
			_exit(1);
		}

		close(skc);
		_exit(0);
	}

	task_waiter_wait4(&t, 1);

	test_daemon();
	test_waitsig();

	task_waiter_complete(&t, 2);

	ret = read(sk, rbuf, sizeof(rbuf));
	if (ret < 0) {
		fail("Can't read data");
		goto err;
	}

	if (ret != sizeof(buf) || memcmp(buf, rbuf, sizeof(buf))) {
		fail("Data mismatch");
		goto err;
	}

	ret = wait(&status);
	if (ret == -1 || !WIFEXITED(status) || WEXITSTATUS(status)) {
		kill(pid, SIGKILL);
		fail("Unable to wait child");
	} else {
		ret = 0;
		pass();
	}

err:
	umount2(path_bind, MNT_DETACH);
	umount2(dirname, MNT_DETACH);
	unlink(path_bind);
	unlink(path_unix);
	close(sk);

	return ret ? 1 : 0;
}
