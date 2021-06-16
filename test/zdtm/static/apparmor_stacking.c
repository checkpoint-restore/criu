#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <linux/limits.h>
#include <signal.h>
#include "zdtmtst.h"

const char *test_doc = "Check apparmor stacking is correctly restored";
const char *test_author = "Tycho Andersen <tycho.andersen@canonical.com>";

static int setprofile(char *to)
{
	char profile[1024];
	int fd, len;

	len = snprintf(profile, sizeof(profile), "changeprofile %s", to);
	if (len < 0 || len >= sizeof(profile)) {
		fail("bad sprintf");
		return -1;
	}

	fd = open("/proc/self/attr/current", O_WRONLY);
	if (fd < 0) {
		fail("couldn't open fd");
		return -1;
	}

	len = write(fd, profile, len);
	close(fd);

	if (len < 0) {
		fail("couldn't write profile");
		return -1;
	}

	return 0;
}

static int checkprofile(pid_t pid, char *expected)
{
	FILE *f;
	char path[PATH_MAX], profile[1024];
	int len;

	sprintf(path, "/proc/%d/attr/current", pid);

	f = fopen(path, "r");
	if (!f) {
		fail("couldn't open lsm current");
		return -1;
	}

	len = fscanf(f, "%[^ \n]s", profile);
	fclose(f);
	if (len != 1) {
		fail("wrong number of items scanned %d", len);
		return -1;
	}

	if (strcmp(profile, expected) != 0) {
		fail("bad profile .%s. expected .%s.", profile, expected);
		return -1;
	}

	return 0;
}

static void prepare_namespace(int sk)
{
	if (mkdir("/sys/kernel/security/apparmor/policy/namespaces/criu_stacking_test", 0755) && errno != EEXIST) {
		fail("mkdir");
		exit(1);
	}

	if (setprofile(":criu_stacking_test:") < 0)
		exit(1);

	if (system("apparmor_parser -r apparmor_stacking.profile") < 0) {
		fail("system");
		exit(1);
	}

	if (setprofile("criu/stacking/test") < 0)
		exit(1);

	if (write(sk, "d", 1) != 1) {
		fail("write");
		exit(1);
	}

	while (1)
		sleep(1000);
}

int main(int argc, char **argv)
{
	pid_t pid;
	int sk_pair[2], sk, ret = 1;
	char c;

	test_init(argc, argv);

	if (socketpair(PF_LOCAL, SOCK_SEQPACKET, 0, sk_pair)) {
		fail("socketpair");
		return 1;
	}

	pid = fork();
	if (pid < 0) {
		fail("fork");
		return 1;
	}

	if (!pid) {
		sk = sk_pair[1];
		close(sk_pair[0]);

		prepare_namespace(sk);
	}

	sk = sk_pair[0];
	close(sk_pair[1]);

	if ((ret = read(sk, &c, 1)) != 1) {
		pr_perror("read %d", ret);
		goto out;
	}

	test_daemon();
	test_waitsig();

	if (checkprofile(pid, ":criu_stacking_test:criu/stacking/test") < 0)
		goto out;

	ret = 0;
	pass();

out:
	kill(pid, SIGKILL);
	rmdir("/sys/kernel/security/apparmor/policy/namespaces/criu_stacking_test");
	return ret;
}
