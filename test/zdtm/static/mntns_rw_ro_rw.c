#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc = "Test read-only bind mounts";
const char *test_author = "Andrey Vagin <xemul@parallels.com>";

int main(int argc, char **argv)
{
	test_init(argc, argv);

	if (mount("/proc/sys/", "/proc/sys", NULL, MS_BIND, NULL)) {
		pr_perror("Unable to bind-mount  /proc/sys");
		return 1;
	}
	if (mount("/proc/sys/net", "/proc/sys/net", NULL, MS_BIND, NULL)) {
		pr_perror("Unable to bind-mount /proc/sys/net");
		return 1;
	}
	if (mount("/proc/sys/", "/proc/sys", NULL, MS_RDONLY | MS_BIND | MS_REMOUNT, NULL)) {
		pr_perror("Unable to remount  /proc/sys");
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (access("/proc/sys/net/ipv4/ip_forward", W_OK)) {
		fail("Unable to access /proc/sys/net/ipv4/ip_forward");
		return 1;
	}

	if (access("/proc/sys/kernel/ns_last_pid", W_OK) != -1 || errno != EROFS) {
		fail("Unable to access /proc/sys/kernel/ns_last_pid");
		return 1;
	}

	pass();

	return 0;
}
