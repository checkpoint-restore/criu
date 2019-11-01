#include <sched.h>

#include "zdtmtst.h"
#include "sysctl.h"

const char *test_doc	= "Check dump and restore a net.unix.max_dgram_qlen sysctl parameter in subns";

typedef struct {
	const char *path;
	int old;
	int new;
} sysctl_opt_t;

#define CONF_UNIX_BASE	"/proc/sys/net/unix"

static sysctl_opt_t net_unix_params[] = {
	{CONF_UNIX_BASE"/max_dgram_qlen", 0, 0},
	{NULL, 0, 0}
};

int main(int argc, char **argv)
{
	sysctl_opt_t *p;
	test_init(argc, argv);

	if (unshare(CLONE_NEWNET)) {
		perror("unshare");
		return 1;
	}

	for (p = net_unix_params; p->path != NULL; p++) {
		p->old = (((unsigned)lrand48()) % 1023) + 1;
		if (sysctl_write_int(p->path, p->old)) {
			pr_perror("Can't change %s", p->path);
			return -1;
		}
	}

	test_daemon();
	test_waitsig();

	for (p = net_unix_params; p->path != NULL; p++) {
		sysctl_read_int(p->path, &p->new);
		if (p->old != p->new) {
			fail();
			return 1;
		}
	}

	pass();
	return 0;
}
