#include <sched.h>

#include "zdtmtst.h"
#include "sysctl.h"

const char *test_doc	= "Check dump and restore a net.unix.max_dgram_qlen sysctl parameter in subns";
const char *test_author	= "Alexander Mikhalitsyn <alexander@mihalicyn.com>";

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
	int ret = 0;
	sysctl_opt_t *p;
	test_init(argc, argv);

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
		if (sysctl_read_int(p->path, &p->new))
			ret = 1;

		if (p->old != p->new) {
			errno = EINVAL;
			pr_perror("%s changed: %d ---> %d", p->path, p->old, p->new);
			ret = 1;
		}
	}

	if (ret)
		fail();
	else
		pass();

	return ret;
}
