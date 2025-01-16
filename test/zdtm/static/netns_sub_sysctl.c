#include <sched.h>

#include "zdtmtst.h"
#include "sysctl.h"

const char *test_doc = "Check dump and restore of sysctls in subns";
const char *test_author = "Alexander Mikhalitsyn <alexander@mihalicyn.com>";

#define MAX_STR_SYSCTL_LEN 200

enum {
	SYSCTL_INT,
	SYSCTL_STR,
};

typedef struct {
	const char *path;
	int type;
	int old;
	int new;
	char s_old[MAX_STR_SYSCTL_LEN];
	char s_new[MAX_STR_SYSCTL_LEN];
} sysctl_opt_t;

#define CONF_UNIX_BASE "/proc/sys/net/unix"
#define IPV4_SYSCTL_BASE "/proc/sys/net/ipv4"

static sysctl_opt_t net_unix_params[] = {
	{CONF_UNIX_BASE "/max_dgram_qlen", SYSCTL_INT},
	{IPV4_SYSCTL_BASE "/ping_group_range", SYSCTL_STR, 0, 0, "40000\t50000\n"},
	{NULL, 0, 0}
};

int main(int argc, char **argv)
{
	int ret = 0;
	sysctl_opt_t *p;
	test_init(argc, argv);

	for (p = net_unix_params; p->path != NULL; p++) {
		if (p->type == SYSCTL_INT) {
			p->old = (((unsigned)lrand48()) % 1023) + 1;
			if (sysctl_write_int(p->path, p->old)) {
				pr_perror("Can't change %s", p->path);
				return -1;
			}
		} else if (p->type == SYSCTL_STR) {
			if (sysctl_write_str(p->path, p->s_old)) {
				pr_perror("Can't change %s", p->path);
				return -1;
			}
		}
	}

	test_daemon();
	test_waitsig();

	for (p = net_unix_params; p->path != NULL; p++) {
		if (p->type == SYSCTL_INT) {
			if (sysctl_read_int(p->path, &p->new))
				ret = 1;

			if (p->old != p->new) {
				errno = EINVAL;
				pr_perror("%s changed: %d ---> %d", p->path, p->old, p->new);
				ret = 1;
			}
		} else if (p->type == SYSCTL_STR) {
			if (sysctl_read_str(p->path, p->s_new, MAX_STR_SYSCTL_LEN)) {
				ret = 1;
			} else {
				if (strcmp(p->s_old, p->s_new)) {
					errno = EINVAL;
					pr_perror("%s changed: %s ---> %s", p->path, p->s_old, p->s_new);
					ret = 1;
				}
			}
		}
	}

	if (ret)
		fail();
	else
		pass();

	return ret;
}
