#include <errno.h>
#include <unistd.h>
#include <sys/types.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that p?pid and e?[ug]id didn't change";
const char *test_author	= "Pavel Emelianov <xemul@parallels.com>";

int main(int argc, char **argv)
{
	pid_t pid, ppid;
	uid_t uid, euid;
	gid_t gid, egid;

	test_init(argc, argv);

#define SET_XID(id)	id = get##id()
	SET_XID(pid);
	ppid = 1;	/* SET_XID(ppid); 	daemonization confuses it */
	SET_XID(uid);
	SET_XID(euid);
	SET_XID(gid);
	SET_XID(egid);

	test_daemon();
	test_waitsig();

#define CHECK(id) do {					\
	if (id != get##id()) {				\
		fail("%s != get%s()\n", #id, #id);	\
		goto out;				\
	}						\
} while (0)

	CHECK(pid);
	CHECK(ppid);
	CHECK(uid);
	CHECK(euid);
	CHECK(gid);
	CHECK(egid);

	pass();
out:
	return 0;
}
