#include <errno.h>
#include <unistd.h>
#include <sys/mount.h>

#include "zdtmtst.h"

const char *test_doc = "Check that clean mntns works";
const char *test_author = "Pavel Emelianov <xemul@parallels.com>";

int main(int argc, char **argv)
{
	test_init(argc, argv);

	if (umount("/proc") < 0)
		pr_perror("Can't umount proc");

	if (umount("/dev/pts") < 0)
		pr_perror("Can't umount devpts");

	test_daemon();
	test_waitsig();

	pass();
	return 0;
}
