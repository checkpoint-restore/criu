#include <errno.h>
#include <unistd.h>
#include <sys/mount.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that clean mntns works";
const char *test_author	= "Pavel Emelianov <xemul@parallels.com>";

int main(int argc, char **argv)
{
	test_init(argc, argv);

	if (umount("/proc") < 0)
		err("Can't umount proc\n");

	if (umount("/dev/pts") < 0)
		err("Can't umount devpts\n");

	test_daemon();
	test_waitsig();

	pass();
	return 0;
}
