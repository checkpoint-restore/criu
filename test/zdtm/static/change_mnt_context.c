#include <sys/mount.h>
#include <sys/stat.h>

#include "zdtmtst.h"
#include "mountinfo.h"

const char *test_doc = "Check that mounts can change LSM context on restore";
const char *test_author = "Adrian Reber <areber@redhat.com>";

char *source = "change_mount_context.test";
char *original_context = "context=\"system_u:object_r:container_file_t:s0:c82,c137\"";
char *new_context = "context=\"system_u:object_r:container_file_t:s0:c204,c495\"";

int main(int argc, char **argv)
{
	char *dname = "/tmp/change_mount_context.XXXXXX";
	struct mountinfo_zdtm *mi;
	MNTNS_ZDTM(mntns);
	int ret = -1;

	mkdir(dname, 755);
	if (mount(source, dname, "tmpfs", 0, original_context)) {
		pr_perror("mount");
		return 1;
	}

	test_init(argc, argv);

	test_daemon();
	test_waitsig();

	if (mntns_parse_mountinfo(&mntns)) {
		fail("Can't parse mountinfo");
		goto out;
	}

	list_for_each_entry(mi, &mntns.mountinfo_list, list) {
		if (strcmp(mi->source, source))
			continue;

		if (strstr(mi->super_opts, new_context))
			ret = 0;
		else
			fail("Not re-mounted with new context");
	}

	if (ret == 0)
		pass();
out:
	mntns_free_all(&mntns);
	umount(dname);
	return ret;
}
