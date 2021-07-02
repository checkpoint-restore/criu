#include <sys/mount.h>
#include <sys/stat.h>

#include "zdtmtst.h"

const char *test_doc = "Check that mounts can change LSM context on restore";
const char *test_author = "Adrian Reber <areber@redhat.com>";

char *source = "change_mount_context.test";
char *original_context = "context=\"system_u:object_r:container_file_t:s0:c82,c137\"";
char *new_context = "context=\"system_u:object_r:container_file_t:s0:c204,c495\"";

int main(int argc, char **argv)
{
	char *dname = "/tmp/change_mount_context.XXXXXX";
	char line[1024];
	char opts[1024];
	int ret = -1;
	FILE *mi;

	mkdir(dname, 755);
	if (mount(source, dname, "tmpfs", 0, original_context)) {
		pr_perror("mount");
		return 1;
	}

	test_init(argc, argv);

	test_daemon();
	test_waitsig();

	mi = fopen("/proc/self/mountinfo", "r");
	if (mi == NULL) {
		fail("No mountinfo file");
		goto out;
	}

	while (fgets(line, sizeof(line), mi)) {
		int result;
		char *pos;

		if (!strstr(line, source))
			continue;

		pos = strstr(line, " - ");
		if (!pos)
			continue;

		result = sscanf(pos, " - %*s %*s %s", opts);
		if (result != 1) {
			fail("Not able to sscanf line from mountinfo");
			goto out;
		}
		if (strstr(opts, new_context))
			ret = 0;
		else
			fail("Not re-mounted with new context");
	}

	if (ret == 0)
		pass();
out:
	umount(dname);
	return ret;
}
