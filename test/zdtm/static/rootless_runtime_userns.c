#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc = "Check rootless restore into a runtime-provided user namespace";
const char *test_author = "Deepak Anand <deepakanand1300@gmail.com>";

static int noninitial_userns(void)
{
	unsigned long ns_id, parent_id, count;
	FILE *map;
	int ret;

	map = fopen("/proc/self/uid_map", "r");
	if (!map) {
		fail("Can't open uid_map");
		return -1;
	}

	ret = fscanf(map, "%lu %lu %lu", &ns_id, &parent_id, &count);
	fclose(map);
	if (ret != 3) {
		fail("Can't parse uid_map");
		return -1;
	}

	return !(ns_id == 0 && parent_id == 0 && count == 4294967295UL);
}

int main(int argc, char **argv)
{
	uid_t ruid, euid, suid, ruid_after, euid_after, suid_after;
	gid_t rgid, egid, sgid, rgid_after, egid_after, sgid_after;

	test_init(argc, argv);

	if (noninitial_userns() <= 0)
		return 1;

	if (getresuid(&ruid, &euid, &suid)) {
		fail("Can't get uid set");
		return 1;
	}

	if (getresgid(&rgid, &egid, &sgid)) {
		fail("Can't get gid set");
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (noninitial_userns() <= 0)
		return 1;

	if (getresuid(&ruid_after, &euid_after, &suid_after)) {
		fail("Can't get restored uid set");
		return 1;
	}

	if (getresgid(&rgid_after, &egid_after, &sgid_after)) {
		fail("Can't get restored gid set");
		return 1;
	}

	if (ruid != ruid_after || euid != euid_after || suid != suid_after) {
		fail("UIDs changed across restore: %u/%u/%u -> %u/%u/%u",
		     (unsigned int)ruid, (unsigned int)euid, (unsigned int)suid,
		     (unsigned int)ruid_after, (unsigned int)euid_after,
		     (unsigned int)suid_after);
		return 1;
	}

	if (rgid != rgid_after || egid != egid_after || sgid != sgid_after) {
		fail("GIDs changed across restore: %u/%u/%u -> %u/%u/%u",
		     (unsigned int)rgid, (unsigned int)egid, (unsigned int)sgid,
		     (unsigned int)rgid_after, (unsigned int)egid_after,
		     (unsigned int)sgid_after);
		return 1;
	}

	pass();
	return 0;
}
