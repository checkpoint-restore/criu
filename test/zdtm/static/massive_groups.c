#include <grp.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

#include "zdtmtst.h"

const char *test_doc = "Test dumping a process with many supplementary groups (Trigger bfd dynamic expansion)";
const char *test_author = "DongSunchao";

/*
 * _SC_NGROUPS_MAX beyond parasite's maximum supported groups, so we use a hardcoded value.
 * Use 900 groups: enough to test the "Groups:" line in /proc/pid/status
 * and triggering dynamic expansion,
 * but still within the PARASITE_MAX_GROUPS limit (~900).
 * So we use the larger value to set GID and test the dynamic expansion of BFD buffer when dumping the process.
 */
#define TEST_NGROUPS 900

int main(int argc, char **argv)
{
	gid_t *group;
	gid_t *restored_groups;
	int i, ngroups;
	int restored_ngroups;

	test_init(argc, argv);

	ngroups = TEST_NGROUPS;

	group = malloc(ngroups * sizeof(gid_t));
	if (!group) {
		pr_perror("Failed to allocate memory for group IDs");
		return 1;
	}

	/*
	 * Fill the group array with large and unique group IDs to reach the maximum limit.
	 * This will trigger the multiple dynamic expansion of the BFD buffer when dumping
	 * the process.
	 */
	for (i = 0; i < ngroups; i++)
		group[i] = i + 1000000000;

	if (setgroups(ngroups, group) < 0) {
		pr_perror("Failed to set supplementary groups");
		free(group);
		return 1;
	}

	test_daemon();

	test_waitsig();

	restored_ngroups = getgroups(0, NULL);
	if (restored_ngroups < 0) {
		pr_perror("Failed to get number of supplementary groups");
		free(group);
		return 1;
	}

	if (restored_ngroups != ngroups) {
		fail("Restored number of supplementary groups (%d) does not match expected (%d)", restored_ngroups, ngroups);
		free(group);
		return 1;
	}

	restored_groups = malloc(restored_ngroups * sizeof(gid_t));

	if (!restored_groups) {
		pr_perror("Failed to allocate memory for restored group IDs");
		free(group);
		return 1;
	}

	if (getgroups(restored_ngroups, restored_groups) < 0) {
		pr_perror("Failed to get supplementary groups");
		free(restored_groups);
		free(group);
		return 1;
	}

	for (i = 0; i < ngroups; i++) {
		if (restored_groups[i] != group[i]) {
			fail("Restored group ID at index %d (%u) does not match expected (%u)", i, (unsigned int)restored_groups[i], (unsigned int)group[i]);
			free(restored_groups);
			free(group);
			return 1;
		}
	}

	free(restored_groups);
	free(group);
	pass();
	return 0;
}
