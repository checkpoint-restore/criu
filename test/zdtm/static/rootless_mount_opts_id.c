#include <stdio.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc = "Check subordinate uid=/gid= mount option fixup across userns C/R";
const char *test_author = "Deepak Anand <deepakanand1300@gmail.com>";

#define TEST_DIR_PREFIX	"rootless_mount_opts_id.test"
#define MAX_EXTENTS	16
#define MAX_CASES	8

struct id_extent {
	unsigned int first;
	unsigned int lower_first;
	unsigned int count;
};

struct test_case {
	unsigned int uid;
	unsigned int gid;
	char dir[64];
	int mounted;
};

static int parse_id_map(const char *path, struct id_extent *extents, int max,
			int *n)
{
	FILE *f;
	int i = 0;

	f = fopen(path, "r");
	if (!f) {
		pr_perror("fopen %s", path);
		return -1;
	}

	while (i < max &&
	       fscanf(f, "%u %u %u", &extents[i].first,
		      &extents[i].lower_first, &extents[i].count) == 3)
		i++;
	fclose(f);
	*n = i;
	return 0;
}

/*
 * Collect ids from every subordinate extent (count > 1).  Each such id
 * is written into mountinfo as a host-subordinate value that must be
 * translated back through the image userns maps on restore.
 */
static int collect_subordinate_ids(struct id_extent *extents, int n,
				   unsigned int *ids, int max_ids)
{
	int i, out = 0;

	for (i = 0; i < n && out < max_ids; i++) {
		if (extents[i].count > 1)
			ids[out++] = extents[i].first + 1;
	}
	return out;
}

static void cleanup_cases(struct test_case *cases, int n)
{
	int i;

	for (i = 0; i < n; i++) {
		if (cases[i].mounted)
			umount(cases[i].dir);
		if (cases[i].dir[0])
			rmdir(cases[i].dir);
	}
}

int main(int argc, char **argv)
{
	struct id_extent uid_map[MAX_EXTENTS], gid_map[MAX_EXTENTS];
	unsigned int uids[MAX_EXTENTS], gids[MAX_EXTENTS];
	int n_uid, n_gid, n_uid_sub, n_gid_sub, nc;
	struct test_case cases[MAX_CASES] = {};
	struct stat st;
	int i, ret = 1;

	test_init(argc, argv);

	if (parse_id_map("/proc/self/uid_map", uid_map, MAX_EXTENTS, &n_uid))
		return 1;
	if (parse_id_map("/proc/self/gid_map", gid_map, MAX_EXTENTS, &n_gid))
		return 1;

	n_uid_sub = collect_subordinate_ids(uid_map, n_uid, uids, MAX_EXTENTS);
	n_gid_sub = collect_subordinate_ids(gid_map, n_gid, gids, MAX_EXTENTS);

	if (n_uid_sub == 0 || n_gid_sub == 0) {
		test_daemon();
		test_waitsig();
		skip("No subordinate uid/gid extent in /proc/self/*_map");
		pass();
		return 0;
	}

	nc = n_uid_sub < n_gid_sub ? n_uid_sub : n_gid_sub;
	if (nc > MAX_CASES)
		nc = MAX_CASES;

	for (i = 0; i < nc; i++) {
		struct test_case *c = &cases[i];

		c->uid = uids[i];
		c->gid = gids[i];
		c->mounted = 0;
		snprintf(c->dir, sizeof(c->dir), "%s%d", TEST_DIR_PREFIX, i);

		if (mkdir(c->dir, 0755) < 0) {
			pr_perror("mkdir %s", c->dir);
			goto out;
		}

		{
			char opt[128];

			snprintf(opt, sizeof(opt), "uid=%u,gid=%u,mode=0755",
				 c->uid, c->gid);
			if (mount("none", c->dir, "tmpfs", 0, opt) < 0) {
				pr_perror("mount %s", c->dir);
				goto out;
			}
		}
		c->mounted = 1;

		if (stat(c->dir, &st) < 0) {
			pr_perror("stat %s", c->dir);
			goto out;
		}

		if (st.st_uid != c->uid || st.st_gid != c->gid) {
			fail("Before C/R [%d]: expected %u:%u, got %u:%u",
			     i, c->uid, c->gid, st.st_uid, st.st_gid);
			goto out;
		}

		test_msg("case %d: uid=%u gid=%u\n", i, c->uid, c->gid);
	}

	test_daemon();
	test_waitsig();

	for (i = 0; i < nc; i++) {
		struct test_case *c = &cases[i];

		if (stat(c->dir, &st) < 0) {
			pr_perror("stat %s", c->dir);
			goto out;
		}

		if (st.st_uid != c->uid || st.st_gid != c->gid) {
			fail("After C/R [%d]: expected %u:%u, got %u:%u",
			     i, c->uid, c->gid, st.st_uid, st.st_gid);
			goto out;
		}
	}

	pass();
	ret = 0;

out:
	cleanup_cases(cases, nc);
	return ret;
}
