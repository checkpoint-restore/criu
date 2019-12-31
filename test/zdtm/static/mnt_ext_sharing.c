#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>

#include "zdtmtst.h"
#include "lock.h"

const char *test_doc = "Check sharing vs external mounts vs mntns";
const char *test_author = "Pavel Tikhomirov <ptikhomirov@virtuozzo.com>";

char *dirname = "mnt_ext_sharing.test";
char *source = "zdtm_ext_sharing";
char *internal_source = "zdtm_ext_sharing.internal";
#define SUBDIR "subdir"
TEST_OPTION(dirname, string, "directory name", 1);

enum {
	TEST_START,
	TEST_STARTED,
	TEST_EXIT,
	TEST_EXITED,
};

struct shared {
	futex_t fstate;
	int ret;
};

struct shared *sh;

#define BUF_SIZE 4096

int pid_mntinfo_get_shid(char *pid, char *source)
{
	char path[PATH_MAX], line[BUF_SIZE];
	FILE *mountinfo;
	char *hyphen, *shared;
	int ret = -1;

	sprintf(path, "/proc/%s/mountinfo", pid);
	mountinfo = fopen(path, "r");
	if (!mountinfo) {
		pr_perror("fopen");
		return ret;
	}

	while (fgets(line, sizeof(line), mountinfo)) {
		hyphen = strchr(line, '-');
		if (!hyphen) {
			pr_perror("no hyphen in mountinfo");
			break;
		}

		if (!strstr(hyphen + 1, source))
			continue;

		shared = strstr(line, "shared:");
		if (!shared) {
			pr_err("no shared id\n");
			break;
		}

		ret = atoi(shared + 7);
		break;
	}

	fclose(mountinfo);
	return ret;
}

int secondary_mntns_child(void)
{
	if (unshare(CLONE_NEWNS)) {
		pr_perror("unshare");
		sh->ret = 1;
		futex_abort_and_wake(&sh->fstate);
		return 1;
	}
	futex_set_and_wake(&sh->fstate, TEST_STARTED);
	futex_wait_until(&sh->fstate, TEST_EXIT);
	/* These task is just holding the reference to secondary mntns */
	futex_set_and_wake(&sh->fstate, TEST_EXITED);
	return 0;
}

int main(int argc, char **argv)
{
	char *root, testdir[PATH_MAX], spid[BUF_SIZE];
	char internal_dst[PATH_MAX], internal_src[PATH_MAX], internal_nsdst[PATH_MAX];
	int internal_shid_self = -1, internal_shid_pid = -1;
	char *tmp = "/tmp/zdtm_ext_sharing.tmp";
	char *zdtm_newns = getenv("ZDTM_NEWNS");
	int pid, status;

	root = getenv("ZDTM_ROOT");
	if (root == NULL) {
		pr_perror("root");
		return 1;
	}

	if (!zdtm_newns) {
		pr_perror("ZDTM_NEWNS is not set");
		return 1;
	} else if (strcmp(zdtm_newns, "1")) {
		goto test;
	}

	/* Prepare directories in test root */
	sprintf(testdir, "%s/%s", root, dirname);
	mkdir(testdir, 0755);

	sprintf(internal_dst, "%s/%s/internal", root, dirname);
	mkdir(internal_dst, 0755);

	/* Prepare directories in criu root */
	mkdir(tmp, 0755);
	if (mount(source, tmp, "tmpfs", 0, NULL)) {
		pr_perror("mount tmpfs");
		return 1;
	}
	if (mount(NULL, tmp, NULL, MS_PRIVATE, NULL)) {
		pr_perror("make private");
		return 1;
	}

	sprintf(internal_src, "%s/internal", tmp);
	mkdir(internal_src, 0755);

	/* Create a shared mount in criu mntns */
	if (mount(internal_source, internal_src, "tmpfs", 0, NULL)) {
		pr_perror("mount tmpfs");
		return 1;
	}
	if (mount(NULL, internal_src, NULL, MS_PRIVATE, NULL)) {
		pr_perror("make private");
		return 1;
	}

	if (mount(NULL, internal_src, NULL, MS_SHARED, NULL)) {
		pr_perror("make shared");
		return 1;
	}

	/*
	 * Create temporary mntns, next mounts will not show up in criu mntns
	 */
	if (unshare(CLONE_NEWNS)) {
		pr_perror("unshare");
		return 1;
	}

	/*
	 * Populate to the tests root only a subdirectory of the internal_src
	 * mount to ensure that it will be restored as an external mount.
	 */
	sprintf(internal_src, "%s/internal/%s", tmp, SUBDIR);
	mkdir(internal_src, 0755);
	if (mount(internal_src, internal_dst, NULL, MS_BIND, NULL)) {
		pr_perror("bind");
		return 1;
	}

test:
	test_init(argc, argv);

	sh = mmap(NULL, sizeof(struct shared), PROT_WRITE | PROT_READ, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (sh == MAP_FAILED) {
		pr_perror("Failed to alloc shared region");
		exit(1);
	}

	futex_set(&sh->fstate, TEST_START);
	sh->ret = 0;

	sprintf(internal_nsdst, "/%s/internal", dirname);
	/* Make "external" mount to have internal sharing */
	if (mount(NULL, internal_nsdst, NULL, MS_PRIVATE, NULL)) {
		pr_perror("make shared");
		return 1;
	}

	if (mount(NULL, internal_nsdst, NULL, MS_SHARED, NULL)) {
		pr_perror("make shared");
		return 1;
	}

	/* Create secondary mntns copying all mounts */
	pid = fork();
	if (pid < 0) {
		pr_perror("fork");
		return 1;
	} else if (pid == 0) {
		exit(secondary_mntns_child());
	}

	futex_wait_until(&sh->fstate, TEST_STARTED);
	if (sh->ret != 0) {
		pr_err("error in child\n");
		return 1;
	}

	test_daemon();
	test_waitsig();

	/*
	 * Check mounts in primary and secondary
	 * mntnses are shared to each other.
	 */
	sprintf(spid, "%d", pid);
	internal_shid_pid = pid_mntinfo_get_shid(spid, internal_source);
	internal_shid_self = pid_mntinfo_get_shid("self", internal_source);

	/* Cleanup */
	futex_set_and_wake(&sh->fstate, TEST_EXIT);
	futex_wait_until(&sh->fstate, TEST_EXITED);

	while (wait(&status) > 0) {
		if (!WIFEXITED(status) || WEXITSTATUS(status)) {
			fail("Wrong exit status: %d", status);
			return 1;
		}
	}

	if (internal_shid_pid == -1 || internal_shid_self == -1 || internal_shid_pid != internal_shid_self) {
		fail("Shared ids does not match (internal)");
		return 1;
	}

	/* Print shared id so that it can be checked in cleanup hook */
	test_msg("internal_shared_id = %d\n", internal_shid_pid);
	pass();

	return 0;
}
