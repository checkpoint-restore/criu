#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include "zdtmtst.h"

const char *test_doc = "Check that cgroups are correctly ignored";
const char *test_author = "Adrian Reber <areber@redhat.com>";

char *dirname;
TEST_OPTION(dirname, string, "cgroup directory name", 1);
static const char *cgname = "zdtmtst";

static size_t read_all(int fd, char *buf, size_t size)
{
	ssize_t r = 0, ret;

	while (r < size) {
		ret = read(fd, buf + r, size - r);
		if (ret < 0) {
			pr_perror("Read failed");
			return -1;
		} else if (ret == 0) {
			return 0;
		}
		r += ret;
	}

	return 0;
}

int main(int argc, char **argv)
{
	cleanup_free char *cgroup_procs = NULL;
	cleanup_close int cgroup_procs_fd = -1;
	cleanup_free char *destination = NULL;
	cleanup_free char *buffer_old = NULL;
	cleanup_free char *buffer_new = NULL;
	cleanup_close int fd = -1;
	int ret = 1;

	test_init(argc, argv);

	buffer_old = malloc(PAGE_SIZE);
	if (!buffer_old) {
		pr_err("Could not allocate memory\n");
		return 1;
	}
	memset(buffer_old, 0, PAGE_SIZE);
	buffer_new = malloc(PAGE_SIZE);
	if (!buffer_new) {
		pr_err("Could not allocate memory\n");
		return 1;
	}
	memset(buffer_new, 0, PAGE_SIZE);

	// Read /proc/self/cgroup to later compare against it
	fd = open("/proc/self/cgroup", O_RDONLY);
	if (fd < 0) {
		pr_err("Could not open /proc/self/cgroup\n");
		return 1;
	}

	if (read_all(fd, buffer_old, PAGE_SIZE)) {
		pr_err("Could not read data from /proc/self/cgroup\n");
		return 1;
	}

	// Create the cgroup root directory
	if (mkdir(dirname, 0700) < 0 && errno != EEXIST) {
		pr_err("Cannot make directory %s\n", dirname);
		return 1;
	}

	// Mount cgroup2, skip if cgroup2 is not available
	if (mount("none", dirname, "cgroup2", 0, 0)) {
		if (errno == ENODEV) {
			skip("Test relies on cgroup2 semantics which this system does not support. Skipping");
			test_daemon();
			test_waitsig();
			pass();
			return 0;
		} else {
			pr_err("Could not mount cgroup2 at %s\n", dirname);
		}
		return 1;
	}

	// Create the cgroup cgname (if it does not already exist)
	if (asprintf(&destination, "%s/%s", dirname, cgname) == -1) {
		pr_err("Could not allocate memory\n");
		goto err;
	}
	if (mkdir(destination, 0700) < 0 && errno != EEXIST) {
		pr_err("Failed to create temporary cgroup directory %s\n", destination);
		goto err;
	}

	// Move this process to the newly created cgroup
	if (asprintf(&cgroup_procs, "%s/cgroup.procs", destination) == -1) {
		pr_err("Could not allocate memory\n");
		goto err;
	}
	cgroup_procs_fd = open(cgroup_procs, O_RDWR);
	if (cgroup_procs_fd < 0) {
		pr_err("Could not open %s\n", cgroup_procs);
		goto err;
	}
	if (write(cgroup_procs_fd, "0", 1) != 1) {
		pr_err("Writing to %s failed\n", cgroup_procs);
		goto err;
	}

	// Read /proc/self/cgroup (should have changed)
	lseek(fd, 0, SEEK_SET);
	if (read_all(fd, buffer_new, PAGE_SIZE)) {
		pr_err("Could not read data from /proc/self/cgroup\n");
		goto err;
	}

	// Test if /proc/self/cgroup has changed
	if (!memcmp(buffer_new, buffer_old, PAGE_SIZE)) {
		fail("/proc/self/cgroup should differ after move to another cgroup");
		pr_err("original /proc/self/cgroup content %s\n", buffer_old);
		pr_err("new /proc/self/cgroup content %s\n", buffer_new);
		goto err;
	}

	test_daemon();
	test_waitsig();

	// Read /proc/self/cgroup. It should not be the same as after
	// moving this process to another cgroup because of restore
	// with '--manage-cgroups=ignore'. The process should be
	// now in cgroup of the current session.
	lseek(fd, 0, SEEK_SET);
	memset(buffer_old, 0, PAGE_SIZE);
	if (read_all(fd, buffer_old, PAGE_SIZE)) {
		pr_err("Could not read data from /proc/self/cgroup\n");
		goto err;
	}

	// Test if /proc/self/cgroup has changed again
	if (!memcmp(buffer_new, buffer_old, PAGE_SIZE)) {
		fail("/proc/self/cgroup should differ after restore");
		pr_err("original /proc/self/cgroup content %s\n", buffer_new);
		pr_err("new /proc/self/cgroup content %s\n", buffer_old);
		goto err;
	}

	ret = 0;
	pass();
err:
	rmdir(destination);
	umount(dirname);

	return ret;
}
