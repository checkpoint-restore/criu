#include <fcntl.h>
#include <stdint.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
#include <asm/types.h>

#include "zdtmtst.h"

const char *test_doc = "Check C/R of fds to files, directories on an unmounted bind mount";
const char *test_author = "Bhavik Sachdev <b.sachdev1904@gmail.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

#define MOUNT_POINT "mnt"
#define SUBDIR	    "mnt/dir"
#define FILE	    "mnt/file"
#define BIND_SUBDIR "bind_subdir"
#define BIND_FILE   "bind_file"

#define BUFLEN 1000

struct _mnt_id_req {
	__u32 size;
	union {
		__u32 mnt_ns_fd;
		__u32 mnt_fd;
	};
	__u64 mnt_id;
	__u64 param;
	__u64 mnt_ns_id;
};

struct _statmount {
	__u32 size;
	__u32 mnt_opts;
	__u64 mask;
	__u32 sb_dev_major;
	__u32 sb_dev_minor;
	__u64 sb_magic;
	__u32 sb_flags;
	__u32 fs_type;
	__u64 mnt_id;
	__u64 mnt_parent_id;
	__u32 mnt_id_old;
	__u32 mnt_parent_id_old;
	__u64 mnt_attr;
	__u64 mnt_propagation;
	__u64 mnt_peer_group;
	__u64 mnt_master;
	__u64 propagate_from;
	__u32 mnt_root;
	__u32 mnt_point;
	__u64 mnt_ns_id;
	__u32 fs_subtype;
	__u32 sb_source;
	__u32 opt_num;
	__u32 opt_array;
	__u32 opt_sec_num;
	__u32 opt_sec_array;
	__u64 supported_mask;
	__u32 mnt_uidmap_num;
	__u32 mnt_uidmap;
	__u32 mnt_gidmap_num;
	__u32 mnt_gidmap;
	__u64 __spare2[43];
	char str[];
};

#ifndef STATMOUNT_MNT_BASIC
#define STATMOUNT_MNT_BASIC 0x00000002U
#endif

#ifndef STATMOUNT_BY_FD
#define STATMOUNT_BY_FD 0x00000001U
#endif

#ifndef __NR_statmount
#define __NR_statmount 457
#endif

static int sys_statmount(struct _mnt_id_req *req, struct _statmount *smbuf,
			 size_t bufsize, unsigned int flags)
{
	return syscall(__NR_statmount, req, smbuf, bufsize, flags);
}

static int check_statmount_by_fd(void)
{
	struct _mnt_id_req req = {
		.size = sizeof(req),
		.mnt_fd = STDIN_FILENO,
		.param = STATMOUNT_MNT_BASIC
	};
	struct _statmount smbuf = {};
	int ret;

	ret = sys_statmount(&req, &smbuf, sizeof(smbuf), STATMOUNT_BY_FD);
	if (ret < 0) {
		if (errno == ENOSYS)
			return 0;
		if (errno == EINVAL)
			return 0;
		return -1;
	}
	return 1;
}

static int create_dir_and_file(uint32_t *crc)
{
	uint8_t buf[BUFLEN];
	int fd;

	if (mkdir(SUBDIR, 0700)) {
		pr_perror("mkdir %s", SUBDIR);
		return -1;
	}
	fd = open(FILE, O_CREAT | O_RDWR, 0644);
	if (fd < 0) {
		pr_perror("open %s", FILE);
		return -1;
	}
	datagen(buf, BUFLEN, crc);
	if (write(fd, buf, BUFLEN) != BUFLEN) {
		pr_perror("write %s", FILE);
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

static int create_bind_paths(void)
{
	int fd;

	if (mkdir(BIND_SUBDIR, 0700)) {
		pr_perror("mkdir %s", BIND_SUBDIR);
		return -1;
	}
	fd = creat(BIND_FILE, 0644);
	if (fd < 0) {
		pr_perror("creat %s", BIND_FILE);
		return -1;
	}
	close(fd);
	return 0;
}

static int create_bind_mounts(void)
{
	if (mount(SUBDIR, BIND_SUBDIR, NULL, MS_BIND, NULL)) {
		pr_perror("bind mount %s", BIND_SUBDIR);
		return -1;
	}
	if (mount(FILE, BIND_FILE, NULL, MS_BIND, NULL)) {
		pr_perror("bind mount %s", BIND_FILE);
		umount(BIND_SUBDIR);
		return -1;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	uint8_t buf[BUFLEN];
	uint32_t crc = ~0;
	int bind_file_fd = -1, bind_subdir_fd = -1, ret = 1;
	struct stat st;

	/* bind mount will be unmounted */
	test_init(argc, argv);

	ret = check_statmount_by_fd();
	if (ret < 0)
		return 1;

	if (ret == 0) {
		test_daemon();
		test_waitsig();
		skip("Test requires statmount() with STATMOUNT_BY_FD. skipping...");
		pass();
		return 0;
	}

	ret = 1;
	if (mkdir(dirname, 0700)) {
		pr_perror("mkdir %s", dirname);
		return 1;
	}

	if (chdir(dirname)) {
		pr_perror("chdir %s", dirname);
		return 1;
	}

	if (mkdir(MOUNT_POINT, 0700)) {
		pr_perror("mkdir %s", MOUNT_POINT);
		return 1;
	}

	if (mount("none", MOUNT_POINT, "tmpfs", 0, NULL)) {
		pr_perror("mount %s", MOUNT_POINT);
		return 1;
	}

	if (create_dir_and_file(&crc))
		goto cleanup;

	if (create_bind_paths())
		goto cleanup;

	if (create_bind_mounts())
		goto cleanup;

	bind_subdir_fd = open(BIND_SUBDIR, O_DIRECTORY);
	if (bind_subdir_fd < 0) {
		pr_perror("open %s", BIND_SUBDIR);
		goto cleanup;
	}

	bind_file_fd = open(BIND_FILE, O_RDWR);
	if (bind_file_fd < 0) {
		pr_perror("open %s", BIND_FILE);
		goto cleanup;
	}

	/* unmount with MNT_DETACH */
	if (umount2(BIND_SUBDIR, MNT_DETACH)) {
		pr_perror("umount2 %s", BIND_SUBDIR);
		goto cleanup;
	}

	if (umount2(BIND_FILE, MNT_DETACH)) {
		pr_perror("umount2 %s", BIND_FILE);
		goto cleanup;
	}

	test_daemon();
	test_waitsig();

	if (read(bind_file_fd, buf, BUFLEN) != BUFLEN) {
		pr_perror("read %s", BIND_FILE);
		ret = 1;
		goto cleanup;
	}

	crc = ~0;
	if (datachk(buf, BUFLEN, &crc)) {
		fail("Data mismatch");
		goto cleanup;
	}

	if (fstat(bind_subdir_fd, &st)) {
		fail("could not stat bind dir fd");
		goto cleanup;
	}

	if (S_ISDIR(st.st_mode)) {
		ret = 0;
		pass();
	} else {
		fail("bind subdir is not a directory");
	}
cleanup:
	umount(MOUNT_POINT);
	chdir("..");
	if (bind_subdir_fd > 0)
		close(bind_subdir_fd);
	if (bind_file_fd > 0)
		close(bind_file_fd);
	return ret;
}
