
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <limits.h>
#include <fcntl.h>

#include "zdtmtst.h"

const char *test_doc	= "Test unix stream sockets\n";
const char *test_author	= "Cyrill Gorcunov <gorcunov@openvz.org";

#define SK_DATA "packet"

char *filename;
TEST_OPTION(filename, string, "socket file name", 1);

#define TEST_MODE 0640

int main(int argc, char *argv[])
{
	int ssk_icon[4];
	struct sockaddr_un addr;
	unsigned int addrlen;

	struct stat st_b, st_a;
	char path[PATH_MAX];
	char buf[64];
	char *cwd;
	uid_t uid = 18943;
	gid_t gid = 58467;

	int ret;

	test_init(argc, argv);

	cwd = get_current_dir_name();
	if (!cwd) {
		fail("getcwd\n");
		exit(1);
	}

	snprintf(path, sizeof(path), "%s/%s", cwd, filename);
	unlink(path);

	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path));
	addrlen = sizeof(addr.sun_family) + strlen(path);

	ssk_icon[0] = socket(AF_UNIX, SOCK_STREAM, 0);
	ssk_icon[1] = socket(AF_UNIX, SOCK_STREAM, 0);
	ssk_icon[2] = socket(AF_UNIX, SOCK_STREAM, 0);
	if (ssk_icon[0] < 0 || ssk_icon[1] < 0 || ssk_icon[2] < 0) {
		fail("socket\n");
		exit(1);
	}

	ret = bind(ssk_icon[0], (struct sockaddr *) &addr, addrlen);
	if (ret) {
		fail("bind\n");
		exit(1);
	}

	ret = chmod(path, TEST_MODE);
	if (ret) {
		pr_perror("chmod");
		exit(1);
	}

	ret = chown(path, uid, gid);
	if (ret) {
		pr_perror("chown");
		exit(1);
	}

	ret = listen(ssk_icon[0], 16);
	if (ret) {
		fail("bind\n");
		exit(1);
	}

	ret = connect(ssk_icon[2], (struct sockaddr *) &addr, addrlen);
	if (ret) {
		fail("connect\n");
		exit(1);
	}

	ssk_icon[3] = accept(ssk_icon[0], NULL, NULL);
	if (ssk_icon[3] < 0) {
		fail("accept");
		exit(1);
	}

	ret = connect(ssk_icon[1], (struct sockaddr *) &addr, addrlen);
	if (ret) {
		fail("connect\n");
		exit(1);
	}

	ret = stat(path, &st_b);
	if (ret) {
		fail("stat");
		exit(1);
	}

	test_daemon();
	test_waitsig();

	ret = stat(path, &st_a);
	if (ret) {
		fail("stat");
		exit(1);
	}

	if (st_b.st_mode != st_a.st_mode) {
		fail("The file permissions for %s were changed %o %o\n",
					path, st_b.st_mode, st_a.st_mode);
		exit(1);
	}

	if (st_b.st_uid != uid || st_b.st_gid != gid) {
		fail("Owner user or group for %s corrupted, uid=%d, gid=%d",
		    path, st_b.st_uid, st_b.st_gid);
		exit(1);
	}

	ret = accept(ssk_icon[0], NULL, NULL);
	if (ret < 0) {
		fail("accept\n");
		exit(1);
	}

	memset(buf, 0, sizeof(buf));
	write(ssk_icon[1], SK_DATA, sizeof(SK_DATA));
	read(ret, &buf, sizeof(buf));
	if (strcmp(buf, SK_DATA)) {
		fail("data corrupted\n");
		exit(1);
	}
	test_msg("stream1           : '%s'\n", buf);

	memset(buf, 0, sizeof(buf));
	write(ssk_icon[2], SK_DATA, sizeof(SK_DATA));
	read(ssk_icon[3], &buf, sizeof(buf));
	if (strcmp(buf, SK_DATA)) {
		fail("data corrupted\n");
		exit(1);
	}
	test_msg("stream2           : '%s'\n", buf);

	pass();
	return 0;
}
