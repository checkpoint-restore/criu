#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/limits.h>
#include <errno.h>

#include "zdtmtst.h"

const char *test_doc = "Check UNIX socket ownership is preserved/handled after C/R";
const char *test_author = "Apurve Karanwal <karanwalapurve@gmail.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

#define TEST_STRING "Hello UNIX socket owner"

int main(int argc, char **argv)
{
	int listen_fd = -1, client_fd = -1, accept_fd = -1;
	struct sockaddr_un addr;
	char filename[PATH_MAX];
	struct stat st_before, st_after;
	uid_t expected_uid;
	gid_t expected_gid;
	char buf[sizeof(TEST_STRING)];
	int ret;

	test_init(argc, argv);

	if (mkdir(dirname, 0755) < 0 && errno != EEXIST) {
		pr_perror("Can't create %s", dirname);
		return 1;
	}

	snprintf(filename, sizeof(filename), "%s/sk_unix_owner.sock", dirname);

	if (unix_fill_sock_name(&addr, filename))
		return 1;

	listen_fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (listen_fd < 0) {
		pr_perror("socket() failed");
		return 1;
	}

	unlink(addr.sun_path);

	if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		pr_perror("bind() failed");
		close(listen_fd);
		return 1;
	}

	if (listen(listen_fd, 5) < 0) {
		pr_perror("listen() failed");
		close(listen_fd);
		return 1;
	}

	/*
	 * If running as root, change socket file ownership to test that uid/gid
	 * are properly saved and restored across C/R. Otherwise, just
	 * verify the current ownership is preserved.
	 */
	if (getuid() == 0) {
		expected_uid = 13333;
		expected_gid = 44444;
		if (chown(addr.sun_path, expected_uid, expected_gid)) {
			pr_perror("chown() failed");
			close(listen_fd);
			return 1;
		}
	} else {
		expected_uid = getuid();
		expected_gid = getgid();
	}

	/* Record ownership before C/R */
	if (stat(addr.sun_path, &st_before)) {
		pr_perror("stat() failed before C/R");
		close(listen_fd);
		return 1;
	}

	test_daemon();
	test_waitsig();

	/* Verify ownership after C/R */
	if (stat(addr.sun_path, &st_after)) {
		pr_perror("stat() failed after C/R");
		close(listen_fd);
		return 1;
	}

	/*
	 * If we run as root, we expect the ownership to be preserved.
	 * In unprivileged mode, we might not have CAP_CHOWN to restore the
	 * ownership to 13333:44444. So we only check for mismatch if getuid() == 0.
	 */
	if (getuid() == 0) {
		if (st_after.st_uid != expected_uid || st_after.st_gid != expected_gid) {
			fail("UID/GID mismatch (got %d/%d but %d/%d expected)",
			     (int)st_after.st_uid, (int)st_after.st_gid,
			     (int)expected_uid, (int)expected_gid);
			close(listen_fd);
			return 1;
		}
	}

	/* Verify the socket still works by connecting and exchanging data */
	client_fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (client_fd < 0) {
		pr_perror("client socket() failed");
		close(listen_fd);
		return 1;
	}

	if (connect(client_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		pr_perror("connect() failed");
		close(client_fd);
		close(listen_fd);
		return 1;
	}

	accept_fd = accept(listen_fd, NULL, NULL);
	if (accept_fd < 0) {
		pr_perror("accept() failed");
		close(client_fd);
		close(listen_fd);
		return 1;
	}

	ret = write(client_fd, TEST_STRING, sizeof(TEST_STRING));
	if (ret != sizeof(TEST_STRING)) {
		pr_perror("write() failed");
		close(accept_fd);
		close(client_fd);
		close(listen_fd);
		return 1;
	}

	ret = read(accept_fd, buf, sizeof(TEST_STRING));
	if (ret != sizeof(TEST_STRING)) {
		pr_perror("read() failed");
		close(accept_fd);
		close(client_fd);
		close(listen_fd);
		return 1;
	}

	if (strcmp(TEST_STRING, buf)) {
		fail("data corruption");
		close(accept_fd);
		close(client_fd);
		close(listen_fd);
		return 1;
	}

	close(accept_fd);
	close(client_fd);
	close(listen_fd);
	unlink(addr.sun_path);

	pass();
	return 0;
}
