#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <fcntl.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that we can migrate with a unix socket "
			"bound in a directory which has been mounted over by"
			" another filesystem";
const char *test_author	= "Roman Kagan <rkagan@parallels.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

static int fill_sock_name(struct sockaddr_un *name, const char *filename)
{
	if (strlen(filename) >= sizeof(name->sun_path))
		return -1;

	name->sun_family = AF_LOCAL;
	strcpy(name->sun_path, filename);
	return 0;
}

static int setup_srv_sock(const char *filename)
{
	struct sockaddr_un name;
	int sock;

	if (fill_sock_name(&name, filename) < 0) {
		err("filename \"%s\" is too long", filename);
		return -1;
	}

	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock < 0) {
		err("can't create socket: %m");
		return -1;
	}

	if (bind(sock, (struct sockaddr *) &name, SUN_LEN(&name)) < 0) {
		err("can't bind to socket \"%s\": %m", filename);
		goto err;
	}

	if (listen(sock, 1) < 0) {
		err("can't listen on a socket \"%s\": %m\n", filename);
		goto err;
	}

	return sock;
err:
	close(sock);
	return -1;
}

static int setup_clnt_sock(const char *filename)
{
	struct sockaddr_un name;
	int sock;

	if (fill_sock_name(&name, filename) < 0)
		return -1;

	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock < 0)
		return -1;

	if (connect(sock, (struct sockaddr *) &name, SUN_LEN(&name)) < 0)
		goto err;

	return sock;
err:
	close(sock);
	return -1;
}

int main(int argc, char ** argv)
{
	int sock, acc_sock, ret;
	char path[256];
	pid_t pid;
	uint32_t crc;
	uint8_t buf[1000];

	test_init(argc, argv);

	if (snprintf(path, sizeof(path), "%s/foo", dirname) >= sizeof(path)) {
		err("directory name \"%s\"is too long", dirname);
		exit(1);
	}

	if (mkdir(dirname, 0700)) {
		err("can't make directory %s: %m\n", dirname);
		exit(1);
	}

	sock = setup_srv_sock(path);
	if (sock < 0)
		goto out;

	pid = fork();
	if (pid < 0) {
		err("can't fork: %m\n");
		goto out;
	}

	if (pid == 0) {	/* child writes to the overmounted socket and returns */
		close(sock);

		sock = setup_clnt_sock(path);
		if (sock < 0)
			_exit(1);

		test_waitsig();

		crc = ~0;
		datagen(buf, sizeof(buf), &crc);
		if (write(sock, buf, sizeof(buf)) != sizeof(buf))
			_exit(errno);

		close(sock);
		_exit(0);
	}

	acc_sock = accept(sock, NULL, NULL);
	if (acc_sock < 0) {
		err("can't accept() the connection on \"%s\": %m", path);
		goto out_kill;
	}

	close(sock);
	sock = acc_sock;

	if (mount("rien", dirname, "tmpfs", 0, 0) < 0) {
		err("can't mount tmpfs over %s: %m", dirname);
		goto out_kill;
	}

	test_daemon();
	test_waitsig();

	if (kill(pid, SIGTERM)) {
		fail("terminating the child failed: %m\n");
		goto out;
	}

	if (wait(&ret) != pid) {
		fail("wait() returned wrong pid %d: %m\n", pid);
		goto out;
	}

	if (WIFEXITED(ret)) {
		ret = WEXITSTATUS(ret);
		if (ret) {
			fail("child exited with nonzero code %d (%s)\n", ret,
				strerror(ret));
			goto out;
		}
	}
	if (WIFSIGNALED(ret)) {
		fail("child exited on unexpected signal %d\n", WTERMSIG(ret));
		goto out;
	}

	if (read(sock, buf, sizeof(buf)) != sizeof(buf)) {
		fail("can't read %s: %m\n", path);
		goto out;
	}

	crc = ~0;
	if (datachk(buf, sizeof(buf), &crc)) {
		fail("CRC mismatch\n");
		goto out;
	}

	if (umount(dirname) < 0) {
		fail("can't umount %s: %m", dirname);
		goto out;
	}

	if (close(sock) < 0) {
		fail("can't close %s: %m", path);
		goto out;
	}

	if (unlink(path) < 0) {
		fail("can't unlink %s: %m", path);
		goto out;
	}

	pass();

out_kill:
	kill(pid, SIGKILL);
out:
	close(sock);
	unlink(path);
	rmdir(dirname);
	return 0;
}
