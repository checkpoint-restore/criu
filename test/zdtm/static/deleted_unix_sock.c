#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "zdtmtst.h"

const char *test_doc = "Create a unix socket, and destroy it before "
		       "migration; check that the child can write to it "
		       "and the parent can read from it after migration";
const char *test_author = "Roman Kagan <rkagan@parallels.com>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

static int setup_srv_sock(void)
{
	struct sockaddr_un name;
	int sock;

	if (unix_fill_sock_name(&name, filename))
		return -1;

	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock < 0) {
		pr_perror("can't create socket");
		return -1;
	}

	if (bind(sock, (struct sockaddr *)&name, SUN_LEN(&name)) < 0) {
		pr_perror("can't bind to socket \"%s\"", filename);
		goto err;
	}

	if (listen(sock, 1) < 0) {
		pr_perror("can't listen on a socket \"%s\"", filename);
		goto err;
	}

	return sock;
err:
	close(sock);
	return -1;
}

static int setup_clnt_sock(void)
{
	struct sockaddr_un name;
	int sock;

	if (unix_fill_sock_name(&name, filename))
		return -1;

	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock < 0)
		return -1;

	if (connect(sock, (struct sockaddr *)&name, SUN_LEN(&name)) < 0)
		goto err;

	return sock;
err:
	close(sock);
	return -1;
}

int main(int argc, char **argv)
{
	int sock, acc_sock, ret;
	pid_t pid;
	uint32_t crc;
	uint8_t buf[1000];

	test_init(argc, argv);

	sock = setup_srv_sock();
	if (sock < 0)
		exit(1);

	pid = test_fork();
	if (pid < 0) {
		pr_perror("can't fork");
		exit(1);
	}

	if (pid == 0) { /* child writes to the unlinked socket and returns */
		close(sock);

		sock = setup_clnt_sock();
		if (sock < 0)
			_exit(1);

		test_waitsig();

		crc = ~0;
		datagen(buf, sizeof(buf), &crc);
		if (write(sock, buf, sizeof(buf)) != sizeof(buf)) {
			pr_perror("can't write to socket");
			exit(errno);
		}

		close(sock);
		exit(0);
	}

	acc_sock = accept(sock, NULL, NULL);
	if (acc_sock < 0) {
		pr_perror("can't accept() the connection on \"%s\"", filename);
		goto out_kill;
	}

	close(sock);
	sock = acc_sock;

	if (unlink(filename)) {
		pr_perror("can't unlink %s", filename);
		goto out_kill;
	}

	test_daemon();
	test_waitsig();

	if (kill(pid, SIGTERM)) {
		fail("terminating the child failed");
		goto out;
	}

	if (wait(&ret) != pid) {
		fail("wait() returned wrong pid %d", pid);
		goto out;
	}

	if (WIFEXITED(ret)) {
		ret = WEXITSTATUS(ret);
		if (ret) {
			fail("child exited with nonzero code %d (%s)", ret, strerror(ret));
			goto out;
		}
	}
	if (WIFSIGNALED(ret)) {
		fail("child exited on unexpected signal %d", WTERMSIG(ret));
		goto out;
	}

	if (read(sock, buf, sizeof(buf)) != sizeof(buf)) {
		fail("can't read %s", filename);
		goto out;
	}

	crc = ~0;
	if (datachk(buf, sizeof(buf), &crc)) {
		fail("CRC mismatch");
		goto out;
	}

	if (close(sock)) {
		fail("close failed");
		goto out;
	}

	if (unlink(filename) != -1 || errno != ENOENT) {
		fail("file %s should have been deleted before migration: unlink", filename);
		goto out;
	}

	pass();

out_kill:
	kill(pid, SIGTERM);
out:
	close(sock);
	return 0;
}
