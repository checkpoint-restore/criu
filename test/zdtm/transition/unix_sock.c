#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <limits.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <fcntl.h>

#include "zdtmtst.h"

const char *test_doc = "Multi-client - server app";
const char *test_author = "Roman Kagan <rkagan@parallels.com>";

#define PROCS_DEF 4
#define PROCS_MAX 64
unsigned int num_procs = PROCS_DEF;
TEST_OPTION(num_procs, uint,
	    "# processes to create "
	    "(default " __stringify(PROCS_DEF) ", max " __stringify(PROCS_MAX) ")",
	    0);

char *filename;
TEST_OPTION(filename, string, "file name", 1);

#define ACCEPT_TIMEOUT 100 /* max delay for the child to connect */

static int fill_sock_name(struct sockaddr_un *name, const char *filename)
{
	if (strlen(filename) >= sizeof(name->sun_path))
		return -1;

	name->sun_family = AF_LOCAL;
	strcpy(name->sun_path, filename);
	return 0;
}

static int setup_srv_sock(void)
{
	struct sockaddr_un name;
	int sock;

	if (fill_sock_name(&name, filename) < 0) {
		pr_err("filename \"%s\" is too long\n", filename);
		return -1;
	}

	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock < 0) {
		pr_perror("can't create socket");
		return -1;
	}

	if (bind(sock, (struct sockaddr *)&name, SUN_LEN(&name)) < 0) {
		pr_perror("can't bind to socket \"%s\"", filename);
		goto err;
	}

	if (fcntl(sock, F_SETFL, O_NONBLOCK) < 0) {
		pr_perror("can't make socket \"%s\" non-blocking", filename);
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

static int accept_one_conn(int sock)
{
	int acc_sock;
	fd_set fds;
	struct timeval timeout = {
		.tv_sec = ACCEPT_TIMEOUT,
	};

	FD_ZERO(&fds);
	FD_SET(sock, &fds);

	switch (select(FD_SETSIZE, &fds, NULL, NULL, &timeout)) {
	case 1:
		break;
	case 0:
		pr_err("timeout accepting a connection\n");
		return -1;
	default:
		pr_perror("error while waiting for a connection");
		return -1;
	}

	acc_sock = accept(sock, NULL, NULL);
	if (acc_sock < 0)
		pr_perror("error accepting a connection");
	return acc_sock;
}

static int setup_clnt_sock(void)
{
	struct sockaddr_un name;
	int sock;
	int ret = 0;

	if (fill_sock_name(&name, filename) < 0) {
		pr_err("filename \"%s\" is too long\n", filename);
		return -1;
	}

	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock < 0) {
		ret = -errno;
		pr_perror("can't create socket");
		return ret;
	}

	if (connect(sock, (struct sockaddr *)&name, SUN_LEN(&name)) < 0) {
		ret = -errno;
		pr_perror("can't connect");
		goto err;
	}

	return sock;
err:
	close(sock);
	return ret;
}

#define BUFLEN 1000

static int child(void)
{
	int ret = 1;
	uint8_t buf[BUFLEN];
	uint32_t crc = ~0;
	int sock = setup_clnt_sock();

	if (sock < 0) {
		ret = -sock;
		goto out;
	}

	signal(SIGPIPE, SIG_IGN);
	while (test_go()) {
		datagen(buf, sizeof(buf), &crc);
		if (write(sock, buf, sizeof(buf)) < 0 && (test_go() /* signal NOT received */ ||
							  (errno != EINTR && errno != EPIPE && errno != ECONNRESET))) {
			ret = errno;
			fail("child write");
			goto out;
		}
	}

	ret = 0;
out:
	close(sock);
	return ret;
}

int main(int argc, char **argv)
{
	struct {
		pid_t pid;
		int sock;
		uint32_t crc;
	} child_desc[PROCS_MAX];
	int i, nproc;
	int sock;
	uint8_t buf[BUFLEN];
	fd_set active_fds, read_fds;

	test_init(argc, argv);

	if (num_procs > PROCS_MAX) {
		pr_err("%d processes is too many: max = %d\n", num_procs, PROCS_MAX);
		exit(1);
	}

	sock = setup_srv_sock();
	if (sock < 0)
		exit(1);

	FD_ZERO(&active_fds);
	for (nproc = 0; nproc < num_procs; nproc++) {
		child_desc[nproc].pid = test_fork();
		if (child_desc[nproc].pid < 0) {
			pr_perror("can't fork");
			goto cleanup;
		}

		if (child_desc[nproc].pid == 0) {
			close(sock);
			exit(child());
		}

		child_desc[nproc].sock = accept_one_conn(sock);
		if (child_desc[nproc].sock < 0) {
			kill(child_desc[nproc].pid, SIGKILL);
			goto cleanup;
		}

		child_desc[nproc].crc = ~0;
		FD_SET(child_desc[nproc].sock, &active_fds);
	}

	close(sock); /* no more connections */
	test_daemon();

	while (test_go()) {
		read_fds = active_fds;
		if (select(FD_SETSIZE, &read_fds, NULL, NULL, NULL) < 0 && errno != EINTR) {
			fail("error waiting for data");
			goto out;
		}

		for (i = 0; i < num_procs; i++)
			if (FD_ISSET(child_desc[i].sock, &read_fds)) {
				if (read(child_desc[i].sock, buf, sizeof(buf)) < 0) {
					if (errno == EINTR) /* we're asked to stop */
						break;
					else {
						fail("error reading data from socket");
						goto out;
					}
				}

				if (datachk(buf, sizeof(buf), &child_desc[i].crc)) {
					fail("CRC mismatch");
					goto out;
				}
			}
	}

out:
	test_waitsig();

	if (kill(0, SIGTERM)) {
		fail("failed to send SIGTERM to my process group");
		goto cleanup; /* shouldn't wait() in this case */
	}

	while (nproc-- > 0) {
		int chret;
		/*
		 * Close socket to make sure that child's write() returns.
		 * This is to avoid race when server stopped reading & sent
		 * signal to child, child has checked for signal & found none
		 * (not yet delivered), then called write(), blocking forever.
		 */
		if (close(child_desc[nproc].sock))
			fail("Can't close server socket");

		if (wait(&chret) < 0) {
			fail("can't wait for a child");
			goto cleanup;
		}

		chret = WEXITSTATUS(chret);
		if (chret) {
			fail("child exited with non-zero code %d (%s)", chret, strerror(chret));
			goto cleanup;
		}
	}

	pass();

cleanup:
	while (nproc-- > 0) {
		close(child_desc[nproc].sock);
		if (child_desc[nproc].pid > 0)
			kill(child_desc[nproc].pid, SIGKILL);
	}
	close(sock);
	unlink(filename);
	return 0;
}
