#define _GNU_SOURCE

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
#include <limits.h>
#include <fcntl.h>

#include "zdtmtst.h"

const char *test_doc	= "Test that we only send one copy of the queue to a dgram socket";
const char *test_author	= "Tycho Andersen <tycho.andersen@canonical.com>\n";

/*
 * /tmp here because as in sockets_dgram, some environments can't handle more
 * than 108 characters for this path.
 */
#define CLIENT1_PATH "/tmp/client1"
#define CLIENT2_PATH "/tmp/client2"
#define SERVER_PATH "/tmp/server"

int main(int argc, char *argv[])
{
	int server, client, ret = 1, i;
	struct sockaddr_un name;
	pid_t pid = 0;

	test_init(argc, argv);

	name.sun_family = AF_UNIX;
	server = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (server < 0) {
		err("socket");
		goto out;
	}

	strcpy(name.sun_path, SERVER_PATH);
	if (bind(server, &name, sizeof(name)) < 0) {
		err("bind");
		goto out;
	}

	pid = fork();
	if (pid < 0) {
		err("fork");
		goto out;
	}

	client = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (client < 0) {
		err("client socket");
		goto out;
	}

	if (pid == 0) {
		strcpy(name.sun_path, CLIENT1_PATH);
		if (bind(client, &name, sizeof(name)) < 0) {
			err("client bind");
			exit(1);
		}

		strcpy(name.sun_path, SERVER_PATH);
		if (connect(client, &name, sizeof(name)) < 0) {
			err("connect");
			exit(1);
		}

		if (write(client, "child-send", 10) != 10) {
			err("write");
			exit(1);
		}
		while (1)
			sleep(1000);
	}

	strcpy(name.sun_path, CLIENT2_PATH);
	if (bind(client, &name, sizeof(name)) < 0) {
		err("client bind");
		goto out;
	}

	strcpy(name.sun_path, SERVER_PATH);
	if (connect(client, &name, sizeof(name)) < 0) {
		err("connect");
		goto out;
	}

	for (i = 0; i < 9; i++) {
		/*
		 * fill the send queue with the other process; 9 messages
		 * because the default for sysctl.max_dgram_qlen is 10 on most
		 * systems, and we already sent one above.
		 */
		if (write(client, "parent-send", 11) != 11) {
			err("write");
			goto out;
		}
	}

	test_daemon();
	test_waitsig();

	pass();

	ret = 0;

out:
	if (pid > 0)
		kill(pid, SIGKILL);
	unlink(CLIENT1_PATH);
	unlink(CLIENT2_PATH);
	unlink(SERVER_PATH);

	return ret;
}
