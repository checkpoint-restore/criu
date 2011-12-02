#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/sem.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <signal.h>
#include <errno.h>

#include "zdtmtst.h"

const char *test_doc="Tests sysv5 msg queues supporting by checkpointing";
const char *test_author="Pavel Emelianov <xemul@parallels.com>";

struct msg1 {
	long mtype;
	char mtext[20];
};
#define TEST_STRING "Test sysv5 msg"

int main(int argc, char **argv)
{
	key_t key;
	int msg, pid;
	struct msg1 msgbuf;
	int chret;

	test_init(argc, argv);

	key = ftok(argv[0], 822155650);
	if (key == -1) {
		err("Can't make key");
		exit(1);
	}

	pid = test_fork();
	if (pid < 0) {
		err("Can't fork");
		exit(1);
	}

	msg = msgget(key, IPC_CREAT | IPC_EXCL | 0666);
	if (msg == -1) {
		msg = msgget(key, 0666);
		if (msg == -1) {
			err("Can't get queue");
			if (pid) {
				kill(pid, SIGKILL);
				wait(NULL);
			}
			exit(1);
		}
	}

	if (pid == 0) {
		if (msgrcv(msg, &msgbuf, sizeof(TEST_STRING), 1, 0) == -1) {
			chret = errno;
			fail("msgrcv failed %d(%m)", errno);
			return chret;
		}
		if (strncmp(TEST_STRING, msgbuf.mtext, sizeof(TEST_STRING))) {
			fail("The source and received strings aren't equal");
			return 1;
		}
		test_msg("Recived %s\n", msgbuf.mtext);
		pass();
		goto out;
	} else {

		test_daemon();
		test_waitsig();

		msgbuf.mtype = 1;
		memcpy(msgbuf.mtext, TEST_STRING, sizeof(TEST_STRING));
		if (msgsnd(msg, &msgbuf, sizeof(TEST_STRING), 0) != 0) {
			fail("msgsnd failed %d(%m)", errno);
			kill(pid, SIGKILL);
			wait(NULL);
			return 1;
		};

		wait(&chret);
		chret = WEXITSTATUS(chret);
		if (chret) {
			fail("child exited with non-zero code %d (%s)\n",
			     chret, strerror(chret));
			return 1;
		}
		pass();
	}

	msgctl(msg, IPC_RMID, 0);

out:
	return 0;
}
