#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <mqueue.h>
#include <sys/stat.h>
#include <errno.h>

#include "zdtmtst.h"

const char *test_doc	= "Test POSIX mqueue checkpoint/restore";
const char *test_author	= "Abdullah Albadawy <abdullahalbadawy1@gmail.com>";

#define MQ_NAME		"/criu_test_mq"
#define MSG_A		"first"
#define MSG_B		"second"
#define PRIO_A		3
#define PRIO_B		7
#define MSGSIZE		64

int main(int argc, char **argv)
{
	mqd_t mqd;
	struct mq_attr attr;
	char buf[MSGSIZE];
	unsigned int prio;

	test_init(argc, argv);

	attr.mq_flags	= 0;
	attr.mq_maxmsg	= 8;
	attr.mq_msgsize	= MSGSIZE;
	attr.mq_curmsgs	= 0;

	mq_unlink(MQ_NAME);

	mqd = mq_open(MQ_NAME, O_CREAT | O_RDWR, 0644, &attr);
	if (mqd == (mqd_t)-1) {
		pr_perror("mq_open");
		return 1;
	}

	if (mq_send(mqd, MSG_A, sizeof(MSG_A), PRIO_A) < 0) {
		pr_perror("mq_send MSG_A");
		goto err;
	}

	if (mq_send(mqd, MSG_B, sizeof(MSG_B), PRIO_B) < 0) {
		pr_perror("mq_send MSG_B");
		goto err;
	}

	test_daemon();
	test_waitsig();

	/*
	 * After restore the queue must still exist with both messages.
	 * Higher-priority message (MSG_B, prio=7) arrives first.
	 */
	if (mq_receive(mqd, buf, MSGSIZE, &prio) < 0) {
		fail("mq_receive first msg failed");
		goto err;
	}

	if (prio != PRIO_B || strcmp(buf, MSG_B)) {
		fail("first msg mismatch: prio=%u body=%s", prio, buf);
		goto err;
	}

	if (mq_receive(mqd, buf, MSGSIZE, &prio) < 0) {
		fail("mq_receive second msg failed");
		goto err;
	}

	if (prio != PRIO_A || strcmp(buf, MSG_A)) {
		fail("second msg mismatch: prio=%u body=%s", prio, buf);
		goto err;
	}

	pass();

	mq_close(mqd);
	mq_unlink(MQ_NAME);
	return 0;

err:
	mq_close(mqd);
	mq_unlink(MQ_NAME);
	return 1;
}