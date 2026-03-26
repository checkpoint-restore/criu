#include <fcntl.h>
#include <sys/stat.h>
#include <mqueue.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "zdtmtst.h"

const char *test_doc = "Test checkpoint/restore of POSIX message queues";
const char *test_author = "sunchao dong <dongsunchao@gmail.com>";

#define MQ_NAME "/zdtm_posix_mqueue_test"
#define MAX_MSG_SIZE 256

struct test_msg {
    unsigned int prio;
    char data[MAX_MSG_SIZE];
} msgs_to_send[] = {
    { 10, "Message A: Priority 10 (First in)" },
    { 20, "Message B: Priority 20 (Highest)" },
    { 10, "Message C: Priority 10 (Second in)" },
    {  5, "Message D: Priority 5 (Lowest)" }
};

#define MSG_COUNT (sizeof(msgs_to_send) / sizeof(msgs_to_send[0]))

int expected_order[] = { 1, 0, 2, 3 };

int main(int argc, char **argv)
{
    mqd_t mq;
    struct mq_attr attr = {
        .mq_maxmsg = 10,
        .mq_msgsize = MAX_MSG_SIZE
    };
    struct stat st_before, st_after;
    int i;

    test_init(argc, argv);

    mq_unlink(MQ_NAME);

    mq = mq_open(MQ_NAME, O_CREAT | O_RDWR, 0666, &attr);
    if (mq == (mqd_t)-1) {
        pr_perror("mq_open failed");
        exit(1);
    }

    test_msg("Sending messages to mqueue...\n");
    for (i = 0; i < MSG_COUNT; i++) {
        if (mq_send(mq, msgs_to_send[i].data, strlen(msgs_to_send[i].data), msgs_to_send[i].prio) == -1) {
            pr_perror("mq_send failed at index %d", i);
            exit(1);
        }
    }

    /*
     * Record the inode of the mqueue fd before C/R.  CRIU's restore path
     * calls mq_unlink() + mq_open() which always produces a new inode.
     * If C/R never happened the inode will be unchanged and we must fail.
     */
    if (fstat(mq, &st_before) == -1) {
        pr_perror("fstat before dump failed");
        exit(1);
    }

    test_daemon();
    test_waitsig();

    /*
     * Verify that a real C/R took place.  When CRIU dump fails, zdtm.py
     * sends SIGTERM to unblock test_waitsig() so the process can clean up.
     * In that situation the original fd is still open with the same inode
     * and all messages are still present, which would produce a false pass.
     */
    if (fstat(mq, &st_after) == -1) {
        pr_perror("fstat after restore failed");
        fail("mqueue fd invalid after restore");
        exit(1);
    }

    if (st_after.st_ino == st_before.st_ino) {
        fail("mqueue inode unchanged - C/R did not actually happen");
        exit(1);
    }

    test_msg("Restored! Receiving and verifying messages...\n");
    for (i = 0; i < MSG_COUNT; i++) {
        char buf[MAX_MSG_SIZE + 1];
        unsigned int prio;
        ssize_t n;
        int exp_idx; 

        n = mq_receive(mq, buf, MAX_MSG_SIZE, &prio);
        if (n == -1) {
            pr_perror("mq_receive failed at iteration %d", i);
            fail("Failed to receive all expected messages.");
            exit(1);
        }
        buf[n] = '\0';

        exp_idx = expected_order[i];
        
        if (prio != msgs_to_send[exp_idx].prio || strcmp(buf, msgs_to_send[exp_idx].data) != 0) {
            fail("Mismatch at receive #%d!\nExpected: [Prio %u] '%s'\nGot:      [Prio %u] '%s'",
                 i, msgs_to_send[exp_idx].prio, msgs_to_send[exp_idx].data,
                 prio, buf);
            exit(1);
        }
        
        test_msg("Verified message #%d: [Prio %u] '%s'\n", i, prio, buf);
    }

    mq_close(mq);
    mq_unlink(MQ_NAME);

    pass();
    return 0;
}