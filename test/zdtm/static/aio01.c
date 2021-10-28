#include <linux/aio_abi.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <aio.h>

#include "zdtmtst.h"

const char *test_doc = "Check head and tail restore correct";
const char *test_author = "Kirill Tkhai <ktkhai@virtuozzo.com>";

struct aio_ring {
	unsigned id;   /* kernel internal index number */
	unsigned nr;   /* number of io_events */
	unsigned head; /* Written to by userland or under ring_lock
				 * mutex by aio_read_events_ring(). */
	unsigned tail;
	unsigned magic;
	unsigned compat_features;
	unsigned incompat_features;
	unsigned header_length; /* size of aio_ring */
	struct io_event io_events[0];
}; /* 128 bytes + ring size */

int main(int argc, char **argv)
{
	struct iocb iocb, *iocbp = &iocb;
	volatile struct aio_ring *ring;
	aio_context_t ctx = 0;
	struct io_event event;
	unsigned tail[2], head[2];
	unsigned nr[2];
	int i, fd, ret;
	char buf[1];

	test_init(argc, argv);

	memset(&iocb, 0, sizeof(iocb));

	if (syscall(__NR_io_setup, 64, &ctx) < 0) {
		pr_perror("Can't setup io ctx");
		return 1;
	}

	fd = open("/dev/null", O_WRONLY);
	if (fd < 0) {
		pr_perror("Can't open /dev/null");
		return 1;
	}

	iocb.aio_fildes = fd;
	iocb.aio_buf = (unsigned long)buf;
	iocb.aio_nbytes = 1;
	iocb.aio_lio_opcode = IOCB_CMD_PWRITE;

	ring = (struct aio_ring *)ctx;
	nr[0] = ring->nr;

	for (i = 0; i < nr[0] + 2; i++) {
		if (syscall(__NR_io_submit, ctx, 1, &iocbp) != 1) {
			fail("Can't submit aio");
			return 1;
		}

		if (!(i % 2))
			continue;

		ret = syscall(__NR_io_getevents, ctx, 0, 1, &event, NULL);
		if (ret != 1) {
			fail("Can't get event");
			return 1;
		}
	}

	tail[0] = *((volatile unsigned *)&ring->tail);
	head[0] = *((volatile unsigned *)&ring->head);

	test_msg("tail=%u, head=%u, nr=%u\n", tail[0], head[0], nr[0]);

	test_daemon();
	test_waitsig();

	tail[1] = *((volatile unsigned *)&ring->tail);
	head[1] = *((volatile unsigned *)&ring->head);
	nr[1] = *((volatile unsigned *)&ring->nr);

	test_msg("tail=%u, head=%u, nr=%u\n", tail[1], head[1], nr[1]);

	if (tail[0] != tail[1] || head[0] != head[1] || nr[0] != nr[1]) {
		fail("mismatch");
		return 1;
	}

	if (syscall(__NR_io_submit, ctx, 1, &iocbp) != 1) {
		fail("Can't submit aio");
		return 1;
	}

	tail[1] = *((volatile unsigned *)&ring->tail);
	head[1] = *((volatile unsigned *)&ring->head);
	nr[1] = *((volatile unsigned *)&ring->nr);

	test_msg("tail=%u, head=%u, nr=%u\n", tail[1], head[1], nr[1]);

	if (tail[1] == tail[0] + 1 && head[1] == head[0] && nr[1] == nr[0])
		pass();
	else
		fail("mismatch");
	return 0;
}
