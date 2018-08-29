#include <linux/types.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <aio.h>

#include "zdtmtst.h"

const char *test_doc	= "Check head and tail restore correct";
const char *test_author	= "Kirill Tkhai <ktkhai@virtuozzo.com>";

/* copied from linux/fs.h */
typedef int __bitwise __kernel_rwf_t;

/* copied from linux/aio_abi.h */
#ifndef COMPEL_SYSCALL_TYPES_H__
typedef __kernel_ulong_t aio_context_t;
#endif

enum {
	IOCB_CMD_PREAD = 0,
	IOCB_CMD_PWRITE = 1,
	IOCB_CMD_FSYNC = 2,
	IOCB_CMD_FDSYNC = 3,
	/* These two are experimental.
	 * IOCB_CMD_PREADX = 4,
	 * IOCB_CMD_POLL = 5,
	 */
	IOCB_CMD_NOOP = 6,
	IOCB_CMD_PREADV = 7,
	IOCB_CMD_PWRITEV = 8,
};
/* read() from /dev/aio returns these structures. */
struct io_event {
	__u64		data;		/* the data field from the iocb */
	__u64		obj;		/* what iocb this event came from */
	__s64		res;		/* result code for this event */
	__s64		res2;		/* secondary result */
};

/*
 * we always use a 64bit off_t when communicating
 * with userland.  its up to libraries to do the
 * proper padding and aio_error abstraction
 */

struct iocb {
	/* these are internal to the kernel/libc. */
	__u64	aio_data;	/* data to be returned in event's data */

#if defined(__BYTE_ORDER) ? __BYTE_ORDER == __LITTLE_ENDIAN : defined(__LITTLE_ENDIAN)
	__u32	aio_key;	/* the kernel sets aio_key to the req # */
	__kernel_rwf_t aio_rw_flags;	/* RWF_* flags */
#elif defined(__BYTE_ORDER) ? __BYTE_ORDER == __BIG_ENDIAN : defined(__BIG_ENDIAN)
	__kernel_rwf_t aio_rw_flags;	/* RWF_* flags */
	__u32	aio_key;	/* the kernel sets aio_key to the req # */
#else
#error edit for your odd byteorder.
#endif

	/* common fields */
	__u16	aio_lio_opcode;	/* see IOCB_CMD_ above */
	__s16	aio_reqprio;
	__u32	aio_fildes;

	__u64	aio_buf;
	__u64	aio_nbytes;
	__s64	aio_offset;

	/* extra parameters */
	__u64	aio_reserved2;	/* TODO: use this for a (struct sigevent *) */

	/* flags for the "struct iocb" */
	__u32	aio_flags;

	/*
	 * if the IOCB_FLAG_RESFD flag of "aio_flags" is set, this is an
	 * eventfd to signal AIO readiness to
	 */
	__u32	aio_resfd;
}; /* 64 bytes */

struct aio_ring {
	unsigned	id;     /* kernel internal index number */
	unsigned	nr;     /* number of io_events */
	unsigned	head;   /* Written to by userland or under ring_lock
				 * mutex by aio_read_events_ring(). */
	unsigned	tail;
	unsigned	magic;
	unsigned	compat_features;
	unsigned	incompat_features;
	unsigned	header_length;	/* size of aio_ring */
	struct io_event	io_events[0];
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
		fail("missmatch");
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
