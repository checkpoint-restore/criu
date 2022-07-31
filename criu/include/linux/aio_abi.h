#ifndef __LINUX__AIO_ABI_H
#define __LINUX__AIO_ABI_H

typedef __kernel_ulong_t aio_context_t;

/* read() from /dev/aio returns these structures. */
struct io_event {
	__u64 data; /* the data field from the iocb */
	__u64 obj;  /* what iocb this event came from */
	__s64 res;  /* result code for this event */
	__s64 res2; /* secondary result */
};

#endif /* __LINUX__AIO_ABI_H */
