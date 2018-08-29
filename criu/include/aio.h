#ifndef __CR_AIO_H__
#define __CR_AIO_H__

#include "images/mm.pb-c.h"
unsigned int aio_estimate_nr_reqs(unsigned int size);
int dump_aio_ring(MmEntry *mme, struct vma_area *vma);
void free_aios(MmEntry *mme);
struct parasite_ctl;
int parasite_collect_aios(struct parasite_ctl *, struct vm_area_list *);
unsigned long aio_rings_args_size(struct vm_area_list *);
struct task_restore_args;
int prepare_aios(struct pstree_item *t, struct task_restore_args *ta);

/* copied from linux/fs.h */
typedef int __bitwise __kernel_rwf_t;

/* copied from linux/aio_abi.h */
#ifndef COMPEL_SYSCALL_TYPES_H__
/* The ifndef is needed to avoid a clang compiler error */
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
	unsigned        id;     /* kernel internal index number */
	unsigned        nr;     /* number of io_events */
	unsigned        head;   /* Written to by userland or under ring_lock
				 * mutex by aio_read_events_ring(). */
	unsigned        tail;

	unsigned        magic;
	unsigned        compat_features;
	unsigned        incompat_features;
	unsigned        header_length;  /* size of aio_ring */

	struct io_event         io_events[0];
};

struct rst_aio_ring {
	unsigned long addr;
	unsigned long len;
	unsigned int nr_req;
};
#endif /* __CR_AIO_H__ */
