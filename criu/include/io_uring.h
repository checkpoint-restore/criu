#ifndef __CR_IO_URING_H__
#define __CR_IO_URING_H__

#include <linux/capability.h>

#include "files.h"
#include "io_uring.pb-c.h"

/* Definitions */
struct __io_uring_restriction {
	__u16 opcode;
	union {
		__u8 register_op; /* IORING_RESTRICTION_REGISTER_OP */
		__u8 sqe_op;	  /* IORING_RESTRICTION_SQE_OP */
		__u8 sqe_flags;	  /* IORING_RESTRICTION_SQE_FLAGS_* */
	};
	__u8 resv;
	__u32 resv2[3];
};

#ifndef IORING_SETUP_IOPOLL
#define IORING_SETUP_IOPOLL (1U << 0) /* io_context is polled */
#endif
#ifndef IORING_SETUP_SQPOLL
#define IORING_SETUP_SQPOLL (1U << 1) /* SQ poll thread */
#endif
#ifndef IORING_SETUP_SQ_AFF
#define IORING_SETUP_SQ_AFF (1U << 2) /* sq_thread_cpu is valid */
#endif
#ifndef IORING_SETUP_CQSIZE
#define IORING_SETUP_CQSIZE (1U << 3) /* app defines CQ size */
#endif
#ifndef IORING_SETUP_ATTACH_WQ
#define IORING_SETUP_ATTACH_WQ (1U << 5) /* attach to existing wq */
#endif
#ifndef IORING_SETUP_R_DISABLED
#define IORING_SETUP_R_DISABLED (1U << 6) /* start with ring disabled */
#endif

#ifndef IORING_OFF_SQ_RING
#define IORING_OFF_SQ_RING 0ULL
#endif
#ifndef IORING_OFF_CQ_RING
#define IORING_OFF_CQ_RING 0x8000000ULL
#endif
#ifndef IORING_OFF_SQES
#define IORING_OFF_SQES 0x10000000ULL
#endif

#ifndef IOSQE_IO_DRAIN
#define IOSQE_IO_DRAIN (1U << 1)
#endif

#define __IORING_RESTRICTION_REGISTER_OP	0
#define __IORING_RESTRICTION_SQE_OP		1
#define __IORING_RESTRICTION_SQE_FLAGS_ALLOWED	2
#define __IORING_RESTRICTION_SQE_FLAGS_REQUIRED 3
#define __IORING_REGISTER_PERSONALITY		9
#define __IORING_REGISTER_RESTRICTIONS		11
#define __IORING_REGISTER_ENABLE_RINGS		12

struct io_uring_file_info {
	IoUringFileEntry *iofe;
	struct file_desc d;
};

struct io_uring_data_info {
	IoUringDataEntry *iode;
};

struct io_uring_group_desc {
	struct list_head list;
	gid_t group;
	char group_name[32];
};

struct io_uring_personality_desc {
	int id;
	uid_t uid;
	uid_t euid;
	uid_t suid;
	uid_t fsuid;
	gid_t gid;
	gid_t egid;
	gid_t sgid;
	gid_t fsgid;
	u32 cap_eff[CR_CAP_SIZE];
	size_t nr_groups;
	struct list_head group_list;
};

struct io_uring_ctx;

extern struct collect_image_info io_uring_cinfo;
extern struct collect_image_info io_uring_data_cinfo;
extern const struct fdtype_ops io_uring_dump_ops;

int is_io_uring_link(char *link);
int io_uring_synchronize_fd(int fd);
int collect_io_uring_map(struct vma_area *vma);
int dump_io_uring_map(struct vma_area *vma);
int add_one_io_uring_mapping(uint64_t offset, ino_t inode);

int io_uring_push_buf(struct io_uring_ctx *ctx, unsigned int idx, long long unsigned int address, unsigned int len);
int io_uring_push_personality(struct io_uring_ctx *ctx, struct io_uring_personality_desc *desc);
IoUringFileEntry *io_uring_get_iofe(struct io_uring_ctx *ctx);

#endif /* __CR_IO_URING_H__ */
