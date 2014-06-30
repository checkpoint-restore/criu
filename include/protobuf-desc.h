#ifndef __CR_PROTOBUF_DESC_H__
#define __CR_PROTOBUF_DESC_H__

#include <sys/types.h>
#include <google/protobuf-c/protobuf-c.h>

enum {
	/* PB_AUTOGEN_START */
	PB_INVENTORY,		/* 0 */
	PB_STATS,
	PB_FDINFO,
	PB_CORE,
	PB_MM,
	PB_VMA,
	PB_ITIMER,
	PB_POSIX_TIMER,
	PB_CREDS,
	PB_FS,
	PB_UTSNS,		/* 10 */
	PB_IPC_VAR,
	PB_IPC_SHM,
	PB_IPC_SEM,
	PB_MNT,
	PB_PSTREE,
	PB_GHOST_FILE,
	PB_TCP_STREAM,
	PB_REG_FILE,
	PB_EXT_FILE,
	PB_NS_FILE,		/* 20 */
	PB_INET_SK,
	PB_UNIX_SK,
	PB_PACKET_SOCK,
	PB_NETLINK_SK,
	PB_PIPE,
	PB_FIFO,
	PB_PIPE_DATA,
	PB_EVENTFD_FILE,
	PB_EVENTPOLL_FILE,
	PB_EVENTPOLL_TFD,	/* 30 */
	PB_SIGNALFD,
	PB_INOTIFY_FILE,
	PB_INOTIFY_WD,
	PB_FANOTIFY_FILE,
	PB_FANOTIFY_MARK,
	PB_TTY_FILE,
	PB_TTY_INFO,
	PB_FILE_LOCK,
	PB_RLIMIT,
	PB_PAGEMAP,		/* 40 */
	PB_SIGINFO,
	PB_TUNFILE,
	PB_IRMAP_CACHE,
	PB_CGROUP,
	PB_TIMERFD,

	/* PB_AUTOGEN_STOP */

	PB_PAGEMAP_HEAD,
	PB_IDS,
	PB_SIGACT,
	PB_NETDEV,
	PB_REMAP_FPATH,		/* 50 */
	PB_SK_QUEUES,
	PB_IPCNS_MSG,
	PB_IPCNS_MSG_ENT,

	PB_MAX,
};

typedef size_t (*pb_getpksize_t)(void *obj);
typedef size_t (*pb_pack_t)(void *obj, void *where);
typedef void  *(*pb_unpack_t)(void *allocator, size_t size, void *from);
typedef void   (*pb_free_t)(void *obj, void *allocator);

struct cr_pb_message_desc {
	pb_getpksize_t				getpksize;
	pb_pack_t				pack;
	pb_unpack_t				unpack;
	pb_free_t				free;
	const ProtobufCMessageDescriptor	*pb_desc;
};

extern void cr_pb_init(void);
extern struct cr_pb_message_desc cr_pb_descs[PB_MAX];

#endif /* __CR_PROTOBUF_DESC_H__ */
