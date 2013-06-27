#ifndef __CR_PROTOBUF_DESC_H__
#define __CR_PROTOBUF_DESC_H__

#include <sys/types.h>
#include <google/protobuf-c/protobuf-c.h>

enum {
	PB_INVENTORY,
	PB_STATS,
	PB_FDINFO,
	PB_CORE,
	PB_MM,
	PB_VMAS,
	PB_SIGACT,
	PB_ITIMERS,
	PB_POSIX_TIMERS,
	PB_CREDS,
	PB_FS,
	PB_UTSNS,
	PB_IPCNS_VAR,
	PB_IPCNS_SHM,
	PB_IPCNS_MSG,
	PB_IPCNS_MSG_ENT,
	PB_IPCNS_SEM,
	PB_MOUNTPOINTS,
	PB_NETDEV,
	PB_PSTREE,
	PB_GHOST_FILE,
	PB_TCP_STREAM,
	PB_SK_QUEUES,
	PB_REG_FILES,
	PB_NS_FILES,
	PB_INETSK,
	PB_UNIXSK,
	PB_PACKETSK,
	PB_NETLINKSK,
	PB_PIPES,
	PB_FIFO,
	PB_PIPES_DATA,
	PB_REMAP_FPATH,
	PB_EVENTFD,
	PB_EVENTPOLL,
	PB_EVENTPOLL_TFD,
	PB_SIGNALFD,
	PB_INOTIFY,
	PB_INOTIFY_WD,
	PB_FANOTIFY,
	PB_FANOTIFY_MARK,
	PB_TTY,
	PB_TTY_INFO,
	PB_FILE_LOCK,
	PB_RLIMIT,
	PB_IDS,
	PB_PAGEMAP_HEAD,
	PB_PAGEMAP,
	PB_SIGINFO,

	PB_MAX
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
