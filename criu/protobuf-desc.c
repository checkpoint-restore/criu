#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <arpa/inet.h>
#include <ctype.h>

#include "common/compiler.h"
#include "log.h"

#include "protobuf-desc.h"

#include "images/inventory.pb-c.h"
#include "images/stats.pb-c.h"
#include "images/regfile.pb-c.h"
#include "images/ext-file.pb-c.h"
#include "images/ns.pb-c.h"
#include "images/eventfd.pb-c.h"
#include "images/eventpoll.pb-c.h"
#include "images/signalfd.pb-c.h"
#include "images/fsnotify.pb-c.h"
#include "images/core.pb-c.h"
#include "images/mm.pb-c.h"
#include "images/pipe.pb-c.h"
#include "images/fifo.pb-c.h"
#include "images/fdinfo.pb-c.h"
#include "images/pipe-data.pb-c.h"
#include "images/pstree.pb-c.h"
#include "images/sa.pb-c.h"
#include "images/sk-unix.pb-c.h"
#include "images/sk-inet.pb-c.h"
#include "images/packet-sock.pb-c.h"
#include "images/sk-packet.pb-c.h"
#include "images/creds.pb-c.h"
#include "images/timer.pb-c.h"
#include "images/utsns.pb-c.h"
#include "images/timens.pb-c.h"
#include "images/pidns.pb-c.h"
#include "images/ipc-var.pb-c.h"
#include "images/ipc-shm.pb-c.h"
#include "images/ipc-msg.pb-c.h"
#include "images/ipc-sem.pb-c.h"
#include "images/fs.pb-c.h"
#include "images/remap-file-path.pb-c.h"
#include "images/ghost-file.pb-c.h"
#include "images/mnt.pb-c.h"
#include "images/netdev.pb-c.h"
#include "images/tcp-stream.pb-c.h"
#include "images/tty.pb-c.h"
#include "images/file-lock.pb-c.h"
#include "images/rlimit.pb-c.h"
#include "images/pagemap.pb-c.h"
#include "images/siginfo.pb-c.h"
#include "images/sk-netlink.pb-c.h"
#include "images/vma.pb-c.h"
#include "images/tun.pb-c.h"
#include "images/cgroup.pb-c.h"
#include "images/timerfd.pb-c.h"
#include "images/cpuinfo.pb-c.h"
#include "images/userns.pb-c.h"
#include "images/seccomp.pb-c.h"
#include "images/binfmt-misc.pb-c.h"
#include "images/autofs.pb-c.h"
#include "images/img-streamer.pb-c.h"
#include "images/bpfmap-file.pb-c.h"
#include "images/bpfmap-data.pb-c.h"
#include "images/apparmor.pb-c.h"
#include "images/pidfd.pb-c.h"

struct cr_pb_message_desc cr_pb_descs[PB_MAX];

#define CR_PB_DESC(__type, __vtype, __ftype) CR_PB_MDESC_INIT(cr_pb_descs[PB_##__type], __vtype##Entry, __ftype##_entry)

#define PB_PACK_TYPECHECK(__o, __fn)             \
	({                                       \
		if (0)                           \
			__fn##__pack(__o, NULL); \
		(pb_pack_t) & __fn##__pack;      \
	})
#define PB_GPS_TYPECHECK(__o, __fn)                         \
	({                                                  \
		if (0)                                      \
			__fn##__get_packed_size(__o);       \
		(pb_getpksize_t) & __fn##__get_packed_size; \
	})
#define PB_UNPACK_TYPECHECK(__op, __fn)                        \
	({                                                     \
		if (0)                                         \
			*__op = __fn##__unpack(NULL, 0, NULL); \
		(pb_unpack_t) & __fn##__unpack;                \
	})
#define PB_FREE_TYPECHECK(__o, __fn)                      \
	({                                                \
		if (0)                                    \
			__fn##__free_unpacked(__o, NULL); \
		(pb_free_t) & __fn##__free_unpacked;      \
	})

/*
 * This should be explicitly "called" to do type-checking
 */

#define CR_PB_MDESC_INIT(__var, __type, __name)                              \
	do {                                                                 \
		__var.getpksize = PB_GPS_TYPECHECK((__type *)NULL, __name);  \
		__var.pack = PB_PACK_TYPECHECK((__type *)NULL, __name);      \
		__var.unpack = PB_UNPACK_TYPECHECK((__type **)NULL, __name); \
		__var.free = PB_FREE_TYPECHECK((__type *)NULL, __name);      \
		__var.pb_desc = &__name##__descriptor;                       \
	} while (0)

void cr_pb_init(void)
{
	CR_PB_DESC(IDS, TaskKobjIds, task_kobj_ids);
	CR_PB_DESC(SIGACT, Sa, sa);
	CR_PB_DESC(SK_QUEUES, SkPacket, sk_packet);
	CR_PB_MDESC_INIT(cr_pb_descs[PB_IPCNS_MSG], IpcMsg, ipc_msg);
	CR_PB_DESC(IPCNS_MSG_ENT, IpcMsg, ipc_msg);
	CR_PB_DESC(REMAP_FPATH, RemapFilePath, remap_file_path);
	CR_PB_DESC(NETDEV, NetDevice, net_device);
	CR_PB_MDESC_INIT(cr_pb_descs[PB_PAGEMAP_HEAD], PagemapHead, pagemap_head);

#include "protobuf-desc-gen.h"
}
