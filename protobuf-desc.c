#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <arpa/inet.h>
#include <ctype.h>

#include "asm/types.h"

#include "compiler.h"
#include "log.h"

#include "protobuf-desc.h"

#include "protobuf/inventory.pb-c.h"
#include "protobuf/stats.pb-c.h"
#include "protobuf/regfile.pb-c.h"
#include "protobuf/ns.pb-c.h"
#include "protobuf/eventfd.pb-c.h"
#include "protobuf/eventpoll.pb-c.h"
#include "protobuf/signalfd.pb-c.h"
#include "protobuf/fsnotify.pb-c.h"
#include "protobuf/core.pb-c.h"
#include "protobuf/mm.pb-c.h"
#include "protobuf/pipe.pb-c.h"
#include "protobuf/fifo.pb-c.h"
#include "protobuf/fdinfo.pb-c.h"
#include "protobuf/pipe-data.pb-c.h"
#include "protobuf/pstree.pb-c.h"
#include "protobuf/sa.pb-c.h"
#include "protobuf/sk-unix.pb-c.h"
#include "protobuf/sk-inet.pb-c.h"
#include "protobuf/packet-sock.pb-c.h"
#include "protobuf/sk-packet.pb-c.h"
#include "protobuf/creds.pb-c.h"
#include "protobuf/timer.pb-c.h"
#include "protobuf/utsns.pb-c.h"
#include "protobuf/ipc-var.pb-c.h"
#include "protobuf/ipc-shm.pb-c.h"
#include "protobuf/ipc-msg.pb-c.h"
#include "protobuf/ipc-sem.pb-c.h"
#include "protobuf/fs.pb-c.h"
#include "protobuf/remap-file-path.pb-c.h"
#include "protobuf/ghost-file.pb-c.h"
#include "protobuf/mnt.pb-c.h"
#include "protobuf/netdev.pb-c.h"
#include "protobuf/tcp-stream.pb-c.h"
#include "protobuf/tty.pb-c.h"
#include "protobuf/file-lock.pb-c.h"
#include "protobuf/rlimit.pb-c.h"
#include "protobuf/pagemap.pb-c.h"
#include "protobuf/siginfo.pb-c.h"
#include "protobuf/sk-netlink.pb-c.h"
#include "protobuf/vma.pb-c.h"
#include "protobuf/tun.pb-c.h"

struct cr_pb_message_desc cr_pb_descs[PB_MAX];

#define CR_PB_DESC(__type, __vtype, __ftype)		\
	CR_PB_MDESC_INIT(cr_pb_descs[PB_##__type],	\
			 __vtype##Entry,		\
			 __ftype##_entry)

#define PB_PACK_TYPECHECK(__o, __fn)	({ if (0) __fn##__pack(__o, NULL); (pb_pack_t)&__fn##__pack; })
#define PB_GPS_TYPECHECK(__o, __fn)	({ if (0) __fn##__get_packed_size(__o); (pb_getpksize_t)&__fn##__get_packed_size; })
#define PB_UNPACK_TYPECHECK(__op, __fn)	({ if (0) *__op = __fn##__unpack(NULL, 0, NULL); (pb_unpack_t)&__fn##__unpack; })
#define PB_FREE_TYPECHECK(__o, __fn)	({ if (0) __fn##__free_unpacked(__o, NULL); (pb_free_t)&__fn##__free_unpacked; })

/*
 * This should be explicitly "called" to do type-checking
 */

#define CR_PB_MDESC_INIT(__var, __type, __name)					\
	do {									\
		__var.getpksize	= PB_GPS_TYPECHECK((__type *)NULL, __name);	\
		__var.pack	= PB_PACK_TYPECHECK((__type *)NULL, __name);	\
		__var.unpack	= PB_UNPACK_TYPECHECK((__type **)NULL, __name);	\
		__var.free	= PB_FREE_TYPECHECK((__type *)NULL, __name);	\
		__var.pb_desc	= &__name##__descriptor;			\
	} while (0)

void cr_pb_init(void)
{
	CR_PB_DESC(IDS,			TaskKobjIds,	task_kobj_ids);
	CR_PB_DESC(SIGACT,		Sa,		sa);
	CR_PB_DESC(SK_QUEUES,		SkPacket,	sk_packet);
	CR_PB_MDESC_INIT(cr_pb_descs[PB_IPCNS_MSG],	IpcMsg, ipc_msg);
	CR_PB_DESC(IPCNS_MSG_ENT,	IpcMsg,		ipc_msg);
	CR_PB_DESC(REMAP_FPATH,		RemapFilePath,	remap_file_path);
	CR_PB_DESC(NETDEV,		NetDevice,	net_device);
	CR_PB_MDESC_INIT(cr_pb_descs[PB_PAGEMAP_HEAD],	PagemapHead,	pagemap_head);

#include "protobuf-desc-gen.h"
}
