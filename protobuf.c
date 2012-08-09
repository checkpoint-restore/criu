#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>

#include <google/protobuf-c/protobuf-c.h>

#include "crtools.h"
#include "compiler.h"
#include "types.h"
#include "log.h"
#include "util.h"

#include "protobuf.h"
#include "protobuf/inventory.pb-c.h"
#include "protobuf/regfile.pb-c.h"
#include "protobuf/eventfd.pb-c.h"
#include "protobuf/eventpoll.pb-c.h"
#include "protobuf/signalfd.pb-c.h"
#include "protobuf/inotify.pb-c.h"
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
#include "protobuf/itimer.pb-c.h"
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

typedef size_t (*pb_getpksize_t)(void *obj);
typedef size_t (*pb_pack_t)(void *obj, void *where);
typedef void  *(*pb_unpack_t)(void *allocator, size_t size, void *from);
typedef void   (*pb_free_t)(void *obj, void *allocator);

struct cr_pb_message_desc {
	pb_getpksize_t	getpksize;
	pb_pack_t	pack;
	pb_unpack_t	unpack;
	pb_free_t	free;
	const ProtobufCMessageDescriptor *pb_desc;
};

#define PB_PACK_TYPECHECK(__o, __fn)	({ if (0) __fn##__pack(__o, NULL); (pb_pack_t)&__fn##__pack; })
#define PB_GPS_TYPECHECK(__o, __fn)	({ if (0) __fn##__get_packed_size(__o); (pb_getpksize_t)&__fn##__get_packed_size; })
#define PB_UNPACK_TYPECHECK(__op, __fn)	({ if (0) *__op = __fn##__unpack(NULL, 0, NULL); (pb_unpack_t)&__fn##__unpack; })
#define PB_FREE_TYPECHECK(__o, __fn)	({ if (0) __fn##__free_unpacked(__o, NULL); (pb_free_t)&__fn##__free_unpacked; })

/*
 * This should be explicitly "called" to do type-checking
 */

#define CR_PB_MDESC_INIT(__var, __type, __name)	do {				\
		__var.getpksize = PB_GPS_TYPECHECK((__type *)NULL, __name);	\
		__var.pack = PB_PACK_TYPECHECK((__type *)NULL, __name);		\
		__var.unpack = PB_UNPACK_TYPECHECK((__type **)NULL, __name);	\
		__var.free = PB_FREE_TYPECHECK((__type *)NULL, __name);		\
		__var.pb_desc = &__name##__descriptor;				\
	} while (0)

static struct cr_pb_message_desc cr_pb_descs[PB_MAX];

#define CR_PB_DESC(__type, __vtype, __ftype)	\
	CR_PB_MDESC_INIT(cr_pb_descs[PB_##__type], __vtype##Entry, __ftype##_entry)

void cr_pb_init(void)
{
	CR_PB_DESC(INVENTORY,		Inventory,	inventory);
	CR_PB_DESC(FDINFO,		Fdinfo,		fdinfo);
	CR_PB_DESC(REG_FILES,		RegFile,	reg_file);
	CR_PB_DESC(EVENTFD,		EventfdFile,	eventfd_file);
	CR_PB_DESC(EVENTPOLL,		EventpollFile,	eventpoll_file);
	CR_PB_DESC(EVENTPOLL_TFD,	EventpollTfd,	eventpoll_tfd);
	CR_PB_DESC(SIGNALFD,		Signalfd,	signalfd);
	CR_PB_DESC(INOTIFY,		InotifyFile,	inotify_file);
	CR_PB_DESC(INOTIFY_WD,		InotifyWd,	inotify_wd);
	CR_PB_DESC(CORE,		Core,		core);
	CR_PB_DESC(MM,			Mm,		mm);
	CR_PB_DESC(VMAS,		Vma,		vma);
	CR_PB_DESC(PIPES,		Pipe,		pipe);
	CR_PB_DESC(PIPES_DATA,		PipeData,	pipe_data);
	CR_PB_DESC(FIFO,		Fifo,		fifo);
	CR_PB_DESC(PSTREE,		Pstree,		pstree);
	CR_PB_DESC(SIGACT,		Sa,		sa);
	CR_PB_DESC(UNIXSK,		UnixSk,		unix_sk);
	CR_PB_DESC(INETSK,		InetSk,		inet_sk);
	CR_PB_DESC(SK_QUEUES,		SkPacket,	sk_packet);
	CR_PB_DESC(ITIMERS,		Itimer,		itimer);
	CR_PB_DESC(CREDS,		Creds,		creds);
	CR_PB_DESC(UTSNS,		Utsns,		utsns);
	CR_PB_DESC(IPCNS_VAR,		IpcVar,		ipc_var);
	CR_PB_DESC(IPCNS_SHM,		IpcShm,		ipc_shm);
	/* There's no _entry suffix in this one :( */
	CR_PB_MDESC_INIT(cr_pb_descs[PB_IPCNS_MSG], 	IpcMsg, ipc_msg);
	CR_PB_DESC(IPCNS_MSG_ENT,	IpcMsg,		ipc_msg);
	CR_PB_DESC(IPCNS_SEM,		IpcSem,		ipc_sem);
	CR_PB_DESC(FS,			Fs,		fs);
	CR_PB_DESC(REMAP_FPATH,		RemapFilePath,	remap_file_path);
	CR_PB_DESC(GHOST_FILE,		GhostFile,	ghost_file);
	CR_PB_DESC(TCP_STREAM,		TcpStream,	tcp_stream);
	CR_PB_DESC(MOUNTPOINTS,		Mnt,		mnt);
	CR_PB_DESC(NETDEV,		NetDevice,	net_device);
	CR_PB_DESC(PACKETSK,		PacketSock,	packet_sock);
}

/*
 * To speed up reading of packed objects
 * by providing space on stack, this should
 * be more than enough for most objects.
 */
#define PB_PKOBJ_LOCAL_SIZE	1024

struct pb_pr_ctrl_s {
	void *arg;
	int single_entry;
	int depth;
};

typedef struct pb_pr_ctrl_s pb_pr_ctl_t;
typedef void (pb_pr_field_t)(void *obj, pb_pr_ctl_t *ctl);

static void pb_msg_int32x(void *obj, pb_pr_ctl_t *ctl)
{
	pr_msg("0x%08x", *(int *)obj);
}

static void pb_msg_int64x(void *obj, pb_pr_ctl_t *ctl)
{
	pr_msg("0x%016lx", *(long *)obj);
}

static void pb_msg_string(void *obj, pb_pr_ctl_t *ctl)
{
	pr_msg("\"%s\"",	*(char **)obj);
}

static void pb_msg_unk(void *obj, pb_pr_ctl_t *ctl)
{
	pr_msg("unknown object %p\n", obj);
}

static inline void print_tabs(pb_pr_ctl_t *ctl)
{
	int counter = ctl->depth;

	if (!ctl->single_entry)
		return;

	while (counter--)
		pr_msg("\t");
}

static void print_nested_message_braces(pb_pr_ctl_t *ctl, int right_brace)
{
	if (right_brace)
		print_tabs(ctl);
	pr_msg("%s%s", (right_brace) ? "}" : "{", (ctl->single_entry) ? "\n" : " ");
}

static void pb_show_msg(const void *msg, pb_pr_ctl_t *ctl);

static void show_nested_message(void *msg, pb_pr_ctl_t *ctl)
{
	print_nested_message_braces(ctl, 0);
	ctl->depth++;
	pb_show_msg(msg, ctl);
	ctl->depth--;
	print_nested_message_braces(ctl, 1);
}

static void show_enum(void *msg, pb_pr_ctl_t *ctl)
{
	ProtobufCEnumDescriptor *d = ctl->arg;
	const char *val_name = NULL;
	int val, i;

	val = *(int *)msg;
	for (i = 0; i < d->n_values; i++)
		if (d->values[i].value == val) {
			val_name = d->values[i].name;
			break;
		}

	if (val_name != NULL)
		pr_msg("%s", val_name);
	else
		pr_msg("%d", val);
}

static void show_bool(void *msg, pb_pr_ctl_t *ctl)
{
	protobuf_c_boolean val = *(protobuf_c_boolean *)msg;

	if (val)
		pr_msg("True");
	else
		pr_msg("False");
}

static void pb_show_field(const ProtobufCFieldDescriptor *fd, void *where,
			  unsigned long nr_fields, pb_pr_ctl_t *ctl)
{
	pb_pr_field_t *show;
	unsigned long counter;
	size_t fsize;

	print_tabs(ctl);

	pr_msg("%s: ", fd->name);

	switch (fd->type) {
		case PROTOBUF_C_TYPE_INT32:
		case PROTOBUF_C_TYPE_SINT32:
		case PROTOBUF_C_TYPE_UINT32:
		case PROTOBUF_C_TYPE_SFIXED32:
			show = pb_msg_int32x;
			fsize = 4;
			break;
		case PROTOBUF_C_TYPE_INT64:
		case PROTOBUF_C_TYPE_SINT64:
		case PROTOBUF_C_TYPE_SFIXED64:
		case PROTOBUF_C_TYPE_FIXED32:
		case PROTOBUF_C_TYPE_UINT64:
		case PROTOBUF_C_TYPE_FIXED64:
			show = pb_msg_int64x;
			fsize = 8;
			break;
		case PROTOBUF_C_TYPE_STRING:
			show = pb_msg_string;
			fsize = sizeof (void *);
			break;
		case PROTOBUF_C_TYPE_MESSAGE:
			where = (void *)(*(long *)where);
			ctl->arg = (void *)fd->descriptor;
			show = show_nested_message;
			fsize = sizeof (void *);
			break;
		case PROTOBUF_C_TYPE_ENUM:
			show = show_enum;
			ctl->arg = (void *)fd->descriptor;
			fsize = 4;
			break;
		case PROTOBUF_C_TYPE_BOOL:
			show = show_bool;
			fsize = 4;
			break;
		case PROTOBUF_C_TYPE_FLOAT:
		case PROTOBUF_C_TYPE_DOUBLE:
		case PROTOBUF_C_TYPE_BYTES:
		default:
			show = pb_msg_unk;
			nr_fields = 1;
			break;
	}

	show(where, ctl);
	where += fsize;

	for (counter = 0; counter < nr_fields - 1; counter++, where += fsize) {
		pr_msg(":");
		show(where, ctl);
	}

	if (ctl->single_entry)
		pr_msg("\n");
	else
		pr_msg(" ");
}

static int pb_optional_field_present(const ProtobufCFieldDescriptor *field,
				    void *msg)
{
	if ((field->type == PROTOBUF_C_TYPE_MESSAGE) ||
		(field->type == PROTOBUF_C_TYPE_STRING)) {
		const void *opt_flag = * (const void * const *)(msg + field->offset);

		if ((opt_flag == NULL) || (opt_flag == field->default_value))
			return 0;
	} else {
		const protobuf_c_boolean *has = msg + field->quantifier_offset;

		if (!*has)
			return 0;
	}
	return 1;
}

static void pb_show_msg(const void *msg, pb_pr_ctl_t *ctl)
{
	int i;
	const ProtobufCMessageDescriptor *md = ctl->arg;

	BUG_ON(md == NULL);

	for (i = 0; i < md->n_fields; i++) {
		const ProtobufCFieldDescriptor fd = md->fields[i];
		unsigned long *data;
		size_t nr_fields;

		nr_fields = 1;
		data = (unsigned long *)(msg + fd.offset);

		if (fd.label == PROTOBUF_C_LABEL_OPTIONAL) {
			if (!pb_optional_field_present(&fd, data))
				continue;
		}

		if (fd.label == PROTOBUF_C_LABEL_REPEATED) {
			nr_fields = *(size_t *)(msg + fd.quantifier_offset);
			data = (unsigned long *)*data;
		}

		pb_show_field(&fd, data, nr_fields, ctl);
	}
}

static inline void pb_no_payload(int fd, void *obj, int flags) { }

void do_pb_show_plain(int fd, int type, int single_entry,
		void (*payload_hadler)(int fd, void *obj, int flags),
		int flags)
{
	pb_pr_ctl_t ctl = {NULL, single_entry, 0};
	void (*handle_payload)(int fd, void *obj, int flags);

	if (!cr_pb_descs[type].pb_desc) {
		pr_err("Wrong object requested %d\n", type);
		return;
	}

	handle_payload = (payload_hadler) ? : pb_no_payload;

	while (1) {
		void *obj;

		if (pb_read_one_eof(fd, &obj, type) <= 0)
			break;

		ctl.arg = (void *)cr_pb_descs[type].pb_desc;
		pb_show_msg(obj, &ctl);
		handle_payload(fd, obj, flags);
		cr_pb_descs[type].free(obj, NULL);
		if (single_entry)
			break;
		pr_msg("\n");
	}
}

/*
 * Reads PB record (header + packed object) from file @fd and unpack
 * it with @unpack procedure to the pointer @pobj
 *
 *  1 on success
 * -1 on error (or EOF met and @eof set to false)
 *  0 on EOF and @eof set to true
 *
 * Don't forget to free memory granted to unpacked object in calling code if needed
 */

int do_pb_read_one(int fd, void **pobj, int type, bool eof)
{
	u8 local[PB_PKOBJ_LOCAL_SIZE];
	void *buf = (void *)&local;
	u32 size;
	int ret;

	if (!cr_pb_descs[type].pb_desc) {
		pr_err("Wrong object requested %d\n", type);
		return -1;
	}

	*pobj = NULL;

	ret = read(fd, &size, sizeof(size));
	if (ret == 0) {
		if (eof) {
			return 0;
		} else {
			pr_err("Unexpected EOF\n");
			return -1;
		}
	} else if (ret < sizeof(size)) {
		pr_perror("Read %d bytes while %d expected",
			  ret, (int)sizeof(size));
		return -1;
	}

	if (size > sizeof(local)) {
		ret = -1;
		buf = xmalloc(size);
		if (!buf)
			goto err;
	}

	ret = read(fd, buf, size);
	if (ret < 0) {
		pr_perror("Can't read %d bytes from file", size);
		goto err;
	} else if (ret != size) {
		pr_perror("Read %d bytes while %d expected", ret, size);
		goto err;
	}

	*pobj = cr_pb_descs[type].unpack(NULL, size, buf);
	if (!*pobj) {
		ret = -1;
		pr_err("Failed unpacking object %p\n", pobj);
		goto err;
	}

	ret = 1;
err:
	if (buf != (void *)&local)
		xfree(buf);

	return ret;
}

/*
 * Writes PB record (header + packed object pointed by @obj)
 * to file @fd, using @getpksize to get packed size and @pack
 * to implement packing
 *
 *  0 on success
 * -1 on error
 */
int pb_write_one(int fd, void *obj, int type)
{
	u8 local[PB_PKOBJ_LOCAL_SIZE];
	void *buf = (void *)&local;
	u32 size, packed;
	int ret = -1;

	if (!cr_pb_descs[type].pb_desc) {
		pr_err("Wron object requested %d\n", type);
		return -1;
	}

	size = cr_pb_descs[type].getpksize(obj);
	if (size > (u32)sizeof(local)) {
		buf = xmalloc(size);
		if (!buf)
			goto err;
	}

	packed = cr_pb_descs[type].pack(obj, buf);
	if (packed != size) {
		pr_err("Failed packing PB object %p\n", obj);
		goto err;
	}

	ret = write(fd, &size, sizeof(size));
	if (ret != sizeof(size)) {
		ret = -1;
		pr_perror("Can't write %d bytes", (int)sizeof(size));
		goto err;
	}

	ret = write(fd, buf, size);
	if (ret != size) {
		ret = -1;
		pr_perror("Can't write %d bytes", size);
		goto err;
	}

	ret = 0;
err:
	if (buf != (void *)&local)
		xfree(buf);
	return ret;
}

int collect_image(int fd_t, int obj_t, unsigned size,
		int (*collect)(void *obj, ProtobufCMessage *msg))
{
	int fd, ret;

	fd = open_image_ro(fd_t);
	if (fd < 0)
		return -1;

	while (1) {
		void *obj;
		ProtobufCMessage *msg;

		if (size) {
			ret = -1;
			obj = xmalloc(size);
			if (!obj)
				break;
		} else
			obj = NULL;

		ret = pb_read_one_eof(fd, &msg, obj_t);
		if (ret <= 0) {
			xfree(obj);
			break;
		}

		ret = collect(obj, msg);
		if (ret < 0) {
			xfree(obj);
			cr_pb_descs[obj_t].free(msg, NULL);
			break;
		}
	}

	close(fd);
	return ret;
}
