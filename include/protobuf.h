#ifndef __CR_PROTOBUF_H__
#define __CR_PROTOBUF_H__

#include "protobuf-desc.h"

#include "asm/types.h"
#include "compiler.h"
#include "util.h"

extern int do_pb_read_one(int fd, void **objp, int type, bool eof);

#define pb_read_one(fd, objp, type) do_pb_read_one(fd, (void **)objp, type, false)
#define pb_read_one_eof(fd, objp, type) do_pb_read_one(fd, (void **)objp, type, true)

extern int pb_write_one(int fd, void *obj, int type);

#define pb_pksize(__obj, __proto_message_name)						\
	(__proto_message_name ##__get_packed_size(__obj) + sizeof(u32))

#define pb_repeated_size(__obj, __member)						\
	((size_t)(sizeof(*(__obj)->__member) * (__obj)->n_ ##__member))

#define pb_msg(__base, __type)			\
	container_of(__base, __type, base)

#include <google/protobuf-c/protobuf-c.h>

extern void do_pb_show_plain(int fd, int type, int single_entry,
		void (*payload_hadler)(int fd, void *obj),
		const char *pretty_fmt);

/* Don't have objects at hands to also do typechecking here */
#define pb_show_plain_payload_pretty(__fd, __type, payload_hadler, pretty)	\
	do_pb_show_plain(__fd, __type, 0, payload_hadler, pretty)

#define pb_show_plain_payload(__fd, __proto_message_name, payload_hadler)	\
	pb_show_plain_payload_pretty(__fd, __proto_message_name, payload_hadler, NULL)

#define pb_show_plain_pretty(__fd, __proto_message_name, __pretty)		\
	pb_show_plain_payload_pretty(__fd, __proto_message_name, NULL, __pretty)

struct collect_image_info {
	int fd_type;
	int pb_type;
	unsigned int priv_size;
	int (*collect)(void *, ProtobufCMessage *);
	unsigned flags;
};

#define COLLECT_SHARED		0x1	/* use shared memory for obj-s */
#define COLLECT_OPTIONAL	0x2	/* image file may be missing */

int collect_image(struct collect_image_info *);

#endif /* __CR_PROTOBUF_H__ */
