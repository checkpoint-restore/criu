#ifndef __CR_PROTOBUF_H__
#define __CR_PROTOBUF_H__

#include <stdbool.h>

#include "protobuf-desc.h"
#include "common/compiler.h"
#include "util.h"

struct cr_img;

extern int do_pb_read_one(struct cr_img *, void **objp, int type, bool eof);

#define pb_read_one(fd, objp, type) do_pb_read_one(fd, (void **)objp, type, false)
#define pb_read_one_eof(fd, objp, type) do_pb_read_one(fd, (void **)objp, type, true)

extern int pb_write_one(struct cr_img *, void *obj, int type);

#define pb_pksize(__obj, __proto_message_name)						\
	(__proto_message_name ##__get_packed_size(__obj) + sizeof(u32))

#define pb_repeated_size(__obj, __member)						\
	((size_t)(sizeof(*(__obj)->__member) * (__obj)->n_ ##__member))

#define pb_msg(__base, __type)			\
	container_of(__base, __type, base)

#include <google/protobuf-c/protobuf-c.h>

struct collect_image_info {
	int fd_type;
	int pb_type;
	unsigned int priv_size;
	int (*collect)(void *, ProtobufCMessage *, struct cr_img *);
	unsigned flags;
};

#define COLLECT_SHARED		0x1	/* use shared memory for obj-s */
#define COLLECT_NOFREE		0x2	/* don't free entry after callback */
#define COLLECT_HAPPENED	0x4	/* image was opened and collected */

extern int collect_image(struct collect_image_info *);
extern int collect_entry(ProtobufCMessage *base, struct collect_image_info *cinfo);

static inline int collect_images(struct collect_image_info **array, unsigned size)
{
	int i;
	for (i = 0; i < size; i++) {
		if (collect_image(array[i]))
			return -1;
	}
	return 0;
}

#endif /* __CR_PROTOBUF_H__ */
