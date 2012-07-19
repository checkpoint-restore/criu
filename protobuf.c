#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>

#include <google/protobuf-c/protobuf-c.h>

#include "compiler.h"
#include "types.h"
#include "log.h"
#include "util.h"

#include "protobuf.h"

/*
 * To speed up reading of packed objects
 * by providing space on stack, this should
 * be more than enough for most objects.
 */
#define PB_PKOBJ_LOCAL_SIZE	1024

typedef void (pb_pr_field_t)(void *obj, void *arg);

static void pb_msg_int32x(void *obj, void *arg)
{
	pr_msg("0x%08x", *(int *)obj);
}

static void pb_msg_int64x(void *obj, void *arg)
{
	pr_msg("0x%016lx", *(long *)obj);
}

static void pb_msg_string(void *obj, void *arg)
{
	pr_msg("\"%s\"",	*(char **)obj);
}

static void pb_msg_unk(void *obj, void *arg)
{
	pr_msg("unknown object %p\n", obj);
}

static void pb_show_msg(const void *msg, const ProtobufCMessageDescriptor *md);

static void show_nested_message(void *msg, void *md)
{
	pr_msg("[ ");
	pb_show_msg(msg, md);
	pr_msg(" ] ");
}

static void show_enum(void *msg, void *md)
{
	ProtobufCEnumDescriptor *d = md;
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

static void pb_show_field(const ProtobufCFieldDescriptor *fd, void *where,
			  unsigned long nr_fields)
{
	pb_pr_field_t *show;
	unsigned long counter;
	size_t fsize;
	void *arg;

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
			arg = (void *)fd->descriptor;
			show = show_nested_message;
			fsize = sizeof (void *);
			break;
		case PROTOBUF_C_TYPE_ENUM:
			show = show_enum;
			arg = (void *)fd->descriptor;
			break;
		case PROTOBUF_C_TYPE_FLOAT:
		case PROTOBUF_C_TYPE_DOUBLE:
		case PROTOBUF_C_TYPE_BOOL:
		case PROTOBUF_C_TYPE_BYTES:
		default:
			show = pb_msg_unk;
			nr_fields = 1;
			break;
	}

	show(where, arg);
	where += fsize;

	for (counter = 0; counter < nr_fields - 1; counter++, where += fsize) {
		pr_msg(":");
		show(where, arg);
	}

	pr_msg(" ");
}

static void pb_show_msg(const void *msg, const ProtobufCMessageDescriptor *md)
{
	int i;

	BUG_ON(md == NULL);

	for (i = 0; i < md->n_fields; i++) {
		const ProtobufCFieldDescriptor fd = md->fields[i];
		unsigned long *data;
		size_t nr_fields;

		if (fd.label == PROTOBUF_C_LABEL_OPTIONAL)
			continue;

		nr_fields = 1;
		data = (unsigned long *)(msg + fd.offset);

		if (fd.label == PROTOBUF_C_LABEL_REPEATED) {
			nr_fields = *(size_t *)(msg + fd.quantifier_offset);
			data = (unsigned long *)*data;
		}

		pb_show_field(&fd, data, nr_fields);
	}
}

void do_pb_show_plain(int fd, const ProtobufCMessageDescriptor *md,
		pb_unpack_t unpack, pb_free_t free)
{
	while (1) {
		void *obj;

		if (pb_read_object_with_header(fd, &obj, unpack, true) <= 0)
			break;

		pb_show_msg(obj, md);
		pr_msg("\n");
		free(obj, NULL);
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
int pb_read_object_with_header(int fd, void **pobj, pb_unpack_t unpack, bool eof)
{
	u8 local[PB_PKOBJ_LOCAL_SIZE];
	void *buf = (void *)&local;
	u32 size;
	int ret;

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

	*pobj = unpack(NULL, size, buf);
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
int pb_write_object_with_header(int fd, void *obj, pb_getpksize_t getpksize, pb_pack_t pack)
{
	u8 local[PB_PKOBJ_LOCAL_SIZE];
	void *buf = (void *)&local;
	u32 size, packed;
	int ret = -1;

	size = getpksize(obj);
	if (size > (u32)sizeof(local)) {
		buf = xmalloc(size);
		if (!buf)
			goto err;
	}

	packed = pack(obj, buf);
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
