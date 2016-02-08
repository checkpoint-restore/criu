#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <ctype.h>

#include <google/protobuf-c/protobuf-c.h>

#include "image.h"
#include "servicefd.h"
#include "compiler.h"
#include "asm/types.h"
#include "log.h"
#include "util.h"
#include "string.h"
#include "sockets.h"
#include "cr_options.h"
#include "bfd.h"
#include "protobuf.h"

/*
 * To speed up reading of packed objects
 * by providing space on stack, this should
 * be more than enough for most objects.
 */
#define PB_PKOBJ_LOCAL_SIZE	1024

static char *image_name(struct cr_img *img)
{
	int fd = img->_x.fd;
	static char image_path[PATH_MAX];

	if (read_fd_link(fd, image_path, sizeof(image_path)) > 0)
		return image_path;
	return NULL;
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

int do_pb_read_one(struct cr_img *img, void **pobj, int type, bool eof)
{
	u8 local[PB_PKOBJ_LOCAL_SIZE];
	void *buf = (void *)&local;
	u32 size;
	int ret;

	if (!cr_pb_descs[type].pb_desc) {
		pr_err("Wrong object requested %d on %s\n",
			type, image_name(img));
		return -1;
	}

	*pobj = NULL;

	if (unlikely(empty_image(img)))
		ret = 0;
	else
		ret = bread(&img->_x, &size, sizeof(size));
	if (ret == 0) {
		if (eof) {
			return 0;
		} else {
			pr_err("Unexpected EOF on %s\n",
			       image_name(img));
			return -1;
		}
	} else if (ret < sizeof(size)) {
		pr_perror("Read %d bytes while %d expected on %s",
			  ret, (int)sizeof(size),
			  image_name(img));
		return -1;
	}

	if (size > sizeof(local)) {
		ret = -1;
		buf = xmalloc(size);
		if (!buf)
			goto err;
	}

	ret = bread(&img->_x, buf, size);
	if (ret < 0) {
		pr_perror("Can't read %d bytes from file %s",
			  size, image_name(img));
		goto err;
	} else if (ret != size) {
		pr_perror("Read %d bytes while %d expected from %s",
			  ret, size, image_name(img));
		ret = -1;
		goto err;
	}

	*pobj = cr_pb_descs[type].unpack(NULL, size, buf);
	if (!*pobj) {
		ret = -1;
		pr_err("Failed unpacking object %p from %s\n",
		       pobj, image_name(img));
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
int pb_write_one(struct cr_img *img, void *obj, int type)
{
	u8 local[PB_PKOBJ_LOCAL_SIZE];
	void *buf = (void *)&local;
	u32 size, packed;
	int ret = -1;
	struct iovec iov[2];

	if (!cr_pb_descs[type].pb_desc) {
		pr_err("Wrong object requested %d\n", type);
		return -1;
	}

	if (lazy_image(img) && open_image_lazy(img))
		return -1;

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

	iov[0].iov_base = &size;
	iov[0].iov_len = sizeof(size);
	iov[1].iov_base = buf;
	iov[1].iov_len = size;

	ret = bwritev(&img->_x, iov, 2);
	if (ret != size + sizeof(size)) {
		pr_perror("Can't write %d bytes", (int)(size + sizeof(size)));
		goto err;
	}

	ret = 0;
err:
	if (buf != (void *)&local)
		xfree(buf);
	return ret;
}

int collect_image(struct collect_image_info *cinfo)
{
	int ret;
	struct cr_img *img;
	void *(*o_alloc)(size_t size) = malloc;
	void (*o_free)(void *ptr) = free;

	pr_info("Collecting %d/%d (flags %x)\n",
			cinfo->fd_type, cinfo->pb_type, cinfo->flags);

	img = open_image(cinfo->fd_type, O_RSTR);
	if (!img)
		return -1;

	cinfo->flags |= COLLECT_HAPPENED;
	if (cinfo->flags & COLLECT_SHARED) {
		o_alloc = shmalloc;
		o_free = shfree_last;
	}

	while (1) {
		void *obj;
		ProtobufCMessage *msg;

		if (cinfo->priv_size) {
			ret = -1;
			obj = o_alloc(cinfo->priv_size);
			if (!obj)
				break;
		} else
			obj = NULL;

		ret = pb_read_one_eof(img, &msg, cinfo->pb_type);
		if (ret <= 0) {
			o_free(obj);
			break;
		}

		ret = cinfo->collect(obj, msg);
		if (ret < 0) {
			o_free(obj);
			cr_pb_descs[cinfo->pb_type].free(msg, NULL);
			break;
		}

		if (!cinfo->priv_size)
			cr_pb_descs[cinfo->pb_type].free(msg, NULL);
	}

	close_image(img);
	pr_debug(" `- ... done\n");
	return ret;
}
