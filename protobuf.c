#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>

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
int pb_read_object_with_header(int fd, void **pobj, pb_unpack_t *unpack, bool eof)
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
int pb_write_object_with_header(int fd, void *obj, pb_getpksize_t *getpksize, pb_pack_t *pack)
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
