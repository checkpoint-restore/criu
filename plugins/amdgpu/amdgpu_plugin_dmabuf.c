#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <linux/limits.h>

#include "common/list.h"
#include "criu-amdgpu.pb-c.h"

#include "xmalloc.h"
#include "criu-log.h"
#include "amdgpu_plugin_drm.h"
#include "amdgpu_plugin_util.h"
#include "amdgpu_plugin_dmabuf.h"
#include "fdstore.h"

#include "util.h"
#include "common/scm.h"

struct dmabuf {
	int id;
	int dmabuf_fd;
	struct list_head node;
};

static LIST_HEAD(dmabuf_list);

/* Return < 0 for error, > 0 for "not a dmabuf" and 0 "is a dmabuf" */
int get_dmabuf_info(int fd, struct stat *st)
{
	char path[PATH_MAX];

	if (read_fd_link(fd, path, sizeof(path)) < 0)
		return -1;

	if (strncmp(path, DMABUF_LINK, strlen(DMABUF_LINK)) != 0)
		return 1;

	return 0;
}

int __amdgpu_plugin_dmabuf_dump(int dmabuf_fd, int id)
{
	int ret = 0;
	char path[PATH_MAX];
	size_t len = 0;
	unsigned char *buf = NULL;
	int gem_handle;

	pr_info("TWI: Dumping dmabuf fd = %d\n", dmabuf_fd);

	gem_handle = handle_for_shared_bo_fd(dmabuf_fd);
	if (gem_handle < 0) {
		pr_err("Failed to get handle for dmabuf_fd = %d\n", dmabuf_fd);
		return -EAGAIN; /* Retry needed */
	}

	CriuDmabufNode *node = xmalloc(sizeof(*node));
	if (!node) {
		pr_err("Failed to allocate memory for dmabuf node\n");
		return -ENOMEM;
	}
	criu_dmabuf_node__init(node);

	node->gem_handle = gem_handle;

	if (node->gem_handle < 0) {
		pr_err("Failed to get handle for dmabuf_fd\n");
		xfree(node);
		return -EINVAL;
	}

	/* Serialize metadata to a file */
	snprintf(path, sizeof(path), IMG_DMABUF_FILE, id);
	len = criu_dmabuf_node__get_packed_size(node);
	buf = xmalloc(len);
	if (!buf) {
		pr_err("Failed to allocate buffer for dmabuf metadata\n");
		xfree(node);
		return -ENOMEM;
	}
	criu_dmabuf_node__pack(node, buf);
	ret = write_img_file(path, buf, len);

	xfree(buf);
	xfree(node);
	return ret;
}

int amdgpu_plugin_dmabuf_restore(int id)
{
	char path[PATH_MAX];
	size_t img_size;
	FILE *img_fp = NULL;
	int ret = 0;
	CriuDmabufNode *rd = NULL;
	unsigned char *buf = NULL;
	int fd_id;

	snprintf(path, sizeof(path), IMG_DMABUF_FILE, id);

	pr_info("TWI: Restoring dmabuf fd, id = %d\n", id);

	/* Read serialized metadata */
	img_fp = open_img_file(path, false, &img_size);
	if (!img_fp) {
		pr_err("Failed to open dmabuf metadata file: %s\n", path);
		return -EINVAL;
	}

	pr_debug("dmabuf Image file size:%ld\n", img_size);
	buf = xmalloc(img_size);
	if (!buf) {
		pr_perror("Failed to allocate memory");
		return -ENOMEM;
	}

	ret = read_fp(img_fp, buf, img_size);
	if (ret) {
		pr_perror("Unable to read from %s", path);
		xfree(buf);
		return ret;
	}

	rd = criu_dmabuf_node__unpack(NULL, img_size, buf);
	if (rd == NULL) {
		pr_perror("Unable to parse the dmabuf message %d", id);
		xfree(buf);
		fclose(img_fp);
		return -1;
	}
	fclose(img_fp);

	pr_info("TWI: dmabuf node gem_handle = %d\n", rd->gem_handle);

	/* Match GEM handle with shared_dmabuf list */
	fd_id = amdgpu_id_for_handle(rd->gem_handle);
	if (fd_id == -1) {
		pr_err("Failed to find dmabuf_fd for GEM handle = %d\n",
		       rd->gem_handle);
		return 1;
	}
	int dmabuf_fd = fdstore_get(fd_id);
	pr_info("TWI: dmabuf node fd_id = %d, dmabuf_fd = %d\n", fd_id, dmabuf_fd);
	if (dmabuf_fd == -1) {
		pr_err("Failed to find dmabuf_fd for GEM handle = %d\n",
		       rd->gem_handle);
		return 1; /* Retry needed */
	} else {
		pr_info("Restored dmabuf_fd = %d for GEM handle = %d\n",
			dmabuf_fd, rd->gem_handle);
	}
	ret = dmabuf_fd;

	pr_info("Successfully restored dmabuf_fd %d\n",
		dmabuf_fd);
	criu_dmabuf_node__free_unpacked(rd, NULL);
	xfree(buf);
	return ret;
}

int amdgpu_plugin_dmabuf_dump(int dmabuf_fd, int id)
{
	int ret;

	ret = __amdgpu_plugin_dmabuf_dump(dmabuf_fd, id);
	if (ret == -EAGAIN) {
		struct dmabuf *b = xmalloc(sizeof(*b));
		b->id = id;
		b->dmabuf_fd = dmabuf_fd;
		list_add(&b->node, &dmabuf_list);
		return 0;
	}
	return ret;
}

int try_dump_dmabuf_list()
{
	struct dmabuf *b, *t;
	list_for_each_entry_safe(b, t, &dmabuf_list, node) {
		int ret = __amdgpu_plugin_dmabuf_dump(b->dmabuf_fd, b->id);
		if (ret == -EAGAIN)
			continue;
		else if (ret)
			return ret;
		list_del(&b->node);
		xfree(b);
	}
	return 0;
}

int post_dump_dmabuf_check()
{
	if (!list_empty(&dmabuf_list)) {
		pr_err("Not all dma buffers have been dumped\n");
		return -1;
	}
	return 1;
}