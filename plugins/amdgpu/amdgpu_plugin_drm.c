#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>

#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <linux/limits.h>

#include <dirent.h>
#include "common/list.h"

#include "criu-amdgpu.pb-c.h"

#include <xf86drm.h>
#include <libdrm/amdgpu.h>

#include "xmalloc.h"
#include "criu-log.h"
#include "kfd_ioctl.h"
#include "amdgpu_plugin_drm.h"
#include "amdgpu_plugin_util.h"
#include "amdgpu_plugin_topology.h"


int amdgpu_plugin_drm_handle_device_vma(int fd, const struct stat *st)
{
	char path[PATH_MAX];
	struct stat drm;
	int ret = 0;

	snprintf(path, sizeof(path), AMDGPU_DRM_DEVICE, DRM_FIRST_RENDER_NODE);
	ret = stat(path, &drm);
	if (ret == -1) {
		pr_err("Error in getting stat for: %s\n", path);
		return ret;
	}

	if ((major(st->st_rdev) != major(drm.st_rdev)) ||
		(minor(st->st_rdev) < minor(drm.st_rdev)) ||
		(minor(st->st_rdev) > DRM_LAST_RENDER_NODE)) {
		pr_err("Can't handle VMA mapping of input device\n");
		return -ENOTSUP;
	}

	pr_debug("AMD DRI(maj,min) = %d:%d VMA Device FD(maj,min) = %d:%d\n",
			 major(drm.st_rdev), minor(drm.st_rdev),
			 major(st->st_rdev), minor(st->st_rdev));

	return 0;
}


int amdgpu_plugin_drm_dump_file(int fd, int id, struct stat *drm)
{
	CriuRenderNode rd = CRIU_RENDER_NODE__INIT;
	struct tp_node *tp_node;
	char path[PATH_MAX];
	unsigned char *buf;
	int minor;
	int len;
	int ret;

	/* Get the topology node of the DRM device */
	minor = minor(drm->st_rdev);
	tp_node = sys_get_node_by_render_minor(&src_topology, minor);
	if (!tp_node) {
		pr_err("Failed to find a device with minor number = %d\n", minor);
		return -ENODEV;
	}

	/* Get the GPU_ID of the DRM device */
	rd.gpu_id = maps_get_dest_gpu(&checkpoint_maps, tp_node->gpu_id);
	if (!rd.gpu_id) {
		pr_err("Failed to find valid gpu_id for the device = %d\n", rd.gpu_id);
		return -ENODEV;
	}

	len = criu_render_node__get_packed_size(&rd);
	buf = xmalloc(len);
	if (!buf)
		return -ENOMEM;

	criu_render_node__pack(&rd, buf);

	snprintf(path, sizeof(path), IMG_DRM_FILE, id);
	ret = write_img_file(path, buf, len);
	xfree(buf);
	return ret;
}
