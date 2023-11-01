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

	pr_info("Entered: %s\n", __func__);

	snprintf(path, sizeof(path), AMDGPU_DRM_DEVICE, DRM_FIRST_RENDER_NODE);
	ret = stat(path, &drm);
	if (ret == -1) {
		pr_err("Error in getting stat for: %s", path);
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

	pr_info("Sairam: %s(), Can handle VMA of input device\n", __func__);
	return 0;
}


