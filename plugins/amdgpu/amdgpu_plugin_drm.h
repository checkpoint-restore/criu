#ifndef __AMDGPU_PLUGIN_DRM_H__
#define __AMDGPU_PLUGIN_DRM_H__

#include <dirent.h>
#include "common/list.h"

#include "xmalloc.h"
#include "criu-log.h"
#include "kfd_ioctl.h"
#include "amdgpu_plugin_util.h"
#include "amdgpu_plugin_topology.h"


/**
 * Determines if VMA's of input file descriptor belong to amdgpu's
 * DRM device and are therefore supported
 */
int amdgpu_plugin_drm_handle_device_vma(int fd, const struct stat *drm);

/**
 * Serialize meta-data about a particular DRM device, its number of BOs,
 * etc into a file. The serialized filename has in it the value ID that
 * is passed in as a parameter
 */
int amdgpu_plugin_drm_dump_file(int fd, int id, struct stat *drm);

#endif		/* __AMDGPU_PLUGIN_DRM_H__ */

