
#ifndef __AMDGPU_PLUGIN_DMABUF_H__
#define __AMDGPU_PLUGIN_DMABUF_H__

#include "amdgpu_plugin_util.h"
#include "criu-amdgpu.pb-c.h"

int amdgpu_plugin_dmabuf_dump(int fd, int id);
int amdgpu_plugin_dmabuf_restore(int id);

int try_dump_dmabuf_list();
int post_dump_dmabuf_check();

int get_dmabuf_info(int fd, struct stat *st);

#endif /* __AMDGPU_PLUGIN_DMABUF_H__ */