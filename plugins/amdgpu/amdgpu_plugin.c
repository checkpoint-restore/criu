#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <linux/limits.h>

#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <stdint.h>

#include "criu-plugin.h"
#include "criu-amdgpu.pb-c.h"

#include "kfd_ioctl.h"
#include "xmalloc.h"
#include "criu-log.h"

#include "common/list.h"

#define DRM_FIRST_RENDER_NODE 128
#define DRM_LAST_RENDER_NODE 255

#define PROCPIDMEM      "/proc/%d/mem"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

struct vma_metadata {
	struct list_head list;
	uint64_t old_pgoff;
	uint64_t new_pgoff;
	uint64_t vma_entry;
};

static LIST_HEAD(update_vma_info_list);

int open_drm_render_device(int minor)
{
	char path[128];
	int fd;

	if (minor < DRM_FIRST_RENDER_NODE || minor > DRM_LAST_RENDER_NODE) {
		pr_perror("DRM render minor %d out of range [%d, %d]\n", minor,
			  DRM_FIRST_RENDER_NODE, DRM_LAST_RENDER_NODE);
		return -EINVAL;
	}

	sprintf(path, "/dev/dri/renderD%d", minor);
	fd = open(path, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		if (errno != ENOENT && errno != EPERM) {
			pr_err("Failed to open %s: %s\n", path, strerror(errno));
			if (errno == EACCES)
				pr_err("Check user is in \"video\" group\n");
		}
		return -EBADFD;
	}

	return fd;
}

/* Call ioctl, restarting if it is interrupted */
int kmtIoctl(int fd, unsigned long request, void *arg)
{
        int ret;

        do {
                ret = ioctl(fd, request, arg);
        } while (ret == -1 && (errno == EINTR || errno == EAGAIN));

        if (ret == -1 && errno == EBADF)
		/* In case pthread_atfork didn't catch it, this will
                 * make any subsequent hsaKmt calls fail in CHECK_KFD_OPEN.
                 */
		pr_perror("KFD file descriptor not valid in this process\n");
	return ret;
}

static void free_e(CriuKfd *e)
{
	for (int i = 0; i < e->n_bo_info_test; i++) {
		if (e->bo_info_test[i]->bo_rawdata.data)
			xfree(e->bo_info_test[i]->bo_rawdata.data);
		if (e->bo_info_test[i])
			xfree(e->bo_info_test[i]);
	}
	for (int i = 0; i < e->n_devinfo_entries; i++) {
		if (e->devinfo_entries[i])
			xfree(e->devinfo_entries[i]);
	}
	xfree(e);
}

static int allocate_devinfo_entries(CriuKfd *e, int num_of_devices)
{
	e->devinfo_entries = xmalloc(sizeof(DevinfoEntry) * num_of_devices);
	if (!e->devinfo_entries) {
		pr_err("Failed to allocate devinfo_entries\n");
		return -1;
	}

	for (int i = 0; i < num_of_devices; i++)
	{
		DevinfoEntry *entry = xmalloc(sizeof(DevinfoEntry));
		if (!entry) {
			pr_err("Failed to allocate entry\n");
			return -ENOMEM;
		}

		devinfo_entry__init(entry);

		e->devinfo_entries[i] = entry;
		e->n_devinfo_entries++;

	}
	return 0;
}

static int allocate_bo_info_test(CriuKfd *e, int num_bos, struct kfd_criu_bo_buckets *bo_bucket_ptr)
{
	e->bo_info_test = xmalloc(sizeof(BoEntriesTest*) * num_bos);
	if (!e->bo_info_test) {
		pr_err("Failed to allocate bo_info\n");
		return -ENOMEM;
	}

	pr_info("Inside allocate_bo_info_test\n");
	for (int i = 0; i < num_bos; i++)
	{
		BoEntriesTest *botest;
		botest = xmalloc(sizeof(*botest));
		if (!botest) {
			pr_err("Failed to allocate botest\n");
			return -ENOMEM;
		}

		bo_entries_test__init(botest);

		if ((bo_bucket_ptr)[i].bo_alloc_flags &
		    KFD_IOC_ALLOC_MEM_FLAGS_VRAM ||
		    (bo_bucket_ptr)[i].bo_alloc_flags &
		    KFD_IOC_ALLOC_MEM_FLAGS_GTT) {
			botest->bo_rawdata.data = xmalloc((bo_bucket_ptr)[i].bo_size);
			botest->bo_rawdata.len = (bo_bucket_ptr)[i].bo_size;
		}

		e->bo_info_test[i] = botest;
		e->n_bo_info_test++;

	}

	return 0;
}

int amdgpu_plugin_init(int stage)
{
	pr_info("amdgpu_plugin: initialized:  %s (AMDGPU/KFD)\n",
						CR_PLUGIN_DESC.name);
	return 0;
}

void amdgpu_plugin_fini(int stage, int ret)
{
	pr_info("amdgpu_plugin: finished  %s (AMDGPU/KFD)\n", CR_PLUGIN_DESC.name);
}

CR_PLUGIN_REGISTER("amdgpu_plugin", amdgpu_plugin_init, amdgpu_plugin_fini)

int amdgpu_plugin_dump_file(int fd, int id)
{
	struct kfd_ioctl_criu_helper_args helper_args = {0};
	struct kfd_criu_devinfo_bucket *devinfo_bucket_ptr;
	struct kfd_ioctl_criu_dumper_args args = {0};
	struct kfd_criu_bo_buckets *bo_bucket_ptr;
	int img_fd, ret, len, mem_fd, drm_fd;
	char img_path[PATH_MAX];
	struct stat st, st_kfd;
	unsigned char *buf;
	char fd_path[128];
	uint8_t *local_buf;
	char *fname;
	void *addr;

	pr_debug("amdgpu_plugin: Enter cr_plugin_dump_file()- ID = 0x%x\n", id);
	ret = 0;
	CriuKfd *e;

	if (fstat(fd, &st) == -1) {
		pr_perror("amdgpu_plugin: fstat error");
		return -1;
	}

	ret = stat("/dev/kfd", &st_kfd);
	if (ret == -1) {
		pr_perror("amdgpu_plugin: fstat error for /dev/kfd\n");
		return -1;
	}

	/* Check whether this plugin was called for kfd or render nodes */
	if (major(st.st_rdev) != major(st_kfd.st_rdev) ||
		 minor(st.st_rdev) != 0) {
		/* This is RenderD dumper plugin, for now just save renderD
		 * minor number to be used during restore. In later phases this
		 * needs to save more data for video decode etc.
		 */

		CriuRenderNode rd = CRIU_RENDER_NODE__INIT;
		pr_info("amdgpu_plugin: Dumper called for /dev/dri/renderD%d, FD = %d, ID = %d\n", minor(st.st_rdev), fd, id);

		rd.minor_number = minor(st.st_rdev);
		snprintf(img_path, sizeof(img_path), "renderDXXX.%d.img", id);

		img_fd = openat(criu_get_image_dir(), img_path, O_WRONLY | O_CREAT, 0600);
		if (img_fd < 0) {
			pr_perror("Can't open %s", img_path);
			return -1;
		}

		len = criu_render_node__get_packed_size(&rd);
		buf = xmalloc(len);
		if (!buf)
			return -ENOMEM;

		criu_render_node__pack(&rd, buf);
		ret = write(img_fd,  buf, len);

		if (ret != len) {
			pr_perror("Unable to write in %s", img_path);
			ret = -1;
		}
		xfree(buf);
		close(img_fd);

		/* Need to return success here so that criu can call plugins for
		 * renderD nodes */
		return ret;
	}

	pr_info("amdgpu_plugin: %s : %s() called for fd = %d\n", CR_PLUGIN_DESC.name,
		  __func__, major(st.st_rdev));

	if (kmtIoctl(fd, AMDKFD_IOC_CRIU_HELPER, &helper_args) == -1) {
		pr_perror("amdgpu_plugin: failed to call helper ioctl\n");
		return -1;
	}

	args.num_of_devices = helper_args.num_of_devices;
	devinfo_bucket_ptr = xmalloc(helper_args.num_of_devices * sizeof(*devinfo_bucket_ptr));

	if (!devinfo_bucket_ptr) {
		pr_perror("amdgpu_plugin: failed to allocate devinfo for dumper ioctl\n");
		return -ENOMEM;
	}
	args.kfd_criu_devinfo_buckets_ptr = (uintptr_t)devinfo_bucket_ptr;

	pr_info("amdgpu_plugin: num of bos = %llu\n", helper_args.num_of_bos);

	bo_bucket_ptr = xmalloc(helper_args.num_of_bos * sizeof(*bo_bucket_ptr));

	if (!bo_bucket_ptr) {
		pr_perror("amdgpu_plugin: failed to allocate args for dumper ioctl\n");
		return -ENOMEM;
	}

	args.num_of_bos = helper_args.num_of_bos;
	args.kfd_criu_bo_buckets_ptr = (uintptr_t)bo_bucket_ptr;

	/* call dumper ioctl, pass num of BOs to dump */
        if (kmtIoctl(fd, AMDKFD_IOC_CRIU_DUMPER, &args) == -1) {
		pr_perror("amdgpu_plugin: failed to call kfd ioctl from plugin dumper for fd = %d\n", major(st.st_rdev));
		xfree(bo_bucket_ptr);
		return -1;
	}

	pr_info("amdgpu_plugin: success in calling dumper ioctl\n");

	e = xmalloc(sizeof(*e));
	if (!e) {
		pr_err("Failed to allocate proto structure\n");
		xfree(bo_bucket_ptr);
		return -ENOMEM;
	}

	criu_kfd__init(e);
	e->pid = helper_args.task_pid;

	ret = allocate_devinfo_entries(e, args.num_of_devices);
	if (ret) {
		ret = -ENOMEM;
		goto failed;
	}

	/* When checkpointing on a node where there was already a checkpoint-restore before, the
	 * user_gpu_id and actual_gpu_id will be different.
	 *
	 * For now, we assume the user_gpu_id and actual_gpu_id is the same. Once we support
	 * restoring on a different node, then we will have a user_gpu_id to actual_gpu_id mapping.
	 */
	for (int i = 0; i < args.num_of_devices; i++) {
		e->devinfo_entries[i]->gpu_id = devinfo_bucket_ptr[i].user_gpu_id;
		if (devinfo_bucket_ptr[i].user_gpu_id != devinfo_bucket_ptr[i].actual_gpu_id) {
			pr_err("Checkpoint-Restore on different node not supported yet\n");
			ret = -ENOTSUP;
			goto failed;
		}
	}

	e->num_of_devices = args.num_of_devices;

	ret = allocate_bo_info_test(e, helper_args.num_of_bos, bo_bucket_ptr);
	if (ret)
		return -1;

	sprintf(fd_path, "/dev/dri/renderD%d", DRM_FIRST_RENDER_NODE);
	drm_fd = open(fd_path, O_RDWR | O_CLOEXEC);
	if (drm_fd < 0) {
		pr_perror("amdgpu_plugin: failed to open drm fd for %s\n", fd_path);
		return -1;
	}

	for (int i = 0; i < helper_args.num_of_bos; i++)
	{
		(e->bo_info_test[i])->bo_addr = (bo_bucket_ptr)[i].bo_addr;
		(e->bo_info_test[i])->bo_size = (bo_bucket_ptr)[i].bo_size;
		(e->bo_info_test[i])->bo_offset = (bo_bucket_ptr)[i].bo_offset;
		(e->bo_info_test[i])->gpu_id = (bo_bucket_ptr)[i].gpu_id;
		(e->bo_info_test[i])->bo_alloc_flags = (bo_bucket_ptr)[i].bo_alloc_flags;
		(e->bo_info_test[i])->idr_handle = (bo_bucket_ptr)[i].idr_handle;
		(e->bo_info_test[i])->user_addr = (bo_bucket_ptr)[i].user_addr;

		local_buf = xmalloc((bo_bucket_ptr)[i].bo_size);
		if (!local_buf) {
			pr_err("failed to allocate memory for BO rawdata\n");
			ret = -1;
			goto failed;
		}

		if ((bo_bucket_ptr)[i].bo_alloc_flags & KFD_IOC_ALLOC_MEM_FLAGS_VRAM) {
			pr_info("VRAM BO Found\n");
		}

		if ((bo_bucket_ptr)[i].bo_alloc_flags & KFD_IOC_ALLOC_MEM_FLAGS_GTT) {
			pr_info("GTT BO Found\n");
		}

		if ((bo_bucket_ptr)[i].bo_alloc_flags &
		    KFD_IOC_ALLOC_MEM_FLAGS_VRAM ||
		    (bo_bucket_ptr)[i].bo_alloc_flags &
		    KFD_IOC_ALLOC_MEM_FLAGS_GTT) {
			if ((e->bo_info_test[i])->bo_alloc_flags &
			    KFD_IOC_ALLOC_MEM_FLAGS_PUBLIC) {
				pr_info("amdgpu_plugin: large bar read possible\n");
				addr = mmap(NULL,
					    (bo_bucket_ptr)[i].bo_size,
					    PROT_READ,
					    MAP_SHARED,
					    drm_fd,	/* mapping on local gpu for prototype */
					    (bo_bucket_ptr)[i].bo_offset);
				if (addr == MAP_FAILED) {
					pr_perror("amdgpu_plugin: mmap failed\n");
					fd = -EBADFD;
					close(drm_fd);
					goto failed;
				}

				/* direct memcpy is possible on large bars */
				memcpy((e->bo_info_test[i])->bo_rawdata.data,
				       addr, bo_bucket_ptr[i].bo_size);
				munmap(addr, bo_bucket_ptr[i].bo_size);

			} else {
				pr_info("Now try reading BO contents with /proc/pid/mem");
				if (asprintf (&fname, PROCPIDMEM, e->pid) < 0) {
					pr_perror("failed in asprintf, %s\n", fname);
					ret = -1;
					goto failed;
				}

				mem_fd = open (fname, O_RDONLY);
				if (mem_fd < 0) {
					pr_perror("Can't open %s for pid %d\n", fname, e->pid);
					free (fname);
					ret = -1;
					goto failed;
				}

				pr_info("Opened %s file for pid = %d\n", fname, e->pid);
				free (fname);
				if (lseek (mem_fd, (off_t) (bo_bucket_ptr)[i].bo_addr, SEEK_SET) == -1) {
					pr_perror("Can't lseek for bo_offset for pid = %d\n", e->pid);
					ret = -1;
					goto failed;
				}
				pr_info("Try to read file now\n");

				if (read(mem_fd, local_buf,
					 (e->bo_info_test[i])->bo_size) !=
				    (e->bo_info_test[i])->bo_size) {
					pr_perror("Can't read buffer\n");
					ret = -1;
					goto failed;
				}

				pr_info("log initial few bytes of the raw data for this BO\n");
				for (int i = 0; i < 10; i ++)
				{
					pr_info("0x%llx\n",((__u64*)local_buf)[i]);
				}

				close(mem_fd);
				memcpy((e->bo_info_test[i])->bo_rawdata.data,
				       (uint8_t*)local_buf,
				       (e->bo_info_test[i])->bo_size);
				xfree(local_buf);
			} /* PROCPIDMEM read done */
		}
	}
	close(drm_fd);

	e->num_of_bos = helper_args.num_of_bos;

	pr_info("Dumping bo_info_test \n");
	for (int i = 0; i < helper_args.num_of_bos; i++)
	{
		pr_info("e->bo_info_test[%d]:\n", i);
		pr_info("bo_addr = 0x%lx, bo_size = 0x%lx, bo_offset = 0x%lx, gpu_id = 0x%x, "
			"bo_alloc_flags = 0x%x, idr_handle = 0x%x\n",
		  (e->bo_info_test[i])->bo_addr,
		  (e->bo_info_test[i])->bo_size,
		  (e->bo_info_test[i])->bo_offset,
		  (e->bo_info_test[i])->gpu_id,
		  (e->bo_info_test[i])->bo_alloc_flags,
		  (e->bo_info_test[i])->idr_handle);

	}

	snprintf(img_path, sizeof(img_path), "kfd.%d.img", id);
	pr_info("amdgpu_plugin: img_path = %s", img_path);
	img_fd = openat(criu_get_image_dir(), img_path, O_WRONLY | O_CREAT, 0600);
	if (img_fd < 0) {
		pr_perror("Can't open %s", img_path);
		ret = -1;
		goto failed;
	}

	len = criu_kfd__get_packed_size(e);

	pr_info("amdgpu_plugin: Len = %d\n", len);

	buf = xmalloc(len);
	if (!buf) {
		pr_perror("failed to allocate memory\n");
		close(img_fd);
		ret = -ENOMEM;
		goto failed;
	}

	criu_kfd__pack(e, buf);

	ret = write(img_fd,  buf, len);
	if (ret != len) {
		pr_perror("Unable to write in %s", img_path);
		ret = -1;
		goto exit;
	}
exit:
	xfree(buf);
	close(img_fd);
failed:
	xfree(devinfo_bucket_ptr);
	xfree(bo_bucket_ptr);
	free_e(e);
	pr_info("amdgpu_plugin: Exiting from dumper for fd = %d\n", major(st.st_rdev));
        return ret;

}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__DUMP_EXT_FILE, amdgpu_plugin_dump_file)

int amdgpu_plugin_restore_file(int id)
{
	struct kfd_criu_devinfo_bucket *devinfo_bucket_ptr = NULL;
	int img_fd, len, fd, mem_fd;
	struct kfd_ioctl_criu_restorer_args args = {0};
	struct kfd_criu_bo_buckets *bo_bucket_ptr;
	__u64 *restored_bo_offsets_array;
	char img_path[PATH_MAX];
	struct stat filestat;
	unsigned char *buf;
	CriuRenderNode *rd;
	char *fname;
	CriuKfd *e;
	void *addr;

	pr_info("amdgpu_plugin: Initialized kfd plugin restorer with ID = %d\n", id);

	snprintf(img_path, sizeof(img_path), "kfd.%d.img", id);
	img_fd = openat(criu_get_image_dir(), img_path, O_RDONLY, 0600);
	if (img_fd < 0) {
		pr_perror("open(%s)", img_path);

		/* This is restorer plugin for renderD nodes. Since criu doesn't
		 * gurantee that they will be called before the plugin is called
		 * for kfd file descriptor, we need to make sure we open the render
		 * nodes only once and before /dev/kfd is open, the render nodes
		 * are open too. Generally, it is seen that during checkpoint and
		 * restore both, the kfd plugin gets called first.
		 */
		snprintf(img_path, sizeof(img_path), "renderDXXX.%d.img", id);
		img_fd = openat(criu_get_image_dir(), img_path, O_RDONLY, 0600);
		if (img_fd < 0) {
			pr_perror("open(%s)", img_path);
			return -ENOTSUP;
		}

		if (stat(img_path, &filestat) == -1)
		{
			pr_perror("Failed to read file stats\n");
			return -1;
		}
		pr_info("renderD file size on disk = %ld\n", filestat.st_size);

		buf = xmalloc(filestat.st_size);
		if (!buf) {
			pr_perror("Failed to allocate memory\n");
			return -ENOMEM;
		}

		len = read(img_fd, buf, filestat.st_size);
		if (len <= 0) {
			pr_perror("Unable to read from %s", img_path);
			xfree(buf);
			close(img_fd);
			return -1;
		}
		close(img_fd);

		rd = criu_render_node__unpack(NULL, len, buf);
		if (rd == NULL) {
			pr_perror("Unable to parse the KFD message %d", id);
			xfree(buf);
			return -1;
		}

		pr_info("amdgpu_plugin: render node minor num = %d\n", rd->minor_number);
		fd = open_drm_render_device(rd->minor_number);
		criu_render_node__free_unpacked(rd,  NULL);
		xfree(buf);
		return fd;
	}

	fd = open("/dev/kfd", O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		pr_perror("failed to open kfd in plugin");
		return -1;
	}

	pr_info("amdgpu_plugin: Opened kfd, fd = %d\n", fd);


	if (stat(img_path, &filestat) == -1)
	{
		pr_perror("Failed to read file stats\n");
		return -1;
	}
	pr_info("kfd img file size on disk = %ld\n", filestat.st_size);

	buf = xmalloc(filestat.st_size);
	if (!buf) {
		pr_perror("Failed to allocate memory\n");
		close(img_fd);
		return -ENOMEM;
	}
	len = read(img_fd, buf, filestat.st_size);
	if (len <= 0) {
		pr_perror("Unable to read from %s", img_path);
		xfree(buf);
		close(img_fd);
		return -1;
	}
	close(img_fd);
	e = criu_kfd__unpack(NULL, len, buf);
	if (e == NULL) {
		pr_err("Unable to parse the KFD message %#x\n", id);
		xfree(buf);
		return -1;
	}

	pr_info("amdgpu_plugin: read image file data\n");

	devinfo_bucket_ptr = xmalloc(e->num_of_devices * sizeof(*devinfo_bucket_ptr));
	if (!devinfo_bucket_ptr) {
		fd = -ENOMEM;
		goto clean;
	}
	args.kfd_criu_devinfo_buckets_ptr = (uintptr_t)devinfo_bucket_ptr;

	for (int i = 0; i < e->num_of_devices; i++) {
		devinfo_bucket_ptr[i].user_gpu_id = e->devinfo_entries[i]->gpu_id;

		// for now always bind the VMA to /dev/dri/renderD128
		// this should allow us later to restore BO on a different GPU node.
		devinfo_bucket_ptr[i].drm_fd = open_drm_render_device(i + DRM_FIRST_RENDER_NODE);
		if (!devinfo_bucket_ptr[i].drm_fd) {
			pr_perror("amdgpu_plugin: Can't pass NULL drm render fd to driver\n");
			fd = -EBADFD;
			goto clean;
		} else {
			pr_info("amdgpu_plugin: passing drm render fd = %d to driver\n", devinfo_bucket_ptr[i].drm_fd);
		}
	}

	for (int i = 0; i < e->num_of_bos; i++ )
	{
		pr_info("reading e->bo_info_test[%d]:\n", i);
		pr_info("bo_addr = 0x%lx, bo_size = 0x%lx, bo_offset = 0x%lx, gpu_id = 0x%x, "
			"bo_alloc_flags = 0x%x, idr_handle = 0x%x user_addr=0x%lx\n",
		  (e->bo_info_test[i])->bo_addr,
		  (e->bo_info_test[i])->bo_size,
		  (e->bo_info_test[i])->bo_offset,
		  (e->bo_info_test[i])->gpu_id,
		  (e->bo_info_test[i])->bo_alloc_flags,
		  (e->bo_info_test[i])->idr_handle,
		  (e->bo_info_test[i])->user_addr);
	}

	bo_bucket_ptr = xmalloc(e->num_of_bos * sizeof(*bo_bucket_ptr));
	if (!bo_bucket_ptr) {
		pr_perror("amdgpu_plugin: failed to allocate args for restorer ioctl\n");
		return -1;
	}

	for (int i = 0; i < e->num_of_bos; i++)
	{
		(bo_bucket_ptr)[i].bo_addr = (e->bo_info_test[i])->bo_addr;
		(bo_bucket_ptr)[i].bo_size = (e->bo_info_test[i])->bo_size;
		(bo_bucket_ptr)[i].bo_offset = (e->bo_info_test[i])->bo_offset;
		(bo_bucket_ptr)[i].gpu_id = (e->bo_info_test[i])->gpu_id;
		(bo_bucket_ptr)[i].bo_alloc_flags = (e->bo_info_test[i])->bo_alloc_flags;
		(bo_bucket_ptr)[i].idr_handle = (e->bo_info_test[i])->idr_handle;
		(bo_bucket_ptr)[i].user_addr = (e->bo_info_test[i])->user_addr;
	}

	args.num_of_bos = e->num_of_bos;
	args.kfd_criu_bo_buckets_ptr = (uintptr_t)bo_bucket_ptr;

	restored_bo_offsets_array = xmalloc(sizeof(uint64_t) * e->num_of_bos);
	if (!restored_bo_offsets_array) {
		xfree(bo_bucket_ptr);
		return -ENOMEM;
	}

	args.restored_bo_array_ptr = (uint64_t)restored_bo_offsets_array;
	args.num_of_devices = 1; /* Only support 1 gpu for now */

	if (kmtIoctl(fd, AMDKFD_IOC_CRIU_RESTORER, &args) == -1) {
		pr_perror("amdgpu_plugin: failed to call kfd ioctl from plugin restorer for id = %d\n", id);
		fd = -EBADFD;
		goto clean;
	}

	for (int i = 0; i < e->num_of_bos; i++)
	{
		if (e->bo_info_test[i]->bo_alloc_flags &
			(KFD_IOC_ALLOC_MEM_FLAGS_VRAM |
			 KFD_IOC_ALLOC_MEM_FLAGS_GTT |
			 KFD_IOC_ALLOC_MEM_FLAGS_MMIO_REMAP)) {

			struct vma_metadata *vma_md;
			vma_md = xmalloc(sizeof(*vma_md));
			if (!vma_md)
				return -ENOMEM;

			vma_md->old_pgoff = (e->bo_info_test[i])->bo_offset;
			vma_md->vma_entry = (e->bo_info_test[i])->bo_addr;
			vma_md->new_pgoff = restored_bo_offsets_array[i];
			list_add_tail(&vma_md->list, &update_vma_info_list);
		}

		if (e->bo_info_test[i]->bo_alloc_flags &
			(KFD_IOC_ALLOC_MEM_FLAGS_VRAM | KFD_IOC_ALLOC_MEM_FLAGS_GTT)) {

			pr_info("amdgpu_plugin: Trying mmap in stage 2\n");
			if ((e->bo_info_test[i])->bo_alloc_flags &
			    KFD_IOC_ALLOC_MEM_FLAGS_PUBLIC ||
			    (e->bo_info_test[i])->bo_alloc_flags &
			    KFD_IOC_ALLOC_MEM_FLAGS_GTT ) {
				pr_info("amdgpu_plugin: large bar write possible\n");
				addr = mmap(NULL,
					    (e->bo_info_test[i])->bo_size,
					    PROT_WRITE,
					    MAP_SHARED,
					    devinfo_bucket_ptr[0].drm_fd,
					    restored_bo_offsets_array[i]);
				if (addr == MAP_FAILED) {
					pr_perror("amdgpu_plugin: mmap failed\n");
					fd = -EBADFD;
					goto clean;
				}

				/* direct memcpy is possible on large bars */
				memcpy(addr, (void *)e->bo_info_test[i]->bo_rawdata.data,
				       (e->bo_info_test[i])->bo_size);
				munmap(addr, e->bo_info_test[i]->bo_size);
			} else {
				/* Use indirect host data path via /proc/pid/mem
				 * on small pci bar GPUs or for Buffer Objects
				 * that don't have HostAccess permissions.
				 */
				pr_info("amdgpu_plugin: using PROCPIDMEM to restore BO contents\n");
				addr = mmap(NULL,
					    (e->bo_info_test[i])->bo_size,
					    PROT_NONE,
					    MAP_SHARED,
					    devinfo_bucket_ptr[0].drm_fd,
					    restored_bo_offsets_array[i]);
				if (addr == MAP_FAILED) {
					pr_perror("amdgpu_plugin: mmap failed\n");
					fd = -EBADFD;
					goto clean;
				}

				if (asprintf (&fname, PROCPIDMEM, e->pid) < 0) {
					pr_perror("failed in asprintf, %s\n", fname);
					munmap(addr, e->bo_info_test[i]->bo_size);
					fd = -EBADFD;
					goto clean;
				}

				mem_fd = open (fname, O_RDWR);
				if (mem_fd < 0) {
					pr_perror("Can't open %s for pid %d\n", fname, e->pid);
					free (fname);
					munmap(addr, e->bo_info_test[i]->bo_size);
					fd = -EBADFD;
					goto clean;
				}

				pr_perror("Opened %s file for pid = %d\n", fname, e->pid);
				free (fname);

				if (lseek (mem_fd, (off_t) addr, SEEK_SET) == -1) {
					pr_perror("Can't lseek for bo_offset for pid = %d\n", e->pid);
					munmap(addr, e->bo_info_test[i]->bo_size);
					fd = -EBADFD;
					goto clean;
				}

				pr_perror("Attempt writting now\n");
				if (write(mem_fd, e->bo_info_test[i]->bo_rawdata.data,
					  (e->bo_info_test[i])->bo_size) !=
				    (e->bo_info_test[i])->bo_size) {
					pr_perror("Can't write buffer\n");
					munmap(addr, e->bo_info_test[i]->bo_size);
					fd = -EBADFD;
					goto clean;
				}
				munmap(addr, e->bo_info_test[i]->bo_size);
				close(mem_fd);
			}
		} else {
			pr_info("Not a VRAM BO\n");
			continue;
		}
	} /* mmap done for VRAM BO */

	for (int i = 0; i < e->num_of_devices; i++) {
		if (devinfo_bucket_ptr[i].drm_fd >= 0)
			close(devinfo_bucket_ptr[i].drm_fd);
	}
clean:
	xfree(devinfo_bucket_ptr);
	xfree(restored_bo_offsets_array);
	xfree(bo_bucket_ptr);
	xfree(buf);
	criu_kfd__free_unpacked(e, NULL);
	pr_info("amdgpu_plugin: returning kfd fd from plugin, fd = %d\n", fd);
	return fd;
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RESTORE_EXT_FILE, amdgpu_plugin_restore_file)

/* return 0 if no match found
 * return -1 for error.
 * return 1 if vmap map must be adjusted. */
int amdgpu_plugin_update_vmamap(const char *old_path, char *new_path, const uint64_t addr,
				const uint64_t old_offset, uint64_t *new_offset)
{
	struct vma_metadata *vma_md;

	pr_info("amdgpu_plugin: Enter %s\n", __func__);

	/* Once we support restoring on different nodes, new_path may be different from old_path
	 * because the restored gpu may have a different minor number.
	 * For now, we are restoring on the same gpu, so new_path is the same as old_path */

	strcpy(new_path, old_path);

	list_for_each_entry(vma_md, &update_vma_info_list, list) {
		if (addr == vma_md->vma_entry && old_offset == vma_md->old_pgoff) {
			*new_offset = vma_md->new_pgoff;

			pr_info("amdgpu_plugin: old_pgoff= 0x%lx new_pgoff = 0x%lx old_path = %s new_path = %s\n",
				vma_md->old_pgoff, vma_md->new_pgoff, old_path, new_path);

			return 1;
		}
	}
	pr_info("No match for addr:0x%lx offset:%lx\n", addr, old_offset);
	return 0;
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__UPDATE_VMA_MAP, amdgpu_plugin_update_vmamap)

int amdgpu_plugin_resume_devices_late(int target_pid)
{
	struct kfd_ioctl_criu_resume_args args = {0};
	int fd, ret = 0;

	pr_info("amdgpu_plugin: Inside %s for target pid = %d\n", __func__, target_pid);

	fd = open("/dev/kfd", O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		pr_perror("failed to open kfd in plugin");
		return -1;
	}

	args.pid = target_pid;
	pr_info("amdgpu_plugin: Calling IOCTL to start notifiers and queues\n");
	if (kmtIoctl(fd, AMDKFD_IOC_CRIU_RESUME, &args) == -1) {
		pr_perror("restore late ioctl failed\n");
		ret = -1;
	}

	close(fd);
	return ret;
}

CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RESUME_DEVICES_LATE, amdgpu_plugin_resume_devices_late)
