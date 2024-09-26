#ifndef __AMDGPU_PLUGIN_UTIL_H__
#define __AMDGPU_PLUGIN_UTIL_H__

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#ifdef COMPILE_TESTS
#undef pr_err
#define pr_err(format, arg...) fprintf(stdout, "%s:%d ERROR:" format, __FILE__, __LINE__, ##arg)
#undef pr_info
#define pr_info(format, arg...) fprintf(stdout, "%s:%d INFO:" format, __FILE__, __LINE__, ##arg)
#undef pr_debug
#define pr_debug(format, arg...) fprintf(stdout, "%s:%d DBG:" format, __FILE__, __LINE__, ##arg)

#undef pr_perror
#define pr_perror(format, arg...) \
	fprintf(stdout, "%s:%d: " format " (errno = %d (%s))\n", __FILE__, __LINE__, ##arg, errno, strerror(errno))
#endif

#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif
#define LOG_PREFIX "amdgpu_plugin: "

#ifdef DEBUG
#define plugin_log_msg(fmt, ...) pr_debug(fmt, ##__VA_ARGS__)
#else
#define plugin_log_msg(fmt, ...) \
	{                        \
	}
#endif


/* Path where KFD device is surfaced */
#define AMDGPU_KFD_DEVICE		"/dev/kfd"

/* Path where DRM devices are surfaced */
#define AMDGPU_DRM_DEVICE		"/dev/dri/renderD%d"

/* Minimum version of KFD IOCTL's that supports C&R */
#define KFD_IOCTL_MAJOR_VERSION			1
#define MIN_KFD_IOCTL_MINOR_VERSION		8

/* Name of file having serialized data of KFD device */
#define IMG_KFD_FILE			"amdgpu-kfd-%d.img"

/* Name of file having serialized data of KFD buffer objects (BOs) */
#define IMG_KFD_PAGES_FILE		"amdgpu-pages-%d-%04x.img"

/* Name of file having serialized data of DRM device */
#define IMG_DRM_FILE			"amdgpu-renderD-%d.img"

/* Name of file having serialized data of DRM device buffer objects (BOs) */
#define IMG_DRM_PAGES_FILE		"amdgpu-drm-pages-%d-%04x.img"

/* Helper macros to Checkpoint and Restore a ROCm file */
#define HSAKMT_SHM_PATH			"/dev/shm/hsakmt_shared_mem"
#define HSAKMT_SHM				"/hsakmt_shared_mem"
#define HSAKMT_SEM_PATH			"/dev/shm/sem.hsakmt_semaphore"
#define HSAKMT_SEM				"hsakmt_semaphore"

/* Help macros to build sDMA command packets */
#define SDMA_PACKET(op, sub_op, e) ((((e)&0xFFFF) << 16) | (((sub_op)&0xFF) << 8) | (((op)&0xFF) << 0))

#define SDMA_OPCODE_COPY	    1
#define SDMA_COPY_SUB_OPCODE_LINEAR 0
#define SDMA_NOP		    0
#define SDMA_LINEAR_COPY_MAX_SIZE   (1ULL << 21)

enum sdma_op_type {
	SDMA_OP_VRAM_READ,
	SDMA_OP_VRAM_WRITE,
};

/* Helper structures to encode device topology of SRC and DEST platforms */
extern struct tp_system src_topology;
extern struct tp_system dest_topology;

/* Helper structures to encode device maps during Checkpoint and Restore operations */
extern struct device_maps checkpoint_maps;
extern struct device_maps restore_maps;

extern int fd_next;

extern bool kfd_fw_version_check;
extern bool kfd_sdma_fw_version_check;
extern bool kfd_caches_count_check;
extern bool kfd_num_gws_check;
extern bool kfd_vram_size_check;
extern bool kfd_numa_check;
extern bool kfd_capability_check;

int read_fp(FILE *fp, void *buf, const size_t buf_len);
int write_fp(FILE *fp, const void *buf, const size_t buf_len);
int read_file(const char *file_path, void *buf, const size_t buf_len);
int write_img_file(char *path, const void *buf, const size_t buf_len);
FILE *open_img_file(char *path, bool write, size_t *size);

bool checkpoint_is_complete();
void decrement_checkpoint_count();
void init_gpu_count(struct tp_system *topology);

void print_kfd_bo_stat(int bo_cnt, struct kfd_criu_bo_bucket *bo_list);

#endif		/* __AMDGPU_PLUGIN_UTIL_H__ */
