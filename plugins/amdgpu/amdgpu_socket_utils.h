#ifndef __KFD_PLUGIN_AMDGPU_SOCKET_UTILS_H__
#define __KFD_PLUGIN_AMDGPU_SOCKET_UTILS_H__

typedef struct {
	int id;
	int fd_write_num; /* The number of buffer objects to be restored. */
	int entry_num;	  /* The number of restore commands.*/
	int gpu_num;
} parallel_restore_cmd_head;

typedef struct {
	int gpu_id;
	int minor;
} parallel_gpu_info;

typedef struct {
	int gpu_id;
	int write_id;
	uint64_t read_offset;
	uint64_t write_offset;
	uint64_t size;
} parallel_restore_entry;

typedef struct {
	parallel_restore_cmd_head cmd_head;
	int *fds_write;
	parallel_gpu_info *gpu_ids;
	parallel_restore_entry *entries;
} parallel_restore_cmd;

/*
 * For parallel_restore, a background thread in the main CRIU process is used to restore the GPU
 * buffer object. However, initially, the ownership of these buffer objects and the metadata for
 * restoration are all with the target process. Therefore, we introduce a series of functions to
 * help the target process send these tasks to the main CRIU process.
 */
int init_parallel_restore_cmd(int num, int id, int gpu_num, parallel_restore_cmd *restore_cmd);

void free_parallel_restore_cmd(parallel_restore_cmd *restore_cmd);

int install_parallel_sock(void);

int send_parallel_restore_cmd(parallel_restore_cmd *restore_cmd);

int recv_parallel_restore_cmd(parallel_restore_cmd *restore_cmd);

void parallel_restore_bo_add(int dmabuf_fd, int gpu_id, uint64_t size, uint64_t offset,
			     parallel_restore_cmd *restore_cmd);

void parallel_restore_gpu_id_add(int gpu_id, int minor, parallel_restore_cmd *restore_cmd);

int close_parallel_restore_server(void);

#endif