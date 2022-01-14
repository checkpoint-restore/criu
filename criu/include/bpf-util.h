#ifndef __CR_BPF_UTIL_H__
#define __CR_BPF_UTIL_H__

#include <unistd.h>
#include <linux/bpf.h>

struct bpf_fdtable {
	int file2index_map_fd;
	int index2file_map_fd;
};

int bpf_fill_task_fdtable(pid_t tgid, struct bpf_fdtable *meta);
int bpf_fill_io_uring_fdtable(int io_uring_fd, struct bpf_fdtable *meta);
int bpf_fill_epoll_fdtable(int epoll_fd, struct bpf_fdtable *meta);

#endif
