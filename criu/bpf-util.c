#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <linux/bpf.h>
#include <sys/syscall.h>

#include "log.h"
#include "xmalloc.h"
#include "bpf-util.h"
#include "bpf_insn.h"
#include "common/bug.h"

/* XXX: Propagate the case of errors from bpf_map_update_elem */

static inline int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}

static inline __u64 ptr_to_u64(const void *ptr)
{
	return (__u64)(unsigned long)ptr;
}

static int bpf_map_create(enum bpf_map_type map_type, int key_size, int value_size, int max_entries)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));

	attr.map_type = map_type;
	attr.key_size = key_size;
	attr.value_size = value_size;
	attr.max_entries = max_entries;

	return sys_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
}

static int bpf_prog_load_iter(struct bpf_insn *insns, int insn_cnt)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.prog_type = BPF_PROG_TYPE_TRACING;
	attr.expected_attach_type = BPF_TRACE_ITER;

	attr.insns = ptr_to_u64(insns);
	attr.insn_cnt = insn_cnt;

	return sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}

struct bpf_insn_buf {
	int insn_cap;
	int insn_cnt;
	struct bpf_insn insns[];
};

static struct bpf_insn_buf *bpf_insn_buf_alloc(void)
{
	struct bpf_insn_buf *ibuf;

	ibuf = xmalloc(offsetof(struct bpf_insn_buf, insns[64]));
	if (!ibuf)
		return NULL;
	ibuf->insn_cap = 64;
	ibuf->insn_cnt = 0;
	return ibuf;
}

static void bpf_insn_buf_free(struct bpf_insn_buf *ibuf)
{
	xfree(ibuf);
}

static int bpf_insn_buf_push(struct bpf_insn_buf *ibuf, struct bpf_insn *insns, int insn_cnt)
{
	BUG_ON(!ibuf);
	if (ibuf->insn_cap >= ibuf->insn_cnt + insn_cnt)
		goto push;
	ibuf = xrealloc(ibuf, offsetof(struct bpf_insn_buf, insns[ibuf->insn_cap + insn_cnt]));
	if (!ibuf)
		return -ENOMEM;
push:
	memcpy(ibuf->insns + ibuf->insn_cnt, insns, insn_cnt * sizeof(*insns));
	ibuf->insn_cnt += insn_cnt;
	ibuf->insn_cap += insn_cnt;
	return 0;
}

#define bpf_push(insn)                                                                                        \
	({                                                                                                    \
		if ((ret = bpf_insn_buf_push(ibuf, (struct bpf_insn[]){ insn },                               \
					     sizeof((struct bpf_insn[]){ insn }) / sizeof(struct bpf_insn)))) \
			goto exit;                                                                            \
	})

typedef int bpf_insn_buf_fill_cb(struct bpf_fdtable *meta, struct bpf_insn_buf *ibuf, void *userdata);

enum fill_type {
	FILL_TASK_FILE,
	FILL_IO_URING,
	FILL_EPOLL,
};

static int bpf_fill_fdtable(enum fill_type type, int *fill_desc, struct bpf_fdtable *meta,
			    int index_size, int max_entries, bpf_insn_buf_fill_cb fill_insn,
			    void *userdata)
{
	int file2index_map_fd, index2file_map_fd, ret;
	struct bpf_insn_buf *ibuf;

	BUG_ON(!meta);
	BUG_ON(index_size != 4 || index_size != 8);

	file2index_map_fd = bpf_map_create(BPF_MAP_TYPE_HASH, sizeof(uint64_t), index_size, max_entries);
	if (file2index_map_fd < 0)
		return -errno;

	index2file_map_fd = bpf_map_create(BPF_MAP_TYPE_HASH, index_size, sizeof(uint64_t), max_entries);
	if (index2file_map_fd < 0) {
		ret = -errno;
		goto end_file2fd;
	}

	meta->file2index_map_fd = file2index_map_fd;
	meta->index2file_map_fd = index2file_map_fd;

	ibuf = bpf_insn_buf_alloc();
	if (!ibuf) {
		ret = -ENOMEM;
		goto end_fd2file;
	}

	if ((ret = fill_insn(meta, ibuf, userdata)))
		goto end_ibuf;

	ret = bpf_prog_load_iter(ibuf->insns, ibuf->insn_cnt);
	if (ret < 0)
		ret = -errno;
	bpf_insn_buf_free(ibuf);

	return ret;
end_ibuf:
	bpf_insn_buf_free(ibuf);
end_fd2file:
	close(index2file_map_fd);
end_file2fd:
	close(file2index_map_fd);
	return ret;
}

static int task_fill_cb(struct bpf_fdtable *meta, struct bpf_insn_buf *ibuf, void *userdata)
{
	int tgid = *(int *)userdata, ret;

	(void)tgid;
	/* XXX: Fixup task_struct::tgid offset and compare (requires libbpf dep) */
	bpf_push(BPF_MOV64_REG(BPF_REG_6, BPF_REG_1));
	/* index -> file */
	bpf_push(BPF_LD_MAP_FD(BPF_REG_1, meta->index2file_map_fd));
	bpf_push(BPF_MOV64_REG(BPF_REG_2, BPF_REG_6));
	bpf_push(BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 8 + 8 /* meta +  */));
	bpf_push(BPF_MOV64_REG(BPF_REG_3, BPF_REG_6));
	bpf_push(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, 8 + 8 + 8 /* meta + task + fd */));
	bpf_push(BPF_MOV64_IMM(BPF_REG_4, 0));
	bpf_push(BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_update_elem));
	/* file -> index */
	bpf_push(BPF_MOV64_REG(BPF_REG_1, meta->file2index_map_fd));
	bpf_push(BPF_MOV64_REG(BPF_REG_2, BPF_REG_6));
	bpf_push(BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 8 + 8 /* meta + ctx */));
	bpf_push(BPF_MOV64_REG(BPF_REG_3, BPF_REG_6));
	bpf_push(BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 8 + 8 + 8 /* meta + ctx + file */));
	bpf_push(BPF_MOV64_IMM(BPF_REG_4, 0));
	bpf_push(BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_update_elem));
	bpf_push(BPF_MOV64_IMM(BPF_REG_0, 0));
	bpf_push(BPF_EXIT_INSN());
	return 0;
exit:
	return ret;
}

int bpf_fill_task_fdtable(int tgid, struct bpf_fdtable *meta)
{
	return bpf_fill_fdtable(FILL_TASK_FILE, &tgid, meta, sizeof(int), 65535, task_fill_cb,
				&tgid);
}

static int io_uring_fill_cb(struct bpf_fdtable *meta, struct bpf_insn_buf *ibuf, void *userdata)
{
	int ret;

	/* XXX: Consider skipping in sparse set */
	bpf_push(BPF_MOV64_REG(BPF_REG_6, BPF_REG_1));
	/* index -> file */
	bpf_push(BPF_LD_MAP_FD(BPF_REG_1, meta->index2file_map_fd));
	bpf_push(BPF_MOV64_REG(BPF_REG_2, BPF_REG_6));
	bpf_push(BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 8 + 8 + 8 /* meta + ctx + file */));
	bpf_push(BPF_MOV64_REG(BPF_REG_3, BPF_REG_6));
	bpf_push(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, 8 + 8 /* meta + ctx */));
	bpf_push(BPF_MOV64_IMM(BPF_REG_4, 0));
	bpf_push(BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_update_elem));
	/* file -> index */
	bpf_push(BPF_MOV64_REG(BPF_REG_1, meta->file2index_map_fd));
	bpf_push(BPF_MOV64_REG(BPF_REG_2, BPF_REG_6));
	bpf_push(BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 8 + 8 /* meta + ctx */));
	bpf_push(BPF_MOV64_REG(BPF_REG_3, BPF_REG_6));
	bpf_push(BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 8 + 8 + 8 /* meta + ctx + file */));
	bpf_push(BPF_MOV64_IMM(BPF_REG_4, 0));
	bpf_push(BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_update_elem));
	bpf_push(BPF_MOV64_IMM(BPF_REG_0, 0));
	bpf_push(BPF_EXIT_INSN());
	return 0;
exit:
	return ret;
}

int bpf_fill_io_uring_fdtable(int io_uring_fd, struct bpf_fdtable *meta)
{
	return bpf_fill_fdtable(FILL_IO_URING, &io_uring_fd, meta, sizeof(unsigned long),
				4096, io_uring_fill_cb, NULL);
}

int epoll_fill_cb(struct bpf_fdtable *meta, struct bpf_insn_buf *ibuf, void *userdata)
{
	int ret;

	/* XXX: Relocate epitem offsets */
	bpf_push(BPF_MOV64_REG(BPF_REG_6, BPF_REG_1));
	/* index -> file */
	bpf_push(BPF_LD_MAP_FD(BPF_REG_1, meta->index2file_map_fd));
	bpf_push(BPF_MOV64_REG(BPF_REG_2, BPF_REG_6));
	bpf_push(BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 8 + 8 + 8 /* meta + ctx + file */));
	bpf_push(BPF_MOV64_REG(BPF_REG_3, BPF_REG_6));
	bpf_push(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, 8 + 8 /* meta + ctx */));
	bpf_push(BPF_MOV64_IMM(BPF_REG_4, 0));
	bpf_push(BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_update_elem));
	/* file -> index */
	bpf_push(BPF_MOV64_REG(BPF_REG_1, meta->file2index_map_fd));
	bpf_push(BPF_MOV64_REG(BPF_REG_2, BPF_REG_6));
	bpf_push(BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 8 + 8 /* meta + ctx */));
	bpf_push(BPF_MOV64_REG(BPF_REG_3, BPF_REG_6));
	bpf_push(BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 8 + 8 + 8 /* meta + ctx + file */));
	bpf_push(BPF_MOV64_IMM(BPF_REG_4, 0));
	bpf_push(BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_update_elem));
	bpf_push(BPF_MOV64_IMM(BPF_REG_0, 0));
	bpf_push(BPF_EXIT_INSN());
	return 0;
exit:
	return ret;
}

int bpf_fill_epoll_fdtable(int epoll_fd, struct bpf_fdtable *meta)
{
	return bpf_fill_fdtable(FILL_EPOLL, &epoll_fd, meta, sizeof(unsigned long),
				4096, io_uring_fill_cb, NULL);
}
