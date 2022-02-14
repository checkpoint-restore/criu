#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/fsuid.h>
#include <sys/syscall.h>
#include <sys/capability.h>
#include <linux/io_uring.h>
#include <linux/capability.h>

#include "util.h"
#include "bitmap.h"
#include "fdinfo.h"
#include "imgset.h"
#include "string.h"
#include "file-ids.h"
#include "io_uring.h"
#include "protobuf.h"
#include "common/list.h"

#include <compel/plugins/std/syscall.h>

#define CTX_F_SEEN_SQE	   (1UL << 0) /* SQE ring mapped */
#define CTX_F_SEEN_SQE_ARR (1UL << 1) /* SQE array mapped */
#define CTX_F_SEEN_CQE	   (1UL << 2) /* CQE ring mapped */
#define CTX_F_SEEN_RINGS   (CTX_F_SEEN_SQE | CTX_F_SEEN_SQE_ARR | CTX_F_SEEN_CQE)
#define CTX_F_SINGLE_MMAP  (1UL << 3) /* SQE/CQE ring are in single mapping */
#define CTX_F_DONE_FILE	   (1UL << 4) /* File dump done */
#define CTX_F_DONE_DATA	   (1UL << 5) /* Data dump done */
#define CTX_F_DONE_ALL	   (CTX_F_DONE_FILE | CTX_F_DONE_DATA)
#define CTX_F_INIT_IOFE	   (1UL << 6) /* Iofe set for ctx */

#define atomic_load_relaxed(x)	     __atomic_load_n((x), __ATOMIC_RELAXED)
#define atomic_load_acquire(x)	     __atomic_load_n((x), __ATOMIC_ACQUIRE)
#define atomic_store_release(x, val) __atomic_store_n((x), (val), __ATOMIC_RELEASE)

#define IO_URING_HASH_TABLE_BITS 5
#define IO_URING_HASH_TABLE_MAX	 (1UL << IO_URING_HASH_TABLE_BITS)
#define IO_URING_HASH_TABLE_MASK (IO_URING_HASH_TABLE_MAX - 1)

#ifndef IORING_FEAT_SQPOLL_NONFIXED
#define IORING_FEAT_SQPOLL_NONFIXED (1U << 7)
#endif

struct io_uring_map {
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	unsigned int *sq_array;
	unsigned int *sq_ring_tail;
	unsigned int *sq_ring_head;
	unsigned int *cqe_ring_head;
	unsigned int *cqe_ring_tail;
	unsigned int *sq_ring_mask;
	unsigned int *cqe_ring_mask;
	size_t sq_len;
	size_t sqe_len;
	size_t cqe_len;
};

struct io_uring_buf {
	struct list_head list;
	unsigned int idx;
	long long unsigned int address;
	unsigned int len;
};

/* We store uid name in image to avoid mismatch on restore which could turn into
 * a potential security risk, as user name may not match for the same UID and
 * user may end up exposing resources to other users unintentionally.
 */
struct io_uring_personality {
	struct list_head list;
	struct io_uring_personality_desc desc;
	char uid_name[32];
	char euid_name[32];
	char suid_name[32];
	char fsuid_name[32];
	char gid_name[32];
	char egid_name[32];
	char sgid_name[32];
	char fsgid_name[32];
};

struct io_uring_ctx {
	struct io_uring_ctx *next;
	ino_t inode;
	u32 id;
	u32 state;
	union {
		struct {
			IoUringFileEntry iofe;
			struct io_uring_map map;

			struct list_head buf_list;
			struct list_head pers_list;
			size_t nr_pers;
		} dump;
		struct {
			void *data;
			size_t sqe_bytes;
			size_t cqe_bytes;
			size_t sq_arr_bytes;
		} restore;
	};
};

static struct io_uring_ctx *ctx_hash_table[IO_URING_HASH_TABLE_MAX];

static struct io_uring_ctx *alloc_ctx(void)
{
	struct io_uring_ctx *ctx;

	ctx = xzalloc(sizeof(*ctx));
	if (!ctx)
		return NULL;

	INIT_LIST_HEAD(&ctx->dump.buf_list);
	INIT_LIST_HEAD(&ctx->dump.pers_list);

	return ctx;
}

static struct io_uring_ctx *lookup_ctx(ino_t inode)
{
	struct io_uring_ctx *ctx;

	ctx = ctx_hash_table[inode & IO_URING_HASH_TABLE_MASK];
	for (; ctx; ctx = ctx->next) {
		if (ctx->inode == inode)
			break;
	}

	return ctx;
}

static void insert_ctx(ino_t inode, struct io_uring_ctx *ctx)
{
	struct io_uring_ctx **slot;

	slot = &ctx_hash_table[inode & IO_URING_HASH_TABLE_MASK];
	ctx->next = *slot;
	*slot = ctx;
}

static uint64_t offset_to_state(uint64_t offset)
{
	switch (offset) {
	case IORING_OFF_SQ_RING:
		return CTX_F_SEEN_SQE;
	case IORING_OFF_CQ_RING:
		return CTX_F_SEEN_CQE;
	case IORING_OFF_SQES:
		return CTX_F_SEEN_SQE_ARR;
	default:
		return 0;
	}
}

static const char *offset_to_str(uint64_t offset)
{
	switch (offset) {
	case IORING_OFF_SQ_RING:
		return "IORING_OFF_SQ_RING";
	case IORING_OFF_CQ_RING:
		return "IORING_OFF_CQ_RING";
	case IORING_OFF_SQES:
		return "IORING_OFF_SQES";
	default:
		return "Unknown";
	}
}

int io_uring_push_buf(struct io_uring_ctx *ctx, unsigned int idx, long long unsigned int address, unsigned int len)
{
	struct io_uring_buf *buf;

	buf = xzalloc(sizeof(*buf));
	if (!buf)
		return -ENOMEM;

	buf->idx = idx;
	buf->address = address;
	buf->len = len;
	list_add_tail(&buf->list, &ctx->dump.buf_list);

	return 0;
}

int io_uring_push_personality(struct io_uring_ctx *ctx, struct io_uring_personality_desc *desc)
{
	struct io_uring_personality *p;
	struct io_uring_group_desc *g;
	struct passwd *pwd;
	struct group *grp;
	int grps = 0;

	p = xzalloc(sizeof(*p));
	if (!p)
		return -ENOMEM;
	INIT_LIST_HEAD(&p->list);

	p->desc = *desc;
	INIT_LIST_HEAD(&p->desc.group_list);

#define X(ptr, sub)                \
	pwd = getpwuid(desc->sub); \
	if (pwd)                   \
		strlcpy(ptr->sub##_name, pwd->pw_name, sizeof(ptr->sub##_name));
	X(p, uid);
	X(p, euid);
	X(p, suid);
	X(p, fsuid);
#undef X
#define X(ptr, sub)                \
	grp = getgrgid(desc->sub); \
	if (grp)                   \
		strlcpy(ptr->sub##_name, grp->gr_name, sizeof(ptr->sub##_name));
	X(p, gid);
	X(p, egid);
	X(p, sgid);
	X(p, fsgid);
#undef X

	list_for_each_entry(g, &desc->group_list, list) {
		grp = getgrgid(g->group);
		if (pwd)
			strlcpy(g->group_name, grp->gr_name, sizeof(g->group_name));
		grps++;
	}
	BUG_ON(grps != desc->nr_groups);

	/* Migrate prepared group list from local desc to personality object */
	list_splice(&desc->group_list, &p->desc.group_list);

	/* ... and append personality object to ctx personality list */
	list_add_tail(&p->list, &ctx->dump.pers_list);
	ctx->dump.nr_pers++;
	return 0;
}

IoUringFileEntry *io_uring_get_iofe(struct io_uring_ctx *ctx)
{
	return &ctx->dump.iofe;
}

/*
 * TODO:
 *  Handle IORING_REGISTER_BUFFERS
 *  Handle IORING_REGISTER_FILES
 *  Handle IORING_REGISTER_EVENTFD_{ASYNC}
 *
 *  Handle wq_fd registration
 *	* Compare in-kernel ctx->sq_data to associate with open fd
 *  Audit memory cleanup after error at various places
 */

static int sys_io_uring_setup(unsigned int entries, struct io_uring_params *p)
{
	return (int)syscall(__NR_io_uring_setup, entries, p);
}

/* XXX: We can expose timeout here to not block indefinitely when trying to sync
 *	io_uring fd during dump stage, in case forward progress depends on one
 *	of the stopped threads.
 */
static int sys_io_uring_enter(int ring_fd, unsigned int to_submit, unsigned int min_complete, unsigned int flags)
{
	return (int)syscall(__NR_io_uring_enter, ring_fd, to_submit, min_complete, flags, NULL, 0);
}

static int sys_io_uring_register(int ring_fd, unsigned int opcode, void *arg, unsigned int nr_args)
{
	return (int)syscall(__NR_io_uring_register, ring_fd, opcode, arg, nr_args);
}

static int io_uring_restore_personality(int fd, IoUringPersonalityId *pers_id)
{
	struct cap_data data[_LINUX_CAPABILITY_U32S_3] = {};
	struct cap_header hdr;
	pid_t pid;
	int ret;

	/* fork into a new child to manipulate credentials and register personality */
	pid = fork();
	if (pid) {
		pid = waitpid(pid, &ret, 0);
		if (pid < 0)
			return -errno;
		return -ret;
	} else if (!pid) {
		u32 cap[2] = {
			pers_id->cap_eff & 0xffffffff00000000,
			pers_id->cap_eff & 0x00000000ffffffff,
		};
		size_t n_grps = 0, sz = 32;
		struct passwd *pwd;
		bool group = false;
		struct group *grp;
		gid_t *groups;

#define X(c, m, x)                                                                                                 \
	if (c) {                                                                                                   \
		if (strcmp(c->m##_name, pers_id->x##_name))                                                        \
			pr_warn("User name from image and system do not match for %s %d\n", group ? "GID" : "UID", \
				pers_id->x);                                                                       \
	} else {                                                                                                   \
		pr_warn("No user for %s %d on system\n", group ? "GID" : "UID", pers_id->x);                       \
	}
		pwd = getpwuid(pers_id->uid);
		X(pwd, pw, uid);
		pwd = getpwuid(pers_id->euid);
		X(pwd, pw, euid);
		pwd = getpwuid(pers_id->suid);
		X(pwd, pw, suid);
		pwd = getpwuid(pers_id->fsuid);
		X(pwd, pw, fsuid);

		group = true;

		grp = getgrgid(pers_id->gid);
		X(grp, gr, gid);
		grp = getgrgid(pers_id->egid);
		X(grp, gr, egid);
		grp = getgrgid(pers_id->sgid);
		X(grp, gr, sgid);
		grp = getgrgid(pers_id->fsgid);
		X(grp, gr, fsgid);
#undef X

		ret = setresuid(pers_id->uid, pers_id->euid, pers_id->suid);
		if (ret < 0)
			goto end;
		ret = setfsuid(pers_id->fsuid);
		if (ret < 0)
			goto end;
		ret = setresgid(pers_id->gid, pers_id->euid, pers_id->suid);
		if (ret < 0)
			goto end;
		ret = setfsgid(pers_id->fsgid);
		if (ret < 0)
			goto end;

		groups = xmalloc(sz * sizeof(*groups));
		if (!groups) {
			errno = ENOMEM;
			goto end;
		}

		for (int i = 0; i < pers_id->n_group_id; i++) {
			IoUringGroupId *gd = pers_id->group_id[i];
			struct group *grp;
			gid_t *g;

			grp = getgrgid(gd->group);
			if (!grp)
				pr_warn("Group name not found for GID %d\n", gd->group);
			if (strcmp(gd->group_name, grp->gr_name))
				pr_warn("Group name in image and on system do not match for GID %d\n", gd->group);

			if (sz <= n_grps) {
				sz *= 2;
				g = xrealloc(groups, sz * sizeof(*g));
				if (!g) {
					xfree(groups);
					errno = ENOMEM;
					goto end;
				}
				groups = g;
			}
			groups[n_grps++] = gd->group;
		}

		ret = setgroups(n_grps, groups);
		xfree(groups);
		if (ret < 0) {
			errno = -ret;
			goto end;
		}

		hdr.version = _LINUX_CAPABILITY_VERSION_3;
		hdr.pid = 0;
		BUILD_BUG_ON(_LINUX_CAPABILITY_U32S_3 != CR_CAP_SIZE);

		for (int i = 0; i < CR_CAP_SIZE; i++)
			data[i].eff = cap[i];

		ret = syscall(__NR_capset, &hdr, data);
		if (ret < 0) {
			errno = -ret;
			goto end;
		}

		ret = sys_io_uring_register(fd, __IORING_REGISTER_PERSONALITY, NULL, 0);
		if (ret < 0) {
			errno = -ret;
			goto end;
		}

		exit(0);
	end:
		exit(errno);
	} else {
		return -errno;
	}

	return 0;
}

int is_io_uring_link(char *link)
{
	return is_anon_link_type(link, "[io_uring]");
}

static void io_uring_submit_nop(struct io_uring_map *map, bool barrier)
{
	unsigned int tail, index;

	BUG_ON(!map);

	tail = atomic_load_acquire(map->sq_ring_tail);
	index = tail & *map->sq_ring_mask;
	map->sqe[index].opcode = IORING_OP_NOP;
	if (barrier)
		map->sqe[index].flags = IOSQE_IO_DRAIN;
	map->sq_array[index] = index;
	atomic_store_release(map->sq_ring_tail, tail + 1);
}

static int io_uring_consume_n(struct io_uring_map *map, int n)
{
	unsigned int head;
	int ret;

	BUG_ON(!map);

	head = *map->cqe_ring_head;
	ret = map->cqe[head & *map->cqe_ring_mask].res;
	atomic_store_release(map->cqe_ring_head, head + n);

	return ret;
}

static void io_uring_consume_all(struct io_uring_map *map)
{
	BUG_ON(!map);

	(void)io_uring_consume_n(map, atomic_load_acquire(map->cqe_ring_tail) - *map->cqe_ring_head);
}

static int map_io_uring_fd(int fd, struct io_uring_params *p, struct io_uring_map *map)
{
	int ret = 0;

	BUG_ON(!p);
	BUG_ON(!map);

	/* XXX: Optimize using FEAT_SINGLE_MMAP */
	map->sq_len = p->sq_off.array + p->sq_entries * sizeof(unsigned int);
	map->cqe_len = p->cq_off.cqes + p->cq_entries * sizeof(struct io_uring_cqe);
	map->sqe_len = p->sq_entries * sizeof(struct io_uring_sqe);

	map->sq_array =
		mmap(NULL, map->sq_len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQ_RING);
	if (map->sq_array == MAP_FAILED) {
		ret = -errno;
		pr_perror("Failed to mmap SQ array ring");
		goto end;
	}

	map->cqe = mmap(NULL, map->cqe_len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_CQ_RING);
	if (map->cqe == MAP_FAILED) {
		ret = -errno;
		pr_perror("Failed to mmap CQE ring");
		goto end_sq_ptr;
	}

	map->sq_ring_head = map->sq_array + p->sq_off.head;
	map->sq_ring_tail = map->sq_array + p->sq_off.tail;
	map->cqe_ring_head = (unsigned int *)map->cqe + p->cq_off.head;
	map->cqe_ring_tail = (unsigned int *)map->cqe + p->cq_off.tail;
	map->sq_ring_mask = map->sq_array + p->sq_off.ring_mask;
	map->cqe_ring_mask = (unsigned int *)map->cqe + p->cq_off.ring_mask;
	map->sq_array += p->sq_off.array;

	map->sqe = mmap(NULL, map->sqe_len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQES);
	if (map->sqe == MAP_FAILED) {
		ret = -errno;
		pr_perror("Failed to mmap SQE ring");
		goto end_cqe_ptr;
	}

	return ret;

	munmap(map->sqe, map->sqe_len);
end_cqe_ptr:
	munmap(map->cqe, map->cqe_len);
end_sq_ptr:
	munmap(map->sq_array, map->sq_len);
end:
	return ret;
}

static void unmap_io_uring_fd(struct io_uring_map *map)
{
	BUG_ON(!map);
	BUG_ON(!map->sqe);
	BUG_ON(!map->cqe);
	BUG_ON(!map->sq_array);

	munmap(map->sqe, map->sqe_len);
	munmap(map->cqe, map->cqe_len);
	munmap(map->sq_array, map->sq_len);
}

int io_uring_synchronize_fd(int fd)
{
	struct io_uring_map map = {};
	struct io_uring_params p;
	struct io_uring_ctx *ctx;
	unsigned int rem;
	struct stat st;
	bool sq_poll;
	int ret;

	if (fd < 0)
		return fd;

	if (fstat(fd, &st))
		return -errno;

	ctx = lookup_ctx(st.st_ino);
	if (!ctx)
		return -ENOENT;

	assert("File Entry must be unitialized" && !(ctx->state & CTX_F_INIT_IOFE));
	/* Obtains sq_off.array, while the rest are offsets we can get from a
	 * io_uring_setup call. Also caches this in ctx so that we don't have to
	 * parse once again.
	 */
	if (parse_fdinfo(fd, FD_TYPES__IO_URING, ctx))
		return -EINVAL;
	ctx->state |= CTX_F_INIT_IOFE;
	return 0;

	sq_poll = ctx->dump.iofe.setup_flags & IORING_SETUP_SQPOLL;

	memset(&p, 0, sizeof(p));
	ret = sys_io_uring_setup(1, &p);
	if (ret < 0)
		return -errno;
	close(ret);

	p.sq_off.array = ctx->dump.iofe.sq_off_array;
	p.sq_entries = ctx->dump.iofe.sq_entries;
	p.cq_entries = ctx->dump.iofe.cq_entries;

	ret = map_io_uring_fd(fd, &p, &map);
	if (ret < 0)
		return ret;

	/* Preserve head/tail and ring mask */
	ctx->dump.iofe.sq_head = atomic_load_acquire(map.sq_ring_head);
	ctx->dump.iofe.sq_tail = *map.sq_ring_tail;
	ctx->dump.iofe.cqe_head = *map.cqe_ring_head;
	ctx->dump.iofe.sq_ring_mask = *map.sq_ring_mask;

	io_uring_consume_all(&map);

	rem = ctx->dump.iofe.sq_tail - ctx->dump.iofe.sq_head;
	/* XXX: Add timeout to gracefully handle indefinite blocking */
	ret = sys_io_uring_enter(fd, rem, rem, IORING_ENTER_GETEVENTS | IORING_ENTER_SQ_WAKEUP);
	if (ret < 0) {
		ret = -errno;
		pr_perror("Failed to call io_uring_enter");
	}

	ctx->dump.iofe.cqe_tail = atomic_load_acquire(map.cqe_ring_tail);
	if (sq_poll)
		ctx->dump.iofe.sq_head = ctx->dump.iofe.sq_tail;

	ctx->dump.map = map;
	return ret;
}

static int replay_io_uring_data(int fd, struct io_uring_ctx *ctx, struct io_uring_params *p, IoUringFileEntry *iofe)
{
	unsigned int nop_count, cons_count;
	struct io_uring_map map;
	int ret = 0, flags = 0;
	void *data;

	BUG_ON(!ctx);
	BUG_ON(!p);
	BUG_ON(!iofe);
	BUG_ON(p->sq_entries != ctx->restore.sqe_bytes / sizeof(struct io_uring_sqe));
	BUG_ON(p->cq_entries != ctx->restore.cqe_bytes / sizeof(struct io_uring_cqe));
	BUG_ON(p->sq_entries != ctx->restore.sq_arr_bytes / sizeof(unsigned int));

	/* To replay the data, we first need to advance head and tail to the
	 * values they were when the io_uring instance was dumped. At the ABI
	 * level the request and completion structure have same size for all
	 * operations, so filling IORING_OP_NOP operations and reaping them
	 * adjust the kernel's offsets, after which we overwrite the ring with
	 * data we dumped in the image.
	 */
	if (p->flags & IORING_SETUP_SQPOLL)
		flags |= IORING_ENTER_SQ_WAKEUP;

	ret = map_io_uring_fd(fd, p, &map);
	if (ret < 0)
		return ret;

	nop_count = iofe->sq_head & iofe->sq_ring_mask;
	cons_count = iofe->cqe_tail & iofe->cq_ring_mask;

	for (int i = 0; i < nop_count; i++)
		io_uring_submit_nop(&map, false);

	ret = sys_io_uring_enter(fd, nop_count, nop_count, IORING_ENTER_GETEVENTS | flags);
	if (ret < 0) {
		pr_perror("Failed to call io_uring_enter");
		goto end;
	}

	io_uring_consume_n(&map, cons_count);

	data = ctx->restore.data;
	memcpy(map.sqe, data, ctx->restore.sqe_bytes);
	data += ctx->restore.sqe_bytes;
	memcpy(map.cqe, data, ctx->restore.cqe_bytes);
	data += ctx->restore.cqe_bytes;
	memcpy(map.sq_array, data, ctx->restore.sq_arr_bytes);

end:
	xfree(ctx->restore.data);
	unmap_io_uring_fd(&map);
	return ret;
}

static int dump_one_io_uring_data(struct io_uring_ctx *ctx, IoUringFileEntry *iofe, int lfd, const struct fd_parms *p)
{
	IoUringDataEntry iode = IO_URING_DATA_ENTRY__INIT;
	struct io_uring_map *map;
	struct cr_img *img;
	int ret;

	map = &ctx->dump.map;

	BUG_ON(!map->sqe);
	BUG_ON(!map->cqe);
	BUG_ON(!map->sq_array);

	img = img_from_set(glob_imgset, CR_FD_IO_URING_DATA);
	BUG_ON(ctx->state & CTX_F_DONE_DATA);

	iode.id = ctx->inode;
	iode.sqe_bytes = sizeof(struct io_uring_sqe) * ctx->dump.iofe.sq_entries;
	iode.cqe_bytes = sizeof(struct io_uring_cqe) * ctx->dump.iofe.cq_entries;
	iode.sq_arr_bytes = sizeof(unsigned int) * ctx->dump.iofe.sq_entries;

	ret = -1;
	if (pb_write_one(img, &iode, PB_IO_URING_DATA))
		goto end;

	/* Layout |SQE|CQE|SQARR| */
	if (write(img_raw_fd(img), map->sqe, iode.sqe_bytes) != iode.sqe_bytes)
		goto end;
	if (write(img_raw_fd(img), map->cqe, iode.cqe_bytes) != iode.cqe_bytes)
		goto end;
	if (write(img_raw_fd(img), map->sq_array, iode.sq_arr_bytes) != iode.sq_arr_bytes)
		goto end;

	ret = 0;
	ctx->state |= CTX_F_DONE_DATA;
end:
	unmap_io_uring_fd(map);
	return ret;
}

static int dump_one_io_uring(int lfd, u32 id, const struct fd_parms *p)
{
	IoUringFileEntry iofe = IO_URING_FILE_ENTRY__INIT;
	struct io_uring_personality *per_i, *ptmp;
	struct io_uring_buf *buf_i, *btmp;
	FileEntry fe = FILE_ENTRY__INIT;
	struct io_uring_ctx *ctx;
	int i = 0, j = 0;

	ctx = lookup_ctx(p->stat.st_ino);
	if (!ctx)
		return -ENOENT;

	BUG_ON(!(ctx->state & CTX_F_INIT_IOFE));
	BUG_ON(ctx->state & CTX_F_DONE_FILE);

	iofe.id = ctx->id = id;
	iofe.inode = ctx->inode;
	iofe.flags = p->flags;
	iofe.fown = (FownEntry *)&p->fown;

	fe.type = FD_TYPES__IO_URING;
	fe.id = iofe.id;
	fe.io_uring = &iofe;

	list_for_each_entry_safe(buf_i, btmp, &ctx->dump.buf_list, list) {
		/* XXX: match struct page address for buf_i->idx from eBPF
		 * iterator output
		 */
		xfree(buf_i);
	}

	BUG_ON(!list_empty(&ctx->dump.pers_list) && !ctx->dump.nr_pers);
	ctx->dump.iofe.n_pers_id = ctx->dump.nr_pers;
	ctx->dump.iofe.pers_id = xzalloc(pb_repeated_size(&ctx->dump.iofe, pers_id));
	if (!ctx->dump.iofe.pers_id)
		return -ENOMEM;

	list_for_each_entry_safe(per_i, ptmp, &ctx->dump.pers_list, list) {
		struct io_uring_group_desc *grp_i, *gtmp;
		IoUringPersonalityId *pers_id;

		BUG_ON(i + 1 != per_i->desc.id);
		ctx->dump.iofe.pers_id[i] = xzalloc(sizeof(*ctx->dump.iofe.pers_id[i]));
		if (!ctx->dump.iofe.pers_id[i])
			return -ENOMEM;

		pers_id = ctx->dump.iofe.pers_id[i];

#define X(x) pers_id->x = per_i->desc.x;
		X(uid);
		X(euid);
		X(suid);
		X(fsuid);
		X(gid);
		X(egid);
		X(sgid);
		X(fsgid);
#undef X

#define X(x)                                          \
	pers_id->x##_name = xstrdup(per_i->x##_name); \
	if (!pers_id->x##_name)                       \
		return -ENOMEM;
		X(uid);
		X(euid);
		X(suid);
		X(fsuid);
		X(gid);
		X(egid);
		X(sgid);
		X(fsgid);
#undef X
		memcpy(&pers_id->cap_eff, per_i->desc.cap_eff, sizeof(per_i->desc.cap_eff));
		BUG_ON(!list_empty(&per_i->desc.group_list) && !per_i->desc.nr_groups);
		pers_id->n_group_id = per_i->desc.nr_groups;
		pers_id->group_id = xzalloc(pb_repeated_size(pers_id, group_id));
		if (!pers_id->group_id)
			return -ENOMEM;
		/* Now, iterate over group list for personality, and dump each
		 * group ID and group name
		 */
		j = 0;
		list_for_each_entry_safe(grp_i, gtmp, &per_i->desc.group_list, list) {
			pers_id->group_id[j] = xzalloc(sizeof(*pers_id->group_id[j]));
			if (!pers_id->group_id[j])
				return -ENOMEM;
			pers_id->group_id[j]->group = grp_i->group;
			pers_id->group_id[j]->group_name = xstrdup(grp_i->group_name);
			if (!pers_id->group_id[j]->group_name)
				return -ENOMEM;
			j++;
			xfree(grp_i);
		}
		BUG_ON(j != per_i->desc.nr_groups);
		i++;
		xfree(per_i);
	}
	BUG_ON(i != ctx->dump.nr_pers);

	if (pb_write_one(img_from_set(glob_imgset, CR_FD_FILES), &fe, PB_FILE))
		return -1;
	ctx->state |= CTX_F_DONE_FILE;

	return dump_one_io_uring_data(ctx, &iofe, lfd, p);
}

const struct fdtype_ops io_uring_dump_ops = {
	.type = FD_TYPES__IO_URING,
	.dump = dump_one_io_uring,
};

static int open_io_uring_desc(struct file_desc *d, int *new_fd)
{
	struct __io_uring_restriction res[4];
	struct io_uring_file_info *iofi;
	struct io_uring_ctx *ctx;
	struct io_uring_params p;
	IoUringFileEntry *iofe;
	int fd, ret = -1;

	iofi = container_of(d, struct io_uring_file_info, d);
	iofe = iofi->iofe;

	/* XXX: when we handle IORING_REGISTER_FILES, and wq_fd registration,
	 * handle post_open processing here to re-register files...
	 *
	 * For wq_fd, there is a parent io_uring fd that will be restored first
	 * (without any other dependencies on io_uring instances). Cycles cannot
	 * be created as io_uring won't allow IORING_REGISTER_FILES for another
	 * io_uring, so we cannot deadlock, and wq_fd registration won't be
	 * circular either. wq_fd is determined using ctx->sq_data matching in
	 * eBPF iteration.
	 */
	ctx = lookup_ctx(iofe->id);
	if (!ctx)
		return -ENOENT;

	memset(&p, 0, sizeof(p));
	p.sq_thread_cpu = iofe->sq_thread_cpu;
	p.sq_thread_idle = iofe->sq_thread_idle;
	p.cq_entries = iofe->cq_entries;
	p.flags = iofe->setup_flags | IORING_SETUP_CQSIZE;

	if (iofe->restrictions)
		p.flags |= IORING_SETUP_R_DISABLED;

	fd = sys_io_uring_setup(iofe->sq_entries, &p);
	if (fd < 0)
		return -errno;

	for (int i = 0; i < iofe->n_pers_id; i++) {
		IoUringPersonalityId *pers_id = iofe->pers_id[i];

		ret = io_uring_restore_personality(fd, pers_id);
		if (ret < 0)
			goto end;
	}

	if (iofe->restrictions) {
		int nr = 0;

		if (iofe->reg_op) {
			res[nr].opcode = __IORING_RESTRICTION_REGISTER_OP;
			res[nr++].register_op = iofe->reg_op;
		}

		if (iofe->sqe_op) {
			res[nr].opcode = __IORING_RESTRICTION_SQE_OP;
			res[nr++].sqe_op = iofe->sqe_op;
		}

		if (iofe->sqe_flags_allowed) {
			res[nr].opcode = __IORING_RESTRICTION_SQE_FLAGS_ALLOWED;
			res[nr++].sqe_flags = iofe->sqe_flags_allowed;
		}

		if (iofe->sqe_flags_required) {
			res[nr].opcode = __IORING_RESTRICTION_SQE_FLAGS_REQUIRED;
			res[nr++].sqe_flags = iofe->sqe_flags_required;
		}

		BUG_ON(nr >= ARRAY_SIZE(res));
		if (nr) {
			ret = sys_io_uring_register(fd, __IORING_REGISTER_RESTRICTIONS, res, nr);
			if (ret < 0)
				goto end;
		}

		ret = sys_io_uring_register(fd, __IORING_REGISTER_ENABLE_RINGS, NULL, 0);
		if (ret < 0)
			goto end;
	}

	if ((p.flags & IORING_SETUP_SQPOLL) && !iofe->nr_user_files && !(p.features & IORING_FEAT_SQPOLL_NONFIXED)) {
		ret = -ENOTSUP;
		pr_err("Dumped io_uring instance %#08x has IORING_SETUP_SQPOLL flag, but no registered files,\n"
		       "and system does not support SQPOLL in this mode, as IORING_FEAT_SQPOLL_NONFIXED \n"
		       "feature is missing\n",
		       iofe->id);
		goto end;
	}

	if (rst_file_params(fd, iofe->fown, iofi->iofe->flags)) {
		pr_perror("Can't restore file params on io_uring %#08x", iofe->id);
		goto end;
	}

	ret = replay_io_uring_data(fd, ctx, &p, iofe);
	if (ret < 0)
		goto end;

	*new_fd = fd;

	return 0;
end:
	close(fd);
	return ret;
}

static struct file_desc_ops io_uring_desc_ops = {
	.type = FD_TYPES__IO_URING,
	.open = open_io_uring_desc,
};

static int collect_one_io_uring(void *o, ProtobufCMessage *base, struct cr_img *i)
{
	struct io_uring_file_info *iofi = o;
	struct io_uring_ctx *ctx;

	ctx = alloc_ctx();
	if (!ctx)
		return -ENOMEM;

	iofi->iofe = pb_msg(base, IoUringFileEntry);
	ctx->inode = iofi->iofe->id;
	insert_ctx(iofi->iofe->id, ctx);
	return file_desc_add(&iofi->d, iofi->iofe->id, &io_uring_desc_ops);
}

struct collect_image_info io_uring_cinfo = {
	.fd_type = CR_FD_IO_URING_FILE,
	.pb_type = PB_IO_URING_FILE,
	.priv_size = sizeof(struct io_uring_file_info),
	.collect = collect_one_io_uring,
};

static int collect_one_io_uring_data(void *o, ProtobufCMessage *base, struct cr_img *i)
{
	struct io_uring_data_info *iodi = o;
	struct io_uring_ctx *ctx;
	size_t bytes;

	iodi->iode = pb_msg(base, IoUringDataEntry);

	ctx = lookup_ctx(iodi->iode->id);
	if (!ctx) {
		/* Should have been inserted by file collect stage */
		pr_err("Failed to failed io_uring restore ctx for id %#08lx\n", (unsigned long)iodi->iode->id);
		return -ENOENT;
	}

	bytes = iodi->iode->sqe_bytes + iodi->iode->cqe_bytes + iodi->iode->sq_arr_bytes;
	ctx->restore.data = xmalloc(bytes);
	if (!ctx->restore.data)
		return -ENOMEM;

	return read_img_buf(i, ctx->restore.data, bytes);
}

struct collect_image_info io_uring_data_cinfo = {
	.fd_type = CR_FD_IO_URING_DATA,
	.pb_type = PB_IO_URING_DATA,
	.priv_size = sizeof(struct io_uring_data_info),
	.collect = collect_one_io_uring_data,
};

static int open_io_uring_map(int pid, struct vma_area *vma)
{
	struct fdinfo_list_entry *fle;
	VmaEntry *vme = vma->e;
	struct file_desc *fd;

	fd = find_file_desc_raw(FD_TYPES__IO_URING, vme->shmid);
	if (!fd)
		return -1;

	list_for_each_entry(fle, &fd->fd_info_head, desc_list) {
		if (fle->pid == pid) {
			int fd;

			fd = dup(fle->fe->fd);
			if (fd < 0)
				return -errno;

			vme->fd = fd;
			return 0;
		}
	}

	return -ENOENT;
}

int collect_io_uring_map(struct vma_area *vma)
{
	vma->vm_open = open_io_uring_map;
	return 0;
}

int dump_io_uring_map(struct vma_area *vma)
{
	struct io_uring_ctx *ctx;

	ctx = lookup_ctx(vma->io_uring_id);
	if (!ctx)
		return -ENOENT;

	if (!(ctx->state & CTX_F_DONE_ALL)) {
		pr_err("Mapping(s) found for io_uring but no fd open, cannot dump "
		       "io_uring instance without access to io_uring fd corresponding "
		       "to the mapping\n");
		return -ENOTSUP;
	}

	vma->e->shmid = ctx->inode;
	return 0;
}

int add_one_io_uring_mapping(uint64_t offset, ino_t inode)
{
	struct io_uring_ctx *ctx;
	uint64_t flag;

	pr_debug("Processing for io_uring mapping at offset=%s\n", offset_to_str(offset));
	flag = offset_to_state(offset);
	if (!flag) {
		pr_err("Invalid offset of mapping offset=%" PRIu64 "\n", offset);
		return -EINVAL;
	}

	ctx = lookup_ctx(inode);
	if (!ctx) {
		pr_debug("No io_uring ctx associated with inode=%lu, creating one...\n", (unsigned long)inode);

		ctx = alloc_ctx();
		if (!ctx)
			return -ENOMEM;

		ctx->inode = inode;
		insert_ctx(ctx->inode, ctx);
	}

	ctx->state |= flag;
	return 0;
}
