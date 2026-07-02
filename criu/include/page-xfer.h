#ifndef __CR_PAGE_XFER__H__
#define __CR_PAGE_XFER__H__
#include "pagemap.h"
#include "types.h"

struct ps_info {
	int pid;
	unsigned short port;
};

/*
 * Wire protocol constants and structures.
 * Shared by page-xfer.c, clone-page-xfer.c, and clone-bulk-send.c.
 */
#define PS_IOV_ADD    1
#define PS_IOV_HOLE   2
#define PS_IOV_OPEN   3
#define PS_IOV_OPEN2  4
#define PS_IOV_PARENT 5
#define PS_IOV_ADD_F  6
#define PS_IOV_GET    7

#define PS_IOV_CLOSE       0x1023
#define PS_IOV_FORCE_CLOSE 0x1024

#define PS_CMD_BITS 16
#define PS_CMD_MASK ((1 << PS_CMD_BITS) - 1)

struct page_server_iov {
	u32 cmd;
	u64 nr_pages;
	u64 vaddr;
	u64 dst_id;
};

/* Protocol helpers - static inline for header inclusion */
static inline u32 encode_ps_cmd(u32 cmd, u32 flags)
{
	return flags << PS_CMD_BITS | cmd;
}

static inline u32 decode_ps_cmd(u32 cmd)
{
	return cmd & PS_CMD_MASK;
}

/* TLS-aware send/recv wrappers (use global TLS session — main socket only) */
extern int page_server_send(int sk, const void *buf, size_t sz, int fl);
extern int page_server_recv(int sk, void *buf, size_t sz, int fl);

/* Raw send/recv — bypasses TLS, for P3 parallel sockets */
extern int page_server_send_raw(int sk, const void *buf, size_t sz, int fl);
extern int page_server_recv_raw(int sk, void *buf, size_t sz, int fl);
extern int send_psi(int sk, struct page_server_iov *pi);
extern void page_server_tcp_nodelay(int sk, bool on);

extern int cr_page_server(bool daemon_mode, bool lazy_dump, int cfd);

/* User buffer for read-mode pre-dump*/
#define PIPE_MAX_BUFFER_SIZE (PIPE_MAX_SIZE << PAGE_SHIFT)

/*
 * page_xfer -- transfer pages into image file.
 * Two images backends are implemented -- local image file
 * and page-server image file.
 */

struct page_xfer {
	/* transfers one vaddr:len entry */
	int (*write_pagemap)(struct page_xfer *self, struct iovec *iov, u32 flags);
	/* transfers pages related to previous pagemap */
	int (*write_pages)(struct page_xfer *self, int pipe, unsigned long len);
	void (*close)(struct page_xfer *self);

	/*
	 * In case we need to dump pagemaps not as-is, but
	 * relative to some address. Used, e.g. by shmem.
	 */
	unsigned long offset;
	bool transfer_lazy;

	/* private data for every page-xfer engine */
	union {
		struct /* local */ {
			struct cr_img *pmi; /* pagemaps */
			struct cr_img *pi;  /* pages */
		};

		struct /* page-server */ {
			int sk;
			u64 dst_id;
		};
	};

	struct page_read *parent;
};

extern int open_page_xfer(struct page_xfer *xfer, int fd_type, unsigned long id);
struct page_pipe;
extern int page_xfer_dump_pages(struct page_xfer *, struct page_pipe *);
extern int page_xfer_predump_pages(int pid, struct page_xfer *, struct page_pipe *);
extern int connect_to_page_server_to_send(void);
extern int connect_to_page_server_to_recv(int epfd);
extern int remove_page_server_from_epoll(int epfd);
extern int disconnect_from_page_server(void);
extern int get_page_server_sk(void);
extern void wait_for_page_server_thread(void);

extern int check_parent_page_xfer(int fd_type, unsigned long id);

/*
 * The post-copy migration makes it necessary to receive pages from
 * remote dump. The protocol we use for that is quite simple:
 * - lazy-pages sends request containing PS_IOV_GET(nr_pages, vaddr, pid)
 * - dump-side page server responds with PS_IOV_ADD(nr_pages, vaddr,
     pid) or PS_IOV_ADD(0, 0, 0) if it failed to locate the required
     pages
 * - dump-side page server sends the raw page data
 */

/* async request/receive of remote pages */
extern int request_remote_pages(unsigned long img_id, unsigned long addr, unsigned long nr_pages);

typedef int (*ps_async_read_complete)(unsigned long img_id, unsigned long vaddr, unsigned long nr_pages, void *);
extern int page_server_start_read(void *buf, unsigned long nr_pages, ps_async_read_complete complete, void *priv, unsigned flags);

/* CLONE phased migration: signal target that all pages sent, can zero-fill rest */
extern int send_all_pages_sent_signal(int sk);

/* CLONE phased migration: target ACK for all_pages_sent, source can close */
extern int send_all_pages_sent_ack(void);

/* P3 parallel transfer: target creates connections and receiver threads */
extern int start_p3_receiver_connections(int num_connections);
extern void stop_p3_receiver_connections(void);

#endif /* __CR_PAGE_XFER__H__ */
