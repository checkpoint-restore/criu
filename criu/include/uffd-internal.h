#ifndef __CR_UFFD_INTERNAL_H_
#define __CR_UFFD_INTERNAL_H_

#include <stdbool.h>
#include <sys/uio.h>
#include "int.h"
#include "common/list.h"
#include "util.h"
#include "pagemap.h"
#include "common/lock.h"

/* CLONE mode protocol signals (shared between uffd.c and clone-uffd.c) */
#define LAZY_PAGES_DRAIN_COMPLETE   0x44524E43
#define LAZY_PAGES_TASKS_FROZEN     0x54534B46

/*
 * Internal uffd structures shared between uffd.c and clone-uffd.c
 */

struct lazy_iov {
	struct list_head l;
	unsigned long start;	 /* run-time start address, tracks remaps */
	unsigned long end;	 /* run-time end address, tracks remaps */
	unsigned long img_start; /* start address at the dump time */
	bool is_new_vma;	 /* true if this IOV is for a Phase 3 new VMA */
};

struct lazy_pages_info {
	int pid;
	bool exited;

	struct list_head iovs;
	struct list_head reqs;

	struct lazy_pages_info *parent;
	unsigned ref_cnt;

	struct page_read pr;

	unsigned long xfer_len; /* in pages */
	unsigned long total_pages;
	unsigned long copied_pages;

	struct epoll_rfd lpfd;

	struct list_head l;

	unsigned long buf_size;
	void *buf;
};

/* Pending EAGAIN requests (for bulk mode) */
struct uffd_eagain_request {
	struct list_head l;
	struct lazy_pages_info *lpi;
	__u64 address;
	unsigned long nr_pages;
	void *buf;  /* Copy of data that couldn't be written */
};


/* Logging macros for lazy_pages_info */
#define lp_debug(lpi, fmt, arg...)  pr_debug("%d-%d: " fmt, lpi->pid, lpi->lpfd.fd, ##arg)
#define lp_info(lpi, fmt, arg...)   pr_info("%d-%d: " fmt, lpi->pid, lpi->lpfd.fd, ##arg)
#define lp_warn(lpi, fmt, arg...)   pr_warn("%d-%d: " fmt, lpi->pid, lpi->lpfd.fd, ##arg)
#define lp_err(lpi, fmt, arg...)    pr_err("%d-%d: " fmt, lpi->pid, lpi->lpfd.fd, ##arg)
#define lp_perror(lpi, fmt, arg...) pr_perror("%d-%d: " fmt, lpi->pid, lpi->lpfd.fd, ##arg)

/* Helper functions from uffd.c needed by clone-uffd.c */
extern void lpi_put(struct lazy_pages_info *lpi);
extern void lazy_pages_summary(struct lazy_pages_info *lpi);

/* Functions from uffd.c exposed for clone-phase3 */
extern int uffd_open_task(int client, struct lazy_pages_info **_lpi);
extern int uffd_prepare_listen_socket(void);
extern struct list_head *uffd_get_lpis(void);
extern struct epoll_rfd *uffd_get_lazy_sk_rfd(void);
extern void uffd_set_epollfd(int fd);
extern int uffd_get_epollfd(void);
extern int uffd_lazy_sk_read_event(struct epoll_rfd *rfd);
extern int uffd_lazy_sk_hangup_event(struct epoll_rfd *rfd);
extern int uffd_zero(struct lazy_pages_info *lpi, __u64 address, unsigned long nr_pages);

#ifdef CONFIG_HAS_LZ4
/*
 * CLONE-specific functions from uffd_clone.c
 */

/*
 * Handle CLONE mode exit conditions.
 * Waits for: all_pages_sent signal, drain thread done, buffer empty.
 * Sends ACK to primary, cleans up lpis.
 * Returns: 1 = exit main loop, 0 = continue
 */
extern int clone_handle_exit(struct list_head *lpis);
#else
static inline int clone_handle_exit(struct list_head *lpis) { (void)lpis; return 0; }
#endif /* CONFIG_HAS_LZ4 */

#endif /* __CR_UFFD_INTERNAL_H_ */
