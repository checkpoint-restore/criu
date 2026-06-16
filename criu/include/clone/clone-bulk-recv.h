#ifndef __CR_CLONE_BULK_RECV_H__
#define __CR_CLONE_BULK_RECV_H__

#include <stdbool.h>

struct epoll_rfd;

/*
 * CLONE control message receiver (target side).
 *
 * All page data is transferred via P3 receiver threads. This module
 * only handles control messages on the main page server socket:
 * - End-of-transfer marker (nr_pages == 0)
 * - PS_IOV_ALL_PAGES_SENT signal
 */

#ifdef CONFIG_HAS_LZ4

/* Epoll callback for main socket control messages */
extern int page_server_async_read_bulk(struct epoll_rfd *f);

/* Initialize the control message reader */
extern int page_server_start_async_read_bulk(void);

/* Cleanup reader state (call before closing socket) */
extern void page_server_cleanup_async_bulk(void);

/* TCP helper (implemented in page-xfer.c) */
extern void page_server_tcp_nodelay(int sk, bool on);

#else /* !CONFIG_HAS_LZ4 */

static inline int page_server_async_read_bulk(struct epoll_rfd *f) { (void)f; return -1; }
static inline int page_server_start_async_read_bulk(void) { return -1; }
static inline void page_server_cleanup_async_bulk(void) { }

#endif /* CONFIG_HAS_LZ4 */

#endif /* __CR_CLONE_BULK_RECV_H__ */
