#ifndef __CR_CLONE_PAGE_XFER_H__
#define __CR_CLONE_PAGE_XFER_H__

#include <stdbool.h>
#include "int.h"

/*
 * CLONE-specific page server protocol commands.
 * These extend the base PS_IOV_* protocol for CLONE migration.
 */
#define PS_IOV_GET_ALL            8   /* Target -> Source: request all pages */
#define PS_IOV_ADD_F_COMPRESS     10  /* Source -> Target: compressed page data */
#define PS_IOV_ALL_PAGES_SENT     16  /* Source -> Target: all pages sent, zero-fill rest */
#define PS_IOV_ALL_PAGES_SENT_ACK 17  /* Target -> Source: ACK, safe to close connection */
#define PS_IOV_SKELETON_FILE      20  /* Source -> Target: skeleton image file transfer */

#ifdef CONFIG_HAS_LZ4

/* Global compression statistics (used by clone-bulk-send.c) */
extern unsigned long g_compress_uncompressed_bytes;
extern unsigned long g_compress_compressed_bytes;

/* Wait for all_pages_sent ACK (called from page-xfer.c) */
extern int wait_for_all_pages_sent_ack(int sk);

/*
 * CLONE signaling functions are declared in page-xfer.h:
 * - send_all_pages_sent_signal()
 * - send_all_pages_sent_ack()
 * - start_p3_receiver_connections()
 * - stop_p3_receiver_connections()
 */


/* P3 parallel receiver functions (clone-p3-receiver.c) */
extern int accept_p3_connections(int *sockets, int max_connections, int timeout_ms);
extern void close_p3_sockets(int *sockets, int num_sockets);

/* CLONE request all pages (batch mode) */
extern int clone_request_all_remote_pages(unsigned long img_id);

/* CLONE server-side socket close */
extern void clone_close_page_server_socket(void);

/* CLONE skeleton file transfer: send all .img files over TCP */
extern int clone_send_skeleton_files(int sk);

/*
 * Write lazy VMA entries to pagemap for uffd handler (collect_iovs).
 * See clone_write_lazy_vmas_to_pagemap() in clone-page-xfer.c for details.
 */
struct page_xfer;
struct lazy_vma_entry;
extern int clone_write_lazy_vmas_to_pagemap(struct page_xfer *xfer, unsigned long before_vaddr,
					    struct lazy_vma_entry **cur_lve);

#else /* !CONFIG_HAS_LZ4 */

/* Stubs when LZ4/CLONE support is not compiled in */
static inline int wait_for_all_pages_sent_ack(int sk) { (void)sk; return -1; }
static inline int accept_p3_connections(int *sockets, int max, int timeout)
{
	(void)sockets; (void)max; (void)timeout;
	return -1;
}
static inline void close_p3_sockets(int *sockets, int num) { (void)sockets; (void)num; }
static inline int clone_request_all_remote_pages(unsigned long img_id) { (void)img_id; return -1; }
static inline void clone_close_page_server_socket(void) { }
static inline int clone_send_skeleton_files(int sk) { (void)sk; return -1; }

struct page_xfer;
struct lazy_vma_entry;
static inline int clone_write_lazy_vmas_to_pagemap(struct page_xfer *xfer,
						   unsigned long before_vaddr,
						   struct lazy_vma_entry **cur_lve)
{
	(void)xfer; (void)before_vaddr; (void)cur_lve;
	return 0;
}

#endif /* CONFIG_HAS_LZ4 */

#endif /* __CR_CLONE_PAGE_XFER_H__ */
