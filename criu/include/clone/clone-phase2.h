#ifndef __CR_CLONE_PHASE2_H__
#define __CR_CLONE_PHASE2_H__

#include <stdbool.h>
#include <sys/epoll.h>

#ifdef CONFIG_HAS_LZ4

/*
 * Clone receive entry point (criu clone-receive command).
 * Receives pages from the source, buffers them, triggers restore.
 */
extern int cr_clone_receive(bool daemon);

/*
 * CLONE Phase 2 entry point (internal, called by cr_clone_receive).
 * Buffers incoming pages without requiring inventory.img/pstree.img.
 */
extern int cr_clone_phase2(bool daemon);

/*
 * Event loop for Phase 2 page buffering.
 */
extern int clone_phase2_handle_pages(int epollfd, struct epoll_event *events, int nr_fds);

#else /* !CONFIG_HAS_LZ4 */

static inline int cr_clone_receive(bool daemon) { (void)daemon; return -1; }
static inline int cr_clone_phase2(bool daemon) { (void)daemon; return -1; }
static inline int clone_phase2_handle_pages(int epollfd, struct epoll_event *events, int nr_fds)
{
	(void)epollfd; (void)events; (void)nr_fds;
	return -1;
}

#endif /* CONFIG_HAS_LZ4 */

#endif /* __CR_CLONE_PHASE2_H__ */
