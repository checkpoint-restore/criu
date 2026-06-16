#ifndef __CR_UFFD_H_
#define __CR_UFFD_H_

struct task_restore_args;
struct epoll_event;

extern int uffd_open(int flags, unsigned long *features, int *err);
extern bool uffd_noncooperative(void);
extern int setup_uffd(int pid, struct task_restore_args *task_args);
extern int lazy_pages_setup_zombie(int pid);
extern int prepare_lazy_pages_socket(void);
extern int lazy_pages_finish_restore(void);

#ifdef CONFIG_HAS_LZ4
/* CLONE phased migration: apply buffered pages after receiving dirty bitmap */
extern int apply_buffered_pages(int uffd, unsigned long *dirty_ranges,
				unsigned int nr_dirty_ranges);

/* Return uffd of first active lazy_pages_info. Used by page-xfer.c. */
extern int get_first_lpi_uffd(void);

/* CLONE Phase 2: Initialize page buffer for pre-buffering */
extern int page_buffer_init(void);

/* CLONE Phase 2: Set up async bulk reader for pre-buffering pages */
extern int clone_setup_prebuffer_reader(void);

/* CLONE Phase 3: Enter restore loop after pages buffered and pstree loaded */
extern int clone_phase3_restore_loop(int epollfd, struct epoll_event **events, int nr_fds);
#endif /* CONFIG_HAS_LZ4 */

#endif /* __CR_UFFD_H_ */
