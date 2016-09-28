#ifndef __COMPEL_INFECT_PRIV_H__
#define __COMPEL_INFECT_PRIV_H__

#include <stdbool.h>

/* parasite control block */
struct parasite_ctl {
	int			rpid;					/* Real pid of the victim */
	void			*remote_map;
	void			*local_map;
	void			*sigreturn_addr;			/* A place for the breakpoint */
	unsigned long		map_length;

	struct infect_ctx	ictx;

	/* thread leader data */
	bool			daemonized;

	struct thread_ctx	orig;

	void			*rstack;				/* thread leader stack*/
	struct rt_sigframe	*sigframe;
	struct rt_sigframe	*rsigframe;				/* address in a parasite */

	void			*r_thread_stack;			/* stack for non-leader threads */

	unsigned long		parasite_ip;				/* service routine start ip */

	unsigned int		*addr_cmd;				/* addr for command */
	void			*addr_args;				/* address for arguments */
	unsigned long		args_size;
	int			tsock;					/* transport socket for transferring fds */
};

#endif
