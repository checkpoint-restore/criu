#ifndef COMPEL_PLUGIN_STD_STD_H__
#define COMPEL_PLUGIN_STD_STD_H__

#include "uapi/plugins.h"
#include "uapi/std/syscall.h"

struct prologue_init_args {
	struct sockaddr		*ctl_sock_addr;
	socklen_t		ctl_sock_addr_len;

	unsigned int		arg_s;
	void			*arg_p;
};

#endif /* COMPEL_PLUGIN_STD_STD_H__ */
