#ifndef __COMPEL_RPC_H__
#define __COMPEL_RPC_H__
struct ctl_msg {
	uint32_t	cmd;			/* command itself */
	uint32_t	ack;			/* ack on command */
	int32_t		err;			/* error code on reply */
};

#define ctl_msg_cmd(_cmd)		\
	(struct ctl_msg){.cmd = _cmd, }

#define ctl_msg_ack(_cmd, _err)	\
	(struct ctl_msg){.cmd = _cmd, .ack = _cmd, .err = _err, }

/*
 * NOTE: each command's args should be arch-independed sized.
 * If you want to use one of the standard types, declare
 * alternative type for compatible tasks in parasite-compat.h
 */
enum {
	PARASITE_CMD_IDLE		= 0,
	PARASITE_CMD_ACK,

	PARASITE_CMD_INIT_DAEMON,

	/*
	 * This must be greater than INITs.
	 */
	PARASITE_CMD_FINI,

	__PARASITE_END_CMDS,
};

struct parasite_init_args {
	int32_t				h_addr_len;
	struct sockaddr_un		h_addr;
	int32_t				log_level;
	uint64_t			sigreturn_addr;
	uint64_t			sigframe; /* pointer to sigframe */
	futex_t				daemon_connected;
};

struct parasite_unmap_args {
	uint64_t	parasite_start;
	uint64_t	parasite_len;
};
#endif
