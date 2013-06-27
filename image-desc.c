#include <stdlib.h>

#include "image-desc.h"
#include "cr-show.h"
#include "magic.h"

/*
 * The cr fd set is the set of files where the information
 * about dumped processes is stored. Each file carries some
 * small portion of info about the whole picture, see below
 * for more details.
 */

#define FD_ENTRY(_name, _fmt, _show)		\
	[CR_FD_##_name] = {			\
		.fmt	= _fmt ".img",		\
		.magic	= _name##_MAGIC,	\
		.show	= _show,		\
	}

struct cr_fd_desc_tmpl fdset_template[CR_FD_MAX] = {
	FD_ENTRY(INVENTORY,	"inventory",		show_inventory),
	FD_ENTRY(FDINFO,	"fdinfo-%d",		show_files),
	FD_ENTRY(PAGEMAP,	"pagemap-%ld",		show_pagemap),
	FD_ENTRY(SHMEM_PAGEMAP,	"pagemap-shmem-%ld",	show_pagemap),
	FD_ENTRY(REG_FILES,	"reg-files",		show_reg_files),
	FD_ENTRY(NS_FILES,	"ns-files",		show_ns_files),
	FD_ENTRY(EVENTFD,	"eventfd",		show_eventfds),
	FD_ENTRY(EVENTPOLL,	"eventpoll",		show_eventpoll),
	FD_ENTRY(EVENTPOLL_TFD,	"eventpoll-tfd",	show_eventpoll_tfd),
	FD_ENTRY(SIGNALFD,	"signalfd",		show_signalfd),
	FD_ENTRY(INOTIFY,	"inotify",		show_inotify),
	FD_ENTRY(INOTIFY_WD,	"inotify-wd",		show_inotify_wd),
	FD_ENTRY(FANOTIFY,	"fanotify",		show_fanotify),
	FD_ENTRY(FANOTIFY_MARK,	"fanotify-mark",	show_fanotify_mark),
	FD_ENTRY(CORE,		"core-%d",		show_core),
	FD_ENTRY(IDS,		"ids-%d",		show_ids),
	FD_ENTRY(MM,		"mm-%d",		show_mm),
	FD_ENTRY(VMAS,		"vmas-%d",		show_vmas),
	FD_ENTRY(PIPES,		"pipes",		show_pipes),
	FD_ENTRY(PIPES_DATA,	"pipes-data",		show_pipes_data),
	FD_ENTRY(FIFO,		"fifo",			show_fifo),
	FD_ENTRY(FIFO_DATA,	"fifo-data",		show_fifo_data),
	FD_ENTRY(PSTREE,	"pstree",		show_pstree),
	FD_ENTRY(SIGACT,	"sigacts-%d",		show_sigacts),
	FD_ENTRY(UNIXSK,	"unixsk",		show_unixsk),
	FD_ENTRY(INETSK,	"inetsk",		show_inetsk),
	FD_ENTRY(PACKETSK,	"packetsk",		show_packetsk),
	FD_ENTRY(NETLINKSK,	"netlinksk",		show_netlinksk),
	FD_ENTRY(SK_QUEUES,	"sk-queues",		show_sk_queues),
	FD_ENTRY(ITIMERS,	"itimers-%d",		show_itimers),
	FD_ENTRY(POSIX_TIMERS,	"posix-timers-%d",	show_posix_timers),
	FD_ENTRY(CREDS,		"creds-%d",		show_creds),
	FD_ENTRY(UTSNS,		"utsns-%d",		show_utsns),
	FD_ENTRY(IPCNS_VAR,	"ipcns-var-%d",		show_ipc_var),
	FD_ENTRY(IPCNS_SHM,	"ipcns-shm-%d",		show_ipc_shm),
	FD_ENTRY(IPCNS_MSG,	"ipcns-msg-%d",		show_ipc_msg),
	FD_ENTRY(IPCNS_SEM,	"ipcns-sem-%d",		show_ipc_sem),
	FD_ENTRY(FS,		"fs-%d",		show_fs),
	FD_ENTRY(REMAP_FPATH,	"remap-fpath",		show_remap_files),
	FD_ENTRY(GHOST_FILE,	"ghost-file-%x",	show_ghost_file),
	FD_ENTRY(TCP_STREAM,	"tcp-stream-%x",	show_tcp_stream),
	FD_ENTRY(MOUNTPOINTS,	"mountpoints-%d",	show_mountpoints),
	FD_ENTRY(NETDEV,	"netdev-%d",		show_netdevices),
	FD_ENTRY(IFADDR,	"ifaddr-%d",		show_raw_image),
	FD_ENTRY(ROUTE,		"route-%d",		show_raw_image),
	FD_ENTRY(TMPFS,		"tmpfs-%d.tar.gz",	show_raw_image),
	FD_ENTRY(TTY,		"tty",			show_tty),
	FD_ENTRY(TTY_INFO,	"tty-info",		show_tty_info),
	FD_ENTRY(FILE_LOCKS,	"filelocks-%d",		show_file_locks),
	FD_ENTRY(RLIMIT,	"rlimit-%d",		show_rlimit),
	FD_ENTRY(PAGES,		"pages-%u",		NULL),
	FD_ENTRY(PAGES_OLD,	"pages-%d",		NULL),
	FD_ENTRY(SHM_PAGES_OLD, "pages-shmem-%ld",	NULL),
	FD_ENTRY(SIGNAL,	"signal-s-%d",		show_siginfo), /* shared signals */
	FD_ENTRY(PSIGNAL,	"signal-p-%d",		show_siginfo), /* private signals */

	[CR_FD_STATS] = {
		.fmt	= "stats-%s",
		.magic	= STATS_MAGIC,
		.show	= show_stats,
	},
};
