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

#define FD_ENTRY(_name, _fmt)			\
	[CR_FD_##_name] = {			\
		.fmt	= _fmt ".img",		\
		.magic	= _name##_MAGIC,	\
	}

struct cr_fd_desc_tmpl fdset_template[CR_FD_MAX] = {
	FD_ENTRY(INVENTORY,	"inventory"),
	FD_ENTRY(FDINFO,	"fdinfo-%d"),
	FD_ENTRY(PAGEMAP,	"pagemap-%ld"),
	FD_ENTRY(SHMEM_PAGEMAP,	"pagemap-shmem-%ld"),
	FD_ENTRY(REG_FILES,	"reg-files"),
	FD_ENTRY(NS_FILES,	"ns-files"),
	FD_ENTRY(EVENTFD_FILE,	"eventfd"),
	FD_ENTRY(EVENTPOLL_FILE,"eventpoll"),
	FD_ENTRY(EVENTPOLL_TFD,	"eventpoll-tfd"),
	FD_ENTRY(SIGNALFD,	"signalfd"),
	FD_ENTRY(INOTIFY_FILE,	"inotify"),
	FD_ENTRY(INOTIFY_WD,	"inotify-wd"),
	FD_ENTRY(FANOTIFY_FILE,	"fanotify"),
	FD_ENTRY(FANOTIFY_MARK,	"fanotify-mark"),
	FD_ENTRY(CORE,		"core-%d"),
	FD_ENTRY(IDS,		"ids-%d"),
	FD_ENTRY(MM,		"mm-%d"),
	FD_ENTRY(VMAS,		"vmas-%d"),
	FD_ENTRY(PIPES,		"pipes"),
	FD_ENTRY(PIPES_DATA,	"pipes-data"),
	FD_ENTRY(FIFO,		"fifo"),
	FD_ENTRY(FIFO_DATA,	"fifo-data"),
	FD_ENTRY(PSTREE,	"pstree"),
	FD_ENTRY(SIGACT,	"sigacts-%d"),
	FD_ENTRY(UNIXSK,	"unixsk"),
	FD_ENTRY(INETSK,	"inetsk"),
	FD_ENTRY(PACKETSK,	"packetsk"),
	FD_ENTRY(NETLINK_SK,	"netlinksk"),
	FD_ENTRY(SK_QUEUES,	"sk-queues"),
	FD_ENTRY(ITIMERS,	"itimers-%d"),
	FD_ENTRY(POSIX_TIMERS,	"posix-timers-%d"),
	FD_ENTRY(CREDS,		"creds-%d"),
	FD_ENTRY(UTSNS,		"utsns-%d"),
	FD_ENTRY(IPC_VAR,	"ipcns-var-%d"),
	FD_ENTRY(IPCNS_SHM,	"ipcns-shm-%d"),
	FD_ENTRY(IPCNS_MSG,	"ipcns-msg-%d"),
	FD_ENTRY(IPCNS_SEM,	"ipcns-sem-%d"),
	FD_ENTRY(FS,		"fs-%d"),
	FD_ENTRY(REMAP_FPATH,	"remap-fpath"),
	FD_ENTRY(GHOST_FILE,	"ghost-file-%x"),
	FD_ENTRY(TCP_STREAM,	"tcp-stream-%x"),
	FD_ENTRY(MNTS,		"mountpoints-%d"),
	FD_ENTRY(NETDEV,	"netdev-%d"),
	FD_ENTRY(IFADDR,	"ifaddr-%d"),
	FD_ENTRY(ROUTE,		"route-%d"),
	FD_ENTRY(IPTABLES,	"iptables-%d"),
	FD_ENTRY(TMPFS,		"tmpfs-%d.tar.gz"),
	FD_ENTRY(TTY_FILES,	"tty"),
	FD_ENTRY(TTY_INFO,	"tty-info"),
	FD_ENTRY(FILE_LOCKS,	"filelocks-%d"),
	FD_ENTRY(RLIMIT,	"rlimit-%d"),
	FD_ENTRY(PAGES,		"pages-%u"),
	FD_ENTRY(PAGES_OLD,	"pages-%d"),
	FD_ENTRY(SHM_PAGES_OLD, "pages-shmem-%ld"),
	FD_ENTRY(SIGNAL,	"signal-s-%d"),
	FD_ENTRY(PSIGNAL,	"signal-p-%d"),
	FD_ENTRY(TUNFILE,	"tunfile"),

	[CR_FD_STATS] = {
		.fmt	= "stats-%s",
		.magic	= STATS_MAGIC,
	},
};
