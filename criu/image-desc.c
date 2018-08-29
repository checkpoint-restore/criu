#include <stdlib.h>

#include "image-desc.h"
#include "magic.h"
#include "image.h"

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

#define FD_ENTRY_F(_name, _fmt, _f)		\
	[CR_FD_##_name] = {			\
		.fmt	= _fmt ".img",		\
		.magic	= _name##_MAGIC,	\
		.oflags	= _f,			\
	}

struct cr_fd_desc_tmpl imgset_template[CR_FD_MAX] = {
	FD_ENTRY(INVENTORY,	"inventory"),
	FD_ENTRY(FDINFO,	"fdinfo-%u"),
	FD_ENTRY(PAGEMAP,	"pagemap-%lu"),
	FD_ENTRY(SHMEM_PAGEMAP,	"pagemap-shmem-%lu"),
	FD_ENTRY(REG_FILES,	"reg-files"),
	FD_ENTRY(EXT_FILES,	"ext-files"),
	FD_ENTRY(NS_FILES,	"ns-files"),
	FD_ENTRY(EVENTFD_FILE,	"eventfd"),
	FD_ENTRY(EVENTPOLL_FILE,"eventpoll"),
	FD_ENTRY(EVENTPOLL_TFD,	"eventpoll-tfd"),
	FD_ENTRY(SIGNALFD,	"signalfd"),
	FD_ENTRY(INOTIFY_FILE,	"inotify"),
	FD_ENTRY(INOTIFY_WD,	"inotify-wd"),
	FD_ENTRY(FANOTIFY_FILE,	"fanotify"),
	FD_ENTRY(FANOTIFY_MARK,	"fanotify-mark"),
	FD_ENTRY(CORE,		"core-%u"),
	FD_ENTRY(IDS,		"ids-%u"),
	FD_ENTRY(MM,		"mm-%u"),
	FD_ENTRY(VMAS,		"vmas-%u"),
	FD_ENTRY(PIPES,		"pipes"),
	FD_ENTRY_F(PIPES_DATA,	"pipes-data", O_NOBUF), /* splices data */
	FD_ENTRY(FIFO,		"fifo"),
	FD_ENTRY_F(FIFO_DATA,	"fifo-data", O_NOBUF), /* the same */
	FD_ENTRY(PSTREE,	"pstree"),
	FD_ENTRY(SIGACT,	"sigacts-%u"),
	FD_ENTRY(UNIXSK,	"unixsk"),
	FD_ENTRY(INETSK,	"inetsk"),
	FD_ENTRY(PACKETSK,	"packetsk"),
	FD_ENTRY(NETLINK_SK,	"netlinksk"),
	FD_ENTRY_F(SK_QUEUES,	"sk-queues", O_NOBUF), /* lseeks the image */
	FD_ENTRY(ITIMERS,	"itimers-%u"),
	FD_ENTRY(POSIX_TIMERS,	"posix-timers-%u"),
	FD_ENTRY(CREDS,		"creds-%u"),
	FD_ENTRY(UTSNS,		"utsns-%u"),
	FD_ENTRY(IPC_VAR,	"ipcns-var-%u"),
	FD_ENTRY_F(IPCNS_SHM,	"ipcns-shm-%u", O_NOBUF), /* writes segments of data */
	FD_ENTRY(IPCNS_MSG,	"ipcns-msg-%u"),
	FD_ENTRY(IPCNS_SEM,	"ipcns-sem-%u"),
	FD_ENTRY(FS,		"fs-%u"),
	FD_ENTRY(REMAP_FPATH,	"remap-fpath"),
	FD_ENTRY_F(GHOST_FILE,	"ghost-file-%x", O_NOBUF),
	FD_ENTRY(TCP_STREAM,	"tcp-stream-%x"),
	FD_ENTRY(MNTS,		"mountpoints-%u"),
	FD_ENTRY(NETDEV,	"netdev-%u"),
	FD_ENTRY(NETNS,		"netns-%u"),
	FD_ENTRY_F(IFADDR,	"ifaddr-%u", O_NOBUF),
	FD_ENTRY_F(ROUTE,	"route-%u", O_NOBUF),
	FD_ENTRY_F(ROUTE6,	"route6-%u", O_NOBUF),
	FD_ENTRY_F(RULE,	"rule-%u", O_NOBUF),
	FD_ENTRY_F(IPTABLES,	"iptables-%u", O_NOBUF),
	FD_ENTRY_F(IP6TABLES,	"ip6tables-%u", O_NOBUF),
	FD_ENTRY_F(TMPFS_IMG,	"tmpfs-%u.tar.gz", O_NOBUF),
	FD_ENTRY_F(TMPFS_DEV,	"tmpfs-dev-%u.tar.gz", O_NOBUF),
	FD_ENTRY_F(AUTOFS,	"autofs-%u", O_NOBUF),
	FD_ENTRY(BINFMT_MISC_OLD, "binfmt-misc-%u"),
	FD_ENTRY(BINFMT_MISC,	"binfmt-misc"),
	FD_ENTRY(TTY_FILES,	"tty"),
	FD_ENTRY(TTY_INFO,	"tty-info"),
	FD_ENTRY_F(TTY_DATA,	"tty-data", O_NOBUF),
	FD_ENTRY(FILE_LOCKS,	"filelocks"),
	FD_ENTRY(RLIMIT,	"rlimit-%u"),
	FD_ENTRY_F(PAGES,	"pages-%u", O_NOBUF),
	FD_ENTRY_F(PAGES_OLD,	"pages-%d", O_NOBUF),
	FD_ENTRY_F(SHM_PAGES_OLD, "pages-shmem-%ld", O_NOBUF),
	FD_ENTRY(SIGNAL,	"signal-s-%u"),
	FD_ENTRY(PSIGNAL,	"signal-p-%u"),
	FD_ENTRY(TUNFILE,	"tunfile"),
	FD_ENTRY(CGROUP,	"cgroup"),
	FD_ENTRY(TIMERFD,	"timerfd"),
	FD_ENTRY(CPUINFO,	"cpuinfo"),
	FD_ENTRY(SECCOMP,	"seccomp"),
	FD_ENTRY(USERNS,	"userns-%u"),
	FD_ENTRY(NETNF_CT,	"netns-ct-%u"),
	FD_ENTRY(NETNF_EXP,	"netns-exp-%u"),
	FD_ENTRY(FILES,		"files"),

	[CR_FD_STATS] = {
		.fmt	= "stats-%s",
		.magic	= STATS_MAGIC,
		.oflags = O_SERVICE | O_FORCE_LOCAL,
	},

	[CR_FD_IRMAP_CACHE] = {
		.fmt	= "irmap-cache",
		.magic	= IRMAP_CACHE_MAGIC,
		.oflags = O_SERVICE | O_FORCE_LOCAL,
	},

	[CR_FD_FILE_LOCKS_PID] = {
		.fmt	= "filelocks-%u.img",
		.magic	= FILE_LOCKS_MAGIC,
	},
};
