#ifndef __CR_MAGIC_H__
#define __CR_MAGIC_H__

/*
 * Basic multi-file images
 */

#define CRTOOLS_IMAGES_V1 1
/*
 * v1.1 has common magic in the head of each image file,
 * except for inventory
 */
#define CRTOOLS_IMAGES_V1_1 2

/*
 * Raw images are images in which data is stored in some
 * non-crtool format (ip tool dumps, tarballs, etc.)
 */

#define RAW_IMAGE_MAGIC 0x0

/*
 * Images have the IMG_COMMON_MAGIC in the head. Service files
 * such as stats and irmap-cache have the IMG_SERVICE_MAGIC.
 */

#define IMG_COMMON_MAGIC  0x54564319 /* Sarov (a.k.a. Arzamas-16) */
#define IMG_SERVICE_MAGIC 0x55105940 /* Zlatoust */

/*
 * The magic-s below correspond to coordinates
 * of various Russian towns in the NNNNEEEE form.
 */

#define INVENTORY_MAGIC	     0x58313116 /* Veliky Novgorod */
#define PSTREE_MAGIC	     0x50273030 /* Kyiv */
#define FDINFO_MAGIC	     0x56213732 /* Dmitrov */
#define PAGEMAP_MAGIC	     0x56084025 /* Vladimir */
#define SHMEM_PAGEMAP_MAGIC  PAGEMAP_MAGIC
#define PAGES_MAGIC	     RAW_IMAGE_MAGIC
#define CORE_MAGIC	     0x55053847 /* Kolomna */
#define IDS_MAGIC	     0x54432030 /* Konigsberg */
#define VMAS_MAGIC	     0x54123737 /* Tula */
#define PIPES_MAGIC	     0x56513555 /* Tver */
#define PIPES_DATA_MAGIC     0x56453709 /* Dubna */
#define FIFO_MAGIC	     0x58364939 /* Kirov */
#define FIFO_DATA_MAGIC	     0x59333054 /* Tosno */
#define SIGACT_MAGIC	     0x55344201 /* Murom */
#define UNIXSK_MAGIC	     0x54373943 /* Ryazan */
#define INETSK_MAGIC	     0x56443851 /* Pereslavl */
#define PACKETSK_MAGIC	     0x60454618 /* Veliky Ustyug */
#define ITIMERS_MAGIC	     0x57464056 /* Kostroma */
#define POSIX_TIMERS_MAGIC   0x52603957 /* Lipetsk */
#define SK_QUEUES_MAGIC	     0x56264026 /* Suzdal */
#define UTSNS_MAGIC	     0x54473203 /* Smolensk */
#define CREDS_MAGIC	     0x54023547 /* Kozelsk */
#define IPC_VAR_MAGIC	     0x53115007 /* Samara */
#define IPCNS_SHM_MAGIC	     0x46283044 /* Odessa */
#define IPCNS_MSG_MAGIC	     0x55453737 /* Moscow */
#define IPCNS_SEM_MAGIC	     0x59573019 /* St. Petersburg */
#define REG_FILES_MAGIC	     0x50363636 /* Belgorod */
#define EXT_FILES_MAGIC	     0x59255641 /* Usolye */
#define FS_MAGIC	     0x51403912 /* Voronezh */
#define MM_MAGIC	     0x57492820 /* Pskov */
#define REMAP_FPATH_MAGIC    0x59133954 /* Vologda */
#define GHOST_FILE_MAGIC     0x52583605 /* Oryol */
#define TCP_STREAM_MAGIC     0x51465506 /* Orenburg */
#define EVENTFD_FILE_MAGIC   0x44523722 /* Anapa */
#define EVENTPOLL_FILE_MAGIC 0x45023858 /* Krasnodar */
#define EVENTPOLL_TFD_MAGIC  0x44433746 /* Novorossiysk */
#define SIGNALFD_MAGIC	     0x57323820 /* Uglich */
#define INOTIFY_FILE_MAGIC   0x48424431 /* Volgograd */
#define INOTIFY_WD_MAGIC     0x54562009 /* Svetlogorsk (Rauschen) */
#define MNTS_MAGIC	     0x55563928 /* Petushki */
#define NETDEV_MAGIC	     0x57373951 /* Yaroslavl */
#define NETNS_MAGIC	     0x55933752 /* Dolgoprudny */
#define TTY_FILES_MAGIC	     0x59433025 /* Pushkin */
#define TTY_INFO_MAGIC	     0x59453036 /* Kolpino */
#define TTY_DATA_MAGIC	     0x59413026 /* Pavlovsk */
#define FILE_LOCKS_MAGIC     0x54323616 /* Kaluga */
#define RLIMIT_MAGIC	     0x57113925 /* Rostov */
#define FANOTIFY_FILE_MAGIC  0x55096122 /* Chelyabinsk */
#define FANOTIFY_MARK_MAGIC  0x56506035 /* Yekaterinburg */
#define SIGNAL_MAGIC	     0x59255647 /* Berezniki */
#define PSIGNAL_MAGIC	     SIGNAL_MAGIC
#define NETLINK_SK_MAGIC     0x58005614 /* Perm */
#define NS_FILES_MAGIC	     0x61394011 /* Nyandoma */
#define TUNFILE_MAGIC	     0x57143751 /* Kalyazin */
#define CGROUP_MAGIC	     0x59383330 /* Tikhvin */
#define TIMERFD_MAGIC	     0x50493712 /* Korocha */
#define CPUINFO_MAGIC	     0x61404013 /* Nyandoma */
#define USERNS_MAGIC	     0x55474906 /* Kazan */
#define SECCOMP_MAGIC	     0x64413049 /* Kostomuksha */
#define BINFMT_MISC_MAGIC    0x67343323 /* Apatity */
#define AUTOFS_MAGIC	     0x49353943 /* Sochi */
#define FILES_MAGIC	     0x56303138 /* Toropets */
#define MEMFD_INODE_MAGIC    0x48453499 /* Dnipro */
#define TIMENS_MAGIC	     0x43114433 /* Beslan */
#define PIDNS_MAGIC	     0x61157326 /* Surgut */
#define BPFMAP_FILE_MAGIC    0x57506142 /* Alapayevsk */
#define BPFMAP_DATA_MAGIC    0x64324033 /* Arkhangelsk */
#define APPARMOR_MAGIC	     0x59423047 /* Nikolskoye */

#define IFADDR_MAGIC	RAW_IMAGE_MAGIC
#define ROUTE_MAGIC	RAW_IMAGE_MAGIC
#define ROUTE6_MAGIC	RAW_IMAGE_MAGIC
#define RULE_MAGIC	RAW_IMAGE_MAGIC
#define TMPFS_IMG_MAGIC RAW_IMAGE_MAGIC
#define TMPFS_DEV_MAGIC RAW_IMAGE_MAGIC
#define IPTABLES_MAGIC	RAW_IMAGE_MAGIC
#define IP6TABLES_MAGIC RAW_IMAGE_MAGIC
#define NFTABLES_MAGIC	RAW_IMAGE_MAGIC
#define NETNF_CT_MAGIC	RAW_IMAGE_MAGIC
#define NETNF_EXP_MAGIC RAW_IMAGE_MAGIC

#define PAGES_OLD_MAGIC	      PAGEMAP_MAGIC
#define SHM_PAGES_OLD_MAGIC   PAGEMAP_MAGIC
#define BINFMT_MISC_OLD_MAGIC BINFMT_MISC_MAGIC

/*
 * These are special files, not exactly images
 */
#define STATS_MAGIC	  0x57093306 /* Ostashkov */
#define IRMAP_CACHE_MAGIC 0x57004059 /* Ivanovo */

/*
 * Main magic for kerndat_s structure.
 */

#define KDAT_MAGIC 0x57023458 /* Torzhok */

#endif /* __CR_MAGIC_H__ */
