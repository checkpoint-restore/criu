#ifndef CR_IMAGE_H
#define CR_IMAGE_H

#include "types.h"
#include "compiler.h"

/*
 * Basic multi-file images
 */

#define CRTOOLS_IMAGES_V1	1

/*
 * Raw images are images in which data is stored in some
 * non-crtool format (ip tool dumps, tarballs, etc.)
 */

#define RAW_IMAGE_MAGIC		0x0

/*
 * The magic-s below correspond to coordinates
 * of various Russian towns in the NNNNEEEE form.
 */

#define INVENTORY_MAGIC		0x58313116 /* Veliky Novgorod */
#define PSTREE_MAGIC		0x50273030 /* Kyiv */
#define FDINFO_MAGIC		0x56213732 /* Dmitrov */
#define PAGES_MAGIC		0x56084025 /* Vladimir */
#define SHMEM_PAGES_MAGIC	PAGES_MAGIC
#define CORE_MAGIC		0x55053847 /* Kolomna */
#define VMAS_MAGIC		0x54123737 /* Tula */
#define PIPES_MAGIC		0x56513555 /* Tver */
#define PIPES_DATA_MAGIC	0x56453709 /* Dubna */
#define FIFO_MAGIC		0x58364939 /* Kirov */
#define FIFO_DATA_MAGIC		0x59333054 /* Tosno */
#define SIGACT_MAGIC		0x55344201 /* Murom */
#define UNIXSK_MAGIC		0x54373943 /* Ryazan */
#define INETSK_MAGIC		0x56443851 /* Pereslavl */
#define PACKETSK_MAGIC		0x60454618 /* Veliky Ustyug */
#define ITIMERS_MAGIC		0x57464056 /* Kostroma */
#define SK_QUEUES_MAGIC		0x56264026 /* Suzdal */
#define UTSNS_MAGIC		0x54473203 /* Smolensk */
#define CREDS_MAGIC		0x54023547 /* Kozelsk */
#define IPCNS_VAR_MAGIC		0x53115007 /* Samara */
#define IPCNS_SHM_MAGIC		0x46283044 /* Odessa */
#define IPCNS_MSG_MAGIC		0x55453737 /* Moscow */
#define IPCNS_SEM_MAGIC		0x59573019 /* St. Petersburg */
#define REG_FILES_MAGIC		0x50363636 /* Belgorod */
#define FS_MAGIC		0x51403912 /* Voronezh */
#define MM_MAGIC		0x57492820 /* Pskov */
#define REMAP_FPATH_MAGIC	0x59133954 /* Vologda */
#define GHOST_FILE_MAGIC	0x52583605 /* Oryol */
#define TCP_STREAM_MAGIC	0x51465506 /* Orenburg */
#define EVENTFD_MAGIC		0x44523722 /* Anapa */
#define EVENTPOLL_MAGIC		0x45023858 /* Krasnodar */
#define EVENTPOLL_TFD_MAGIC	0x44433746 /* Novorossiysk */
#define SIGNALFD_MAGIC		0x57323820 /* Uglich */
#define INOTIFY_MAGIC		0x48424431 /* Volgograd */
#define INOTIFY_WD_MAGIC	0x54562009 /* Svetlogorsk (Rauschen) */
#define MOUNTPOINTS_MAGIC	0x55563928 /* Petushki */
#define NETDEV_MAGIC		0x57373951 /* Yaroslavl */
#define TTY_MAGIC		0x59433025 /* Pushkin */
#define TTY_INFO_MAGIC		0x59453036 /* Kolpino */

#define IFADDR_MAGIC		RAW_IMAGE_MAGIC
#define ROUTE_MAGIC		RAW_IMAGE_MAGIC
#define TMPFS_MAGIC		RAW_IMAGE_MAGIC

#define PAGE_IMAGE_SIZE	4096
#define PAGE_RSS	1
#define PAGE_ANON	2

/*
 * Top bit set in the tgt id means we've remapped
 * to a ghost file.
 */
#define REMAP_GHOST	(1 << 31)

#define USK_EXTERN	(1 << 0)

#define VMA_AREA_NONE		(0 <<  0)
#define VMA_AREA_REGULAR	(1 <<  0)	/* Dumpable area */
#define VMA_AREA_STACK		(1 <<  1)
#define VMA_AREA_VSYSCALL	(1 <<  2)
#define VMA_AREA_VDSO		(1 <<  3)
#define VMA_FORCE_READ		(1 <<  4)	/* VMA changed to be readable */
#define VMA_AREA_HEAP		(1 <<  5)

#define VMA_FILE_PRIVATE	(1 <<  6)
#define VMA_FILE_SHARED		(1 <<  7)
#define VMA_ANON_SHARED		(1 <<  8)
#define VMA_ANON_PRIVATE	(1 <<  9)

#define VMA_AREA_SYSVIPC	(1 <<  10)

#define vma_entry_is(vma, s)	(((vma)->status & (s)) == (s))
#define vma_entry_len(vma)	((vma)->end - (vma)->start)

struct page_entry {
	u64	va;
	u8	data[PAGE_IMAGE_SIZE];
} __packed;

#define CR_CAP_SIZE	2

#ifdef CONFIG_X86_64

#define GDT_ENTRY_TLS_ENTRIES 3
#define TASK_COMM_LEN 16

#define TASK_PF_USED_MATH		0x00002000

#ifdef CONFIG_X86_64
# define AT_VECTOR_SIZE 44
#else
# define AT_VECTOR_SIZE 22		/* Not needed at moment */
#endif

#define TASK_ALIVE		0x1
#define TASK_DEAD		0x2
#define TASK_STOPPED		0x3 /* FIXME - implement */
#define TASK_HELPER		0x4

#endif /* CONFIG_X86_64 */

/*
 * There are always 4 magic bytes at the
 * beginning of the every file.
 */
#define MAGIC_OFFSET		(sizeof(u32))
#define GET_FILE_OFF(s, m)	(offsetof(s,m) + MAGIC_OFFSET)
#define GET_FILE_OFF_AFTER(s)	(sizeof(s) + MAGIC_OFFSET)

#endif /* CR_IMAGE_H */
