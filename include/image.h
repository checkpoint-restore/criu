#ifndef CR_IMAGE_H
#define CR_IMAGE_H

#include "types.h"
#include "compiler.h"

/*
 * The magic-s below correspond to coordinates
 * of various Russian towns in the NNNNEEEE form.
 */

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
#define INOTIFY_MAGIC		0x48424431 /* Volgograd */
#define INOTIFY_WD_MAGIC	0x54562009 /* Svetlogorsk (Rauschen) */
#define MOUNTPOINTS_MAGIC	0x55563928 /* Petushki */

#define PAGE_IMAGE_SIZE	4096
#define PAGE_RSS	1
#define PAGE_ANON	2

/*
 * Top bit set in the tgt id means we've remapped
 * to a ghost file.
 */
#define REMAP_GHOST	(1 << 31)

#define USK_EXTERN	(1 << 0)

struct vma_entry {
	u64	start;
	u64	end;
	u64	pgoff;
	u64	shmid;
	u32	prot;
	u32	flags;
	u32	status;
	s64	fd;
} __packed;

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

struct creds_entry {
	u32	uid;
	u32	gid;
	u32	euid;
	u32	egid;
	u32	suid;
	u32	sgid;
	u32	fsuid;
	u32	fsgid;

	u32	cap_inh[CR_CAP_SIZE];
	u32	cap_prm[CR_CAP_SIZE];
	u32	cap_eff[CR_CAP_SIZE];
	u32	cap_bnd[CR_CAP_SIZE];

	u32	secbits;
} __packed;

#define HEADER_VERSION		1
#define HEADER_ARCH_X86_64	1

struct image_header {
	u16	version;
	u16	arch;
	u32	flags;
} __packed;

/*
 * PTRACE_GETREGS
 * PTRACE_GETFPREGS
 * PTRACE_GETFPXREGS		dep CONFIG_X86_32
 * PTRACE_GET_THREAD_AREA	dep CONFIG_X86_32 || CONFIG_IA32_EMULATION
 * PTRACE_GETFDPIC		dep CONFIG_BINFMT_ELF_FDPIC
 *
 * PTRACE_ARCH_PRCTL		dep CONFIG_X86_64
 *  ARCH_SET_GS/ARCH_GET_FS
 *  ARCH_SET_FS/ARCH_GET_GS
 */

#ifdef CONFIG_X86_64

struct user_regs_entry {
	u64	r15;
	u64	r14;
	u64	r13;
	u64	r12;
	u64	bp;
	u64	bx;
	u64	r11;
	u64	r10;
	u64	r9;
	u64	r8;
	u64	ax;
	u64	cx;
	u64	dx;
	u64	si;
	u64	di;
	u64	orig_ax;
	u64	ip;
	u64	cs;
	u64	flags;
	u64	sp;
	u64	ss;
	u64	fs_base;
	u64	gs_base;
	u64	ds;
	u64	es;
	u64	fs;
	u64	gs;
} __packed;

struct desc_struct {
 union {
	struct {
		u32 a;
		u32 b;
	} x86_32;
	u64	base_addr;
 };
} __packed;

struct user_fpregs_entry {
	u16	cwd;
	u16	swd;
	u16	twd;	/* Note this is not the same as
			   the 32bit/x87/FSAVE twd */
	u16	fop;
	u64	rip;
	u64	rdp;
	u32	mxcsr;
	u32	mxcsr_mask;
	u32	st_space[32];	/* 8*16 bytes for each FP-reg = 128 bytes */
	u32	xmm_space[64];	/* 16*16 bytes for each XMM-reg = 256 bytes */
	u32	padding[24];
} __packed;

#define GDT_ENTRY_TLS_ENTRIES 3
#define TASK_COMM_LEN 16

#define TASK_PF_USED_MATH		0x00002000

#define CKPT_ARCH_SIZE			(1 * 4096)

struct ckpt_arch_entry {
	union {
		struct {
			struct user_regs_entry		gpregs;
			struct user_fpregs_entry	fpregs;
		};
		u8 __arch_pad[CKPT_ARCH_SIZE];	/* should be enough for all */
	};
};

#define CKPT_CORE_SIZE			(2 * 4096)

#ifdef CONFIG_X86_64
# define AT_VECTOR_SIZE 44
#else
# define AT_VECTOR_SIZE 22		/* Not needed at moment */
#endif

struct task_core_entry {
	u8				task_state;
	u8				pad[3];
	u32				exit_code;

	u32				personality;
	u8				comm[TASK_COMM_LEN];
	u32				flags;
	u64				blk_sigset;
};

struct core_ids_entry {
	u32	vm_id;
	u32	files_id;
	u32	fs_id;
	u32	sighand_id;
} __packed;

struct core_entry {
	union {
		struct {
			struct image_header	header;
			struct task_core_entry	tc;
			struct ckpt_arch_entry	arch;
			struct core_ids_entry	ids;
			u64 clear_tid_address;
		};
		u8 __core_pad[CKPT_CORE_SIZE];
	};
} __packed;

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
