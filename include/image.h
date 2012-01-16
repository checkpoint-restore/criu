#ifndef CR_IMAGE_H
#define CR_IMAGE_H

#include "types.h"
#include "compiler.h"

#define FDINFO_MAGIC	0x01010101
#define PAGES_MAGIC	0x20202020
#define CORE_MAGIC	0xa75b8d43
#define SHMEM_MAGIC	0x03300330
#define PIPEFS_MAGIC	0x50495045
#define PSTREE_MAGIC	0x40044004
#define PIPES_MAGIC	0x05055050
#define SIGACT_MAGIC	0x60606060
#define UNIXSK_MAGIC	0x07070707

#define FDINFO_FD	1
#define FDINFO_MAP	2

#define FDINFO_CWD	(~0ULL)

#define PAGE_IMAGE_SIZE	4096
#define PAGE_RSS	1
#define PAGE_ANON	2

#define FD_ID_SIZE	50

struct fdinfo_entry {
	u8	type;
	u8	len;
	u16	flags;
	u32	pos;
	u64	addr;
	u8	id[FD_ID_SIZE];
	u8	name[0];
} __packed;

#define fd_is_special(fe)	(((fe)->type != FDINFO_FD) || ((fe)->addr == FDINFO_CWD))

struct shmem_entry {
	u64	start;
	u64	end;
	u64	shmid;
} __packed;

struct pstree_entry {
	u32	pid;
	u32	nr_children;
	u32	nr_threads;
} __packed;

struct pipe_entry {
	u32	fd;
	u32	pipeid;
	u32	flags;
	u32	bytes;
	u8	data[0];
} __packed;

struct unix_sk_entry {
	u32	fd;
	u32	id;
	u8	type;
	u8	state;
	u8	namelen; /* fits UNIX_PATH_MAX */
	u8	pad;
	u32	backlog;
	u32	peer;
	u8	name[0];
} __packed;

struct vma_entry {
	u64	start;
	u64	end;
	u64	pgoff;
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

#define vma_entry_is(vma, s)	(((vma)->status & (s)) == (s))
#define vma_entry_len(vma)	((vma)->end - (vma)->start)
#define final_vma_entry(vma)	((vma)->start == 0 && (vma)->end == 0)

struct page_entry {
	u64	va;
	u8	data[PAGE_IMAGE_SIZE];
} __packed;

#define final_page_va(va)		((va) == 0)
#define final_page_entry(page_entry)	(final_page_va((page_entry)->va))

struct sa_entry {
	u64		sigaction;
	u64		flags;
	u64		restorer;
	u64		mask;
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

struct ckpt_arch_entry {
	struct user_regs_entry		gpregs;
	struct user_fpregs_entry	fpregs;
};

#define CKPT_ARCH_SIZE			(1 * 4096)
#define CKPT_CORE_SIZE			(2 * 4096)

struct core_entry {
  union {
    struct {
	struct image_header		header;
	union {
		struct ckpt_arch_entry	arch;				/* per-arch specific */
		u8			__arch_pad[CKPT_ARCH_SIZE];	/* should be enough for all */
	} u;
	u32				task_personality;
	u8				task_comm[TASK_COMM_LEN];
	u32				task_flags;
	u64				mm_start_code;
	u64				mm_end_code;
	u64				mm_start_data;
	u64				mm_end_data;
	u64				mm_start_stack;
	u64				mm_start_brk;
	u64				mm_brk;
	u64				task_sigset;
    };
    u8					__core_pad[CKPT_CORE_SIZE];
  };
} __packed;

#endif /* CONFIG_X86_64 */

/*
 * There are always 4 magic bytes at the
 * beginning of the every file.
 */
#define MAGIC_OFFSET		(sizeof(u32))
#define GET_FILE_OFF(s, m)	(offsetof(s,m) + MAGIC_OFFSET)
#define GET_FILE_OFF_AFTER(s)	(sizeof(s) + MAGIC_OFFSET)

#endif /* CR_IMAGE_H */
