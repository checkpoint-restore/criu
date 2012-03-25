#ifndef CR_IMAGE_H
#define CR_IMAGE_H

#include "types.h"
#include "compiler.h"

/*
 * The magic-s below correspond to coordinates
 * of various Russian towns in the NNNNEEEE form.
 */

#define PSTREE_MAGIC	0x50273030 /* Kyiv */
#define FDINFO_MAGIC	0x56213732 /* Dmitrov */
#define PAGES_MAGIC	0x56084025 /* Vladimir */
#define CORE_MAGIC	0x55053847 /* Kolomna */
#define VMAS_MAGIC	0x54123737 /* Tula */
#define PIPES_MAGIC	0x56513555 /* Tver */
#define SIGACT_MAGIC	0x55344201 /* Murom */
#define UNIXSK_MAGIC	0x54373943 /* Ryazan */
#define INETSK_MAGIC	0x56443851 /* Pereslavl */
#define ITIMERS_MAGIC	0x57464056 /* Kostroma */
#define SK_QUEUES_MAGIC	0x56264026 /* Suzdal */
#define UTSNS_MAGIC	0x54473203 /* Smolensk */
#define CREDS_MAGIC	0x54023547 /* Kozelsk */
#define IPCNS_VAR_MAGIC	0x53115007 /* Samara */
#define IPCNS_SHM_MAGIC	0x46283044 /* Odessa */
#define IPCNS_MSG_MAGIC	0x55453737 /* Moscow */
#define IPCNS_SEM_MAGIC	0x59573019 /* St. Petersburg */

#define PIPEFS_MAGIC	0x50495045

enum fd_types {
	FDINFO_UND,
	FDINFO_REG,
	FDINFO_MAP,

	FDINFO_CWD,
	FDINFO_EXE,

	FD_INFO_MAX
};

#define PAGE_IMAGE_SIZE	4096
#define PAGE_RSS	1
#define PAGE_ANON	2

struct fdinfo_entry {
	u8	type;
	u16	len;
	u16	flags;
	u64	pos;
	u64	addr;
	u32	id;
	u8	name[0];
} __packed;

#define fd_is_special(fe)		\
	(((fe)->type == FDINFO_MAP) ||	\
	 ((fe)->type == FDINFO_CWD) ||	\
	 ((fe)->type == FDINFO_EXE))

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

#define USK_INFLIGHT		1

struct unix_sk_entry {
	u32	fd;
	u32	id;
	u8	type;
	u8	state;
	u8	namelen; /* fits UNIX_PATH_MAX */
	u8	flags;
	u32	backlog;
	u32	peer;
	u8	name[0];
} __packed;

struct inet_sk_entry {
	u32	fd;
	u32	id;
	u8	family;
	u8	type;
	u8	proto;
	u8	state;
	u16	src_port;
	u16	dst_port;
	u32	backlog;
	u32	src_addr[4];
	u32	dst_addr[4];
} __packed;

struct sk_packet_entry {
	u32	id_for;
	u32	length;
	u8	data[0];
} __packed;

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

struct ipc_var_entry {
	u32	sem_ctls[4];
	u32	msg_ctlmax;
	u32	msg_ctlmnb;
	u32	msg_ctlmni;
	u32	auto_msgmni;
	u64	shm_ctlmax;
	u64	shm_ctlall;
	u32	shm_ctlmni;
	u32	shm_rmid_forced;
	u32	mq_queues_max;
	u32	mq_msg_max;
	u32	mq_msgsize_max;
} __packed;

struct ipc_desc_entry {
	u32	key;
	u32	uid;
	u32	gid;
	u32	cuid;
	u32	cgid;
	u32	mode;
	u32	id;
	u8	pad[4];
} __packed;

struct ipc_shm_entry {
	struct ipc_desc_entry desc;
	u64	size;
} __packed;

struct ipc_msg {
	u64	mtype;
	u32	msize;
	u8	pad[4];
} __packed;

struct ipc_msg_entry {
	struct ipc_desc_entry desc;
	u16	qbytes;
	u16	qnum;
	u8	pad[4];
} __packed;

struct ipc_sem_entry {
	struct ipc_desc_entry desc;
	u16	nsems;
	u8	pad[6];
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

#define final_page_va(va)		((va) == ~0LL)
#define final_page_entry(page_entry)	(final_page_va((page_entry)->va))

struct sa_entry {
	u64		sigaction;
	u64		flags;
	u64		restorer;
	u64		mask;
} __packed;

struct itimer_entry {
	u64		isec;
	u64		iusec;
	u64		vsec;
	u64		vusec;
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
	u64				mm_start_code;
	u64				mm_end_code;
	u64				mm_start_data;
	u64				mm_end_data;
	u64				mm_start_stack;
	u64				mm_start_brk;
	u64				mm_brk;
	u64				mm_arg_start;
	u64				mm_arg_end;
	u64				mm_env_start;
	u64				mm_env_end;
	u64				blk_sigset;
	u64				mm_saved_auxv[AT_VECTOR_SIZE];
};

struct core_entry {
	union {
		struct {
			struct image_header	header;
			struct task_core_entry	tc;
			struct ckpt_arch_entry	arch;
			u64 clear_tid_address;
		};
		u8 __core_pad[CKPT_CORE_SIZE];
	};
} __packed;

#define TASK_ALIVE		0x1
#define TASK_DEAD		0x2
#define TASK_STOPPED		0x3 /* FIXME - implement */

#endif /* CONFIG_X86_64 */

/*
 * There are always 4 magic bytes at the
 * beginning of the every file.
 */
#define MAGIC_OFFSET		(sizeof(u32))
#define GET_FILE_OFF(s, m)	(offsetof(s,m) + MAGIC_OFFSET)
#define GET_FILE_OFF_AFTER(s)	(sizeof(s) + MAGIC_OFFSET)

#endif /* CR_IMAGE_H */
