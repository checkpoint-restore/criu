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

enum fd_types {
	FDINFO_UND,
	FDINFO_REG,
	FDINFO_PIPE,
	FDINFO_INETSK,
	FDINFO_UNIXSK,
	FDINFO_EVENTFD,
	FDINFO_EVENTPOLL,
	FDINFO_INOTIFY,

	FD_INFO_MAX
};

#define PAGE_IMAGE_SIZE	4096
#define PAGE_RSS	1
#define PAGE_ANON	2

typedef struct {
	u32	uid;
	u32	euid;
	u32	signum;
	u32	pid_type;
	u32	pid;
} __packed fown_t;

struct reg_file_entry {
	u32	id;
	u16	flags;
	u16	len;
	u64	pos;
	fown_t	fown;
	u8	name[0];
} __packed;

struct remap_file_path_entry {
	u32	orig_id;
	u32	remap_id;
} __packed;

/*
 * Top bit set in the tgt id means we've remapped
 * to a ghost file.
 */
#define REMAP_GHOST	(1 << 31)

struct ghost_file_entry {
	u32	uid;
	u32	gid;
	u32	mode;
} __packed;

struct eventfd_file_entry {
	u32	id;
	u16	flags;
	fown_t	fown;
	u64	counter;
} __packed;

struct eventpoll_tfd_entry {
	u32	id;
	u32	tfd;
	u32	events;
	u64	data;
} __packed;

struct eventpoll_file_entry {
	u32	id;
	u32	flags;
	fown_t	fown;
} __packed;

struct inotify_wd_entry {
	u32	id;
	u64	i_ino;
	u32	mask;
	u32	s_dev;
	u32	wd;
	fh_t	f_handle;
} __packed;

struct inotify_file_entry {
	u32	id;
	u16	flags;
	fown_t	fown;
} __packed;

struct fdinfo_entry {
	u32	fd;
	u8	type;
	u8	flags;
	u32	id;
} __packed;

struct fs_entry {
	u32	cwd_id;
	u32	root_id;
} __packed;

struct pstree_entry {
	u32	pid;
	u32	ppid;
	u32	pgid;
	u32	sid;
	u32	nr_threads;
} __packed;

struct pipe_entry {
	u32	id;
	u32	pipe_id;
	u32	flags;
	fown_t	fown;
} __packed;

struct pipe_data_entry {
	u32	pipe_id;
	u32	bytes;
	u32	off;
	u8	data[0];
} __packed;

/*
 * splice() connect cache pages to pipe buffer, so
 * some part of pages may be loosed if data are not
 * aligned in a file.
 */
#define PIPE_DEF_BUFFERS	16
#define PIPE_MAX_NONALIG_SIZE	((PIPE_DEF_BUFFERS - 1) * PAGE_SIZE)

#define USK_EXTERN	(1 << 0)

struct sk_opts_entry {
	u32	so_sndbuf;
	u32	so_rcvbuf;
	u64	so_snd_tmo[2];
	u64	so_rcv_tmo[2];
};

struct unix_sk_entry {
	u32	id;
	u32	ino;
	u8	type;
	u8	state;
	u8	namelen; /* fits UNIX_PATH_MAX */
	u8	pad;
	u32	flags;
	u32	uflags;  /* own service flags */
	u32	backlog;
	u32	peer;
	fown_t	fown;
	struct sk_opts_entry opts;
	u8	name[0];
} __packed;

struct inet_sk_entry {
	u32	id;
	u32	ino;
	u8	family;
	u8	type;
	u8	proto;
	u8	state;
	u16	src_port;
	u16	dst_port;
	u32	flags;
	u32	backlog;
	fown_t	fown;
	u32	src_addr[4];
	u32	dst_addr[4];
	struct sk_opts_entry opts;
} __packed;

struct tcp_stream_entry {
	u32	inq_len;
	u32	inq_seq;
	u32	outq_len;
	u32	outq_seq;

	u8	opt_mask;	/* TCPI_OPT_ bits */
	u8	snd_wscale;
	u16	mss_clamp;
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

struct mnt_entry {
	u32	mnt_id;
	u32	root_dev;
	u32	root_dentry_len;
	u32	parent_mnt_id;
	u32	mountpoint_path_len;
	u32	flags;
	u32	source_len;
	u32	options_len;
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
	u64				blk_sigset;
};

struct mm_entry {
	u64	mm_start_code;
	u64	mm_end_code;
	u64	mm_start_data;
	u64	mm_end_data;
	u64	mm_start_stack;
	u64	mm_start_brk;
	u64	mm_brk;
	u64	mm_arg_start;
	u64	mm_arg_end;
	u64	mm_env_start;
	u64	mm_env_end;
	u64	mm_saved_auxv[AT_VECTOR_SIZE];
	u32	exe_file_id;
} __packed;

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
