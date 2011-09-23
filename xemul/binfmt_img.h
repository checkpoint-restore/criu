#ifndef __BINFMT_IMG_H__
#define __BINFMT_IMG_H__

#include <linux/types.h>

#define __packed	__attribute__((packed))

struct binfmt_img_header {
	__u32	magic;
	__u32	version;
	__u16	arch;
	__u16	flags;
} __packed;

#define CKPT_TLS_ENTRIES	3

struct binfmt_regs_image {
	union {
		struct {
			__u64	r15;
			__u64	r14;
			__u64	r13;
			__u64	r12;
			__u64	r11;
			__u64	r10;
			__u64	r9;
			__u64	r8;
			__u64	ax;
			__u64	orig_ax;
			__u64	bx;
			__u64	cx;
			__u64	dx;
			__u64	si;
			__u64	di;
			__u64	ip;
			__u64	flags;
			__u64	bp;
			__u64	sp;

			__u64	gs;
			__u64	fs;
			__u64	tls[CKPT_TLS_ENTRIES];
			__u16	gsindex;
			__u16	fsindex;
			__u16	cs;
			__u16	ss;
			__u16	ds;
			__u16	es;
		} r;
		__u64	dummy[32];
	};
} __packed;

#define CKPT_X86_SEG_NULL       0
#define CKPT_X86_SEG_USER32_CS  1
#define CKPT_X86_SEG_USER32_DS  2
#define CKPT_X86_SEG_USER64_CS  3
#define CKPT_X86_SEG_USER64_DS  4
#define CKPT_X86_SEG_TLS        0x4000
#define CKPT_X86_SEG_LDT        0x8000

struct binfmt_mm_image {
	__u64	flags;
	__u64	def_flags;
	__u64	start_code;
	__u64	end_code;
	__u64	start_data;
	__u64	end_data;
	__u64	start_brk;
	__u64	brk;
	__u64	start_stack;
	__u64	arg_start;
	__u64	arg_end;
	__u64	env_start;
	__u64	env_end;
	__u32	exe_fd;
} __packed;

struct binfmt_vma_image {
	__u32	prot;
	__u32	flags;
	__u32	pad;
	__u32	fd;
	__u64	start;
	__u64	end;
	__u64	pgoff;
} __packed;

struct binfmt_page_image {
	__u64	vaddr;
} __packed;

#define BINFMT_IMG_MAGIC	0xa75b8d43
#define BINFMT_IMG_VERS_0	0x00000100

#endif
