#ifndef UAPI_COMPEL_ASM_TYPES_H__
#define UAPI_COMPEL_ASM_TYPES_H__

#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <compel/plugins/std/asm/syscall-types.h>

#define SIGMAX	   64
#define SIGMAX_OLD 31

#define ARCH_HAS_PTRACE_GET_THREAD_AREA

/*
 * Linux preserves three TLS segments in GDT.
 * Offsets in GDT differ between 32-bit and 64-bit machines.
 * For 64-bit x86 those GDT offsets are the same
 * for native and compat tasks.
 */
#define GDT_ENTRY_TLS_MIN 12
#define GDT_ENTRY_TLS_MAX 14
#define GDT_ENTRY_TLS_NUM 3
typedef struct {
	user_desc_t desc[GDT_ENTRY_TLS_NUM];
} tls_t;

struct thread_ctx;
struct parasite_ctl;
struct parasite_thread_ctl;
extern int __compel_arch_fetch_thread_area(int tid, struct thread_ctx *th);
extern int compel_arch_fetch_thread_area(struct parasite_thread_ctl *tctl);
extern void compel_arch_get_tls_thread(struct parasite_thread_ctl *tctl, tls_t *out);
extern void compel_arch_get_tls_task(struct parasite_ctl *ctl, tls_t *out);

typedef struct {
	uint64_t r15;
	uint64_t r14;
	uint64_t r13;
	uint64_t r12;
	uint64_t bp;
	uint64_t bx;
	uint64_t r11;
	uint64_t r10;
	uint64_t r9;
	uint64_t r8;
	uint64_t ax;
	uint64_t cx;
	uint64_t dx;
	uint64_t si;
	uint64_t di;
	uint64_t orig_ax;
	uint64_t ip;
	uint64_t cs;
	uint64_t flags;
	uint64_t sp;
	uint64_t ss;
	uint64_t fs_base;
	uint64_t gs_base;
	uint64_t ds;
	uint64_t es;
	uint64_t fs;
	uint64_t gs;
} user_regs_struct64;

typedef struct {
	uint32_t bx;
	uint32_t cx;
	uint32_t dx;
	uint32_t si;
	uint32_t di;
	uint32_t bp;
	uint32_t ax;
	uint32_t ds;
	uint32_t es;
	uint32_t fs;
	uint32_t gs;
	uint32_t orig_ax;
	uint32_t ip;
	uint32_t cs;
	uint32_t flags;
	uint32_t sp;
	uint32_t ss;
} user_regs_struct32;

/*
 * To be sure that we rely on inited reg->__is_native, this member
 * is (short int) instead of initial (bool). The right way to
 * check if regs are native or compat is to use user_regs_native() macro.
 * This should cost nothing, as *usually* sizeof(bool) == sizeof(short)
 */
typedef struct {
	union {
		user_regs_struct64 native;
		user_regs_struct32 compat;
	};
	short __is_native; /* use user_regs_native macro to check it */
} user_regs_struct_t;

#define NATIVE_MAGIC 0x0A
#define COMPAT_MAGIC 0x0C
static inline bool user_regs_native(user_regs_struct_t *pregs)
{
	return pregs->__is_native == NATIVE_MAGIC;
}

#define get_user_reg(pregs, name) ((user_regs_native(pregs)) ? ((pregs)->native.name) : ((pregs)->compat.name))

#define set_user_reg(pregs, name, val) \
	((user_regs_native(pregs)) ? ((pregs)->native.name = (val)) : ((pregs)->compat.name = (val)))

#if 0
typedef struct {
	unsigned short	cwd;
	unsigned short	swd;
	unsigned short	twd;	/* Note this is not the same as
				   the 32bit/x87/FSAVE twd */
	unsigned short	fop;
	u64		rip;
	u64		rdp;
	u32		mxcsr;
	u32		mxcsr_mask;
	u32		st_space[32];	/* 8*16 bytes for each FP-reg = 128 bytes */
	u32		xmm_space[64];	/* 16*16 bytes for each XMM-reg = 256 bytes */
	u32		padding[24];
} user_fpregs_struct_t;
#endif

typedef struct xsave_struct user_fpregs_struct_t;

#define REG_RES(regs)	      get_user_reg(&regs, ax)
#define REG_IP(regs)	      get_user_reg(&regs, ip)
#define SET_REG_IP(regs, val) set_user_reg(&regs, ip, val)
#define REG_SP(regs)	      get_user_reg(&regs, sp)
#define REG_SYSCALL_NR(regs)  get_user_reg(&regs, orig_ax)

#define __NR(syscall, compat) ((compat) ? __NR32_##syscall : __NR_##syscall)

/*
 * For x86_32 __NR_mmap inside the kernel represents old_mmap system
 * call, but since we didn't use it yet lets go further and simply
 * define own alias for __NR_mmap2 which would allow us to unify code
 * between 32 and 64 bits version.
 */
#define __NR32_mmap __NR32_mmap2

#endif /* UAPI_COMPEL_ASM_TYPES_H__ */
