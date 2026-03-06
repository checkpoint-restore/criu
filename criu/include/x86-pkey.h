#ifndef __CR_PIE_X86_PKEY_H__
#define __CR_PIE_X86_PKEY_H__

#include <errno.h>
#include <stdint.h>
#include <sys/mman.h>

#include <compel/asm/fpu.h>
#include <compel/asm/sigframe.h>
#include <compel/plugins/std/syscall.h>

#include "criu-log.h"
#include "types.h"

#if defined(CONFIG_X86_64)

#define X86_CPUID_EXT_FEATURES	7
#define X86_CPUID_PKU_BIT	(1U << 3)
#define X86_CPUID_OSPKE_BIT	(1U << 4)
/* x86 PKU exposes 16 keys (0..15): 4 pkey bits in the PTE, 16 PKRU slots. */
#define X86_NR_PKEYS		16
#define X86_USER_PKEY_MASK	(((1U << X86_NR_PKEYS) - 1U) & ~1U)
/*
 * These are PKRU bit encodings, not policy values discovered from libc.
 * glibc exposes matching PKEY_DISABLE_* macros, but some libcs (for example
 * musl/Alpine) do not, so keep the x86 hardware values local here.
 */
#define X86_PKEY_DISABLE_ACCESS	0x1U
#define X86_PKEY_DISABLE_WRITE	0x2U
#define X86_PKEY_ACCESS_MASK	(X86_PKEY_DISABLE_ACCESS | X86_PKEY_DISABLE_WRITE)

struct x86_pkey_free_set {
	int pkeys[X86_NR_PKEYS];
	int nr_pkeys;
	u32 mask;
	u32 saved_pkru;
};

static inline void x86_cpuid_count(unsigned int op, unsigned int count, unsigned int *eax,
				   unsigned int *ebx, unsigned int *ecx, unsigned int *edx)
{
	*eax = op;
	*ecx = count;
	asm volatile("cpuid" : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx) : "0"(*eax), "2"(*ecx) : "memory");
}

static inline bool x86_pkeys_enabled(void)
{
	unsigned int eax, ebx, ecx, edx;

	x86_cpuid_count(0, 0, &eax, &ebx, &ecx, &edx);
	if (eax < X86_CPUID_EXT_FEATURES)
		return false;

	x86_cpuid_count(X86_CPUID_EXT_FEATURES, 0, &eax, &ebx, &ecx, &edx);
	return (ecx & X86_CPUID_PKU_BIT) && (ecx & X86_CPUID_OSPKE_BIT);
}

static inline u32 x86_rdpkru(void)
{
	u32 pkru;

	asm volatile(".byte 0x0f, 0x01, 0xee" : "=a"(pkru) : "c"(0) : "edx");
	return pkru;
}

static inline void x86_wrpkru(u32 pkru)
{
	asm volatile(".byte 0x0f, 0x01, 0xef" : : "a"(pkru), "c"(0), "d"(0));
}

static inline int x86_pkru_xsave_offset(u32 *off)
{
	unsigned int eax, ebx, ecx, edx;

	x86_cpuid_count(XSTATE_CPUID, XFEATURE_PKRU, &eax, &ebx, &ecx, &edx);
	if (ecx & 1) {
		pr_err("Cannot patch execute_only PKRU: compacted-only PKRU xstate layout is unsupported here\n");
		return -1;
	}

	*off = ebx;
	return 0;
}

static inline int x86_sigframe_get_pkru(struct rt_sigframe *sigframe, u32 **pkru)
{
	uint32_t off;

	if (!RT_SIGFRAME_HAS_FPU(sigframe)) {
		pr_err("Cannot patch execute_only PKRU in sigframe without FPU state\n");
		return -1;
	}

	if (x86_pkru_xsave_offset(&off))
		return -1;
	if (sigframe->is_native) {
		struct xsave_struct *x = &sigframe->native.fpu_state.fpu_state_64.xsave;

		if (!(x->xsave_hdr.xstate_bv & XFEATURE_MASK_PKRU)) {
			pr_err("Cannot patch execute_only PKRU: native sigframe has no PKRU xstate\n");
			return -1;
		}

		/*
		 * CPUID[0xD, XFEATURE_PKRU].EBX gives offset from XSAVE base,
		 * not from extended_state_area[].
		 */
		*pkru = (u32 *)((char *)x + off);
	} else {
		struct xsave_struct_ia32 *x = &sigframe->compat.fpu_state.fpu_state_ia32.xsave;

		if (!(x->xsave_hdr.xstate_bv & XFEATURE_MASK_PKRU)) {
			pr_err("Cannot patch execute_only PKRU: compat sigframe has no PKRU xstate\n");
			return -1;
		}

		*pkru = (u32 *)((char *)x + off);
	}

	return 0;
}

static inline void x86_pkru_move_execute_only_slot(u32 *pkru, int image_execute_only_pkey, int runtime_execute_only_pkey)
{
	u32 image_shift = 2U * image_execute_only_pkey;
	u32 runtime_shift = 2U * runtime_execute_only_pkey;

	*pkru &= ~(X86_PKEY_ACCESS_MASK << image_shift);
	*pkru &= ~(X86_PKEY_ACCESS_MASK << runtime_shift);
	*pkru |= X86_PKEY_DISABLE_ACCESS << runtime_shift;
}

static inline void init_free_pkey_set(struct x86_pkey_free_set *free_set)
{
	free_set->nr_pkeys = 0;
	free_set->mask = 0;
	free_set->saved_pkru = 0;
}

static inline int collect_free_pkey_set(struct x86_pkey_free_set *free_set)
{
	int ret;

	init_free_pkey_set(free_set);
	free_set->saved_pkru = x86_rdpkru();

	while (1) {
		ret = sys_pkey_alloc(0, 0);
		if (ret >= 0) {
			if (ret <= 0 || ret >= X86_NR_PKEYS)
				return -1;

			free_set->pkeys[free_set->nr_pkeys++] = ret;
			free_set->mask |= 1U << ret;
			continue;
		}

		if (ret == -ENOSPC)
			return 0;

		return ret;
	}
}

static inline u32 nonfree_pkey_mask(const struct x86_pkey_free_set *free_set)
{
	return X86_USER_PKEY_MASK & ~free_set->mask;
}

static inline int cleanup_free_pkey_set(struct x86_pkey_free_set *free_set, int ret, const char *what)
{
	while (free_set->nr_pkeys > 0) {
		int pkey = free_set->pkeys[--free_set->nr_pkeys];
		int free_ret = sys_pkey_free(pkey);

		if (free_ret < 0) {
			pr_err("%s: pkey_free(%d) failed: %d\n", what, pkey, free_ret);
			if (!ret)
				ret = free_ret;
		}
	}

	x86_wrpkru(free_set->saved_pkru);
	return ret;
}

/*
 * x86 can reserve one execute-only pkey in mm->context. It appears in the
 * mm-level allocated bitmap, but mm_pkey_is_allocated() excludes it from the
 * userspace pkey interfaces. On current x86/Linux, freeing ordinary user pkeys
 * still works here, while pkey_free(execute_only_pkey) returns -EINVAL.
 */
static inline int probe_execute_only_pkey(u32 allocated_pkey_mask, int *execute_only_pkey,
					  bool *has_execute_only_pkey)
{
	int pkey;

	*execute_only_pkey = 0;
	*has_execute_only_pkey = false;

	for (pkey = 1; pkey < X86_NR_PKEYS; pkey++) {
		int alloc_ret, ret;

		if (!(allocated_pkey_mask & (1U << pkey)))
			continue;

		ret = sys_pkey_free(pkey);
		if (ret == -EINVAL) {
			if (*has_execute_only_pkey) {
				pr_err("Multiple execute-only pkey candidates in mm bitmap %#x\n",
				       allocated_pkey_mask);
				return -1;
			}

			*execute_only_pkey = pkey;
			*has_execute_only_pkey = true;
			continue;
		}

		if (ret < 0) {
			pr_err("pkey_free(%d) probe failed: %d\n", pkey, ret);
			return ret;
		}

		alloc_ret = sys_pkey_alloc(0, 0);
		if (alloc_ret != pkey) {
			pr_err("Failed to restore user pkey %d during probe, got %d\n",
			       pkey, alloc_ret);
			if (alloc_ret >= 0)
				sys_pkey_free(alloc_ret);
			return -1;
		}
	}

	return 0;
}

/*
 * The kernel keeps this bitmap in mm->context.pkey_allocation_map, but it
 * does not expose the current value through /proc and there is no syscall to
 * query it directly. The pkey syscalls available to userspace are mutators
 * (pkey_alloc/pkey_free/pkey_mprotect), not "get current map" helpers.
 *
 * This also cannot be reconstructed from VMA pkeys alone. Userspace may have
 * allocated a pkey and not bound it to any VMA yet, so callers that persist
 * mm state must preserve allocated-but-unused keys as well.
 *
 * The probe allocates every free user pkey until the kernel reports ENOSPC,
 * then frees them all again. The keys we managed to allocate form the free
 * set; mm_pkey_allocation_map is the user-visible allocated set, i.e. all user
 * pkeys except key 0 minus that free set.
 *
 * pkey_alloc() updates current thread PKRU, so this helper saves and restores
 * PKRU around the probe to avoid leaking state changes to callers.
 *
 * x86_pkeys_enabled() check is intentionally outside this helper.
 */
static inline int probe_mm_pkey_allocation_map(int *execute_only_pkey, bool *has_execute_only_pkey,
					       u32 *mm_pkey_allocation_map, bool *has_mm_pkey_allocation_map)
{
	struct x86_pkey_free_set free_set;
	int ret;

	*execute_only_pkey = 0;
	*has_execute_only_pkey = false;
	*mm_pkey_allocation_map = 0;
	*has_mm_pkey_allocation_map = false;

	ret = collect_free_pkey_set(&free_set);
	if (ret) {
		pr_err("pkey_alloc probe failed: %d\n", ret);
		return cleanup_free_pkey_set(&free_set, ret, "probe_mm_pkey_allocation_map");
	}

	*mm_pkey_allocation_map = nonfree_pkey_mask(&free_set);
	*has_mm_pkey_allocation_map = true;
	ret = probe_execute_only_pkey(*mm_pkey_allocation_map, execute_only_pkey, has_execute_only_pkey);

	return cleanup_free_pkey_set(&free_set, ret, "probe_mm_pkey_allocation_map");
}

#endif /* CONFIG_X86_64 */

#endif /* __CR_PIE_X86_PKEY_H__ */
