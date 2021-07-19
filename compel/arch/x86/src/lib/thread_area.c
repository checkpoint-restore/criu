#include <errno.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include "log.h"
#include "asm/infect-types.h"
#include "infect.h"
#include "infect-priv.h"

#ifndef PTRACE_GET_THREAD_AREA
#define PTRACE_GET_THREAD_AREA 25
#endif

/*
 * For 64-bit applications, TLS (fs_base for Glibc) is in MSR,
 * which are dumped with the help of ptrace() and restored with
 * arch_prctl(ARCH_SET_FS/ARCH_SET_GS).
 *
 * But SET_FS_BASE will update GDT if base pointer fits in 4 bytes.
 * Otherwise it will set only MSR, which allows for mixed 64/32-bit
 * code to use: 2 MSRs as TLS base _and_ 3 GDT entries.
 * Having in sum 5 TLS pointers, 3 of which are four bytes and
 * other two eight bytes:
 * struct thread_struct {
 *	struct desc_struct	tls_array[3];
 *	...
 * #ifdef CONFIG_X86_64
 *	unsigned long		fsbase;
 *	unsigned long		gsbase;
 * #endif
 *	...
 * };
 *
 * Most x86_64 applications don't use GDT, but mixed code (i.e. Wine)
 * can use it. Be pessimistic and dump it for 64-bit applications too.
 */
int __compel_arch_fetch_thread_area(int tid, struct thread_ctx *th)
{
	bool native_mode = user_regs_native(&th->regs);
	tls_t *ptls = &th->tls;
	int err, i;

	/* Initialise as not present by default */
	for (i = 0; i < GDT_ENTRY_TLS_NUM; i++) {
		user_desc_t *d = &ptls->desc[i];

		memset(d, 0, sizeof(user_desc_t));
		d->seg_not_present = 1;
		d->entry_number = GDT_ENTRY_TLS_MIN + i;
	}

	for (i = 0; i < GDT_ENTRY_TLS_NUM; i++) {
		user_desc_t *d = &ptls->desc[i];

		err = ptrace(PTRACE_GET_THREAD_AREA, tid, GDT_ENTRY_TLS_MIN + i, d);
		/*
		 * Ignoring absent syscall on !CONFIG_IA32_EMULATION
		 * where such mixed code can't run.
		 * XXX: Add compile CONFIG_X86_IGNORE_64BIT_TLS
		 * (for x86_64 systems with CONFIG_IA32_EMULATION)
		 */
		if (err == -EIO && native_mode)
			return 0;
		if (err) {
			pr_perror("get_thread_area failed for %d", tid);
			return err;
		}
	}

	return 0;
}

int compel_arch_fetch_thread_area(struct parasite_thread_ctl *tctl)
{
	return __compel_arch_fetch_thread_area(tctl->tid, &tctl->th);
}

void compel_arch_get_tls_task(struct parasite_ctl *ctl, tls_t *out)
{
	memcpy(out, &ctl->orig.tls, sizeof(tls_t));
}

void compel_arch_get_tls_thread(struct parasite_thread_ctl *tctl, tls_t *out)
{
	memcpy(out, &tctl->th.tls, sizeof(tls_t));
}
