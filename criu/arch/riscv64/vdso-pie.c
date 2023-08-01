#include <unistd.h>

#include "asm/types.h"

#include <compel/asm/instruction_formats.h>
#include <compel/plugins/std/string.h>
#include <compel/plugins/std/syscall.h>
#include <compel/plugins/std/syscall-codes.h>
#include "atomic.h"
#include "parasite-vdso.h"
#include "log.h"
#include "common/bug.h"

#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif
#define LOG_PREFIX "vdso: "

/* These symbols are defined in vdso-lookup.S */
extern char *riscv_vdso_lookup, *riscv_vdso_lookup_end;

/*
 *  li t0, INDEX
 *  jal x0, riscv_vdso_lookup
 */
#define TRAMP_CALL_SIZE (2 * sizeof(uint32_t))

static inline void invalidate_caches(void)
{
	// We're supposed to use the VDSO as the officially sanctioned ABI. But oh well.
	int ret;
	__smp_mb();
	asm volatile("li a0, 0\n"
		     "li a1, 0\n"
		     "li a2, 1\n"   /* SYS_RISCV_FLUSH_ICACHE_ALL */
		     "li a7, 259\n" /* __NR_arch_specific_syscall */
		     "ecall\n"
		     : "=r"(ret)
		     :
		     : "a7");
}

static inline size_t vdso_trampoline_size(void)
{
	return (size_t)&riscv_vdso_lookup_end - (size_t)&riscv_vdso_lookup;
}

static uint64_t put_trampoline(uint64_t at, struct vdso_symtable *sym)
{
	int i, j;
	uint64_t total_size, trampoline_size;
	uint64_t trampoline = 0;

	/* First of all we have to find a place where to put the trampoline
	 * code.
	 */
	trampoline_size = vdso_trampoline_size();
	total_size = trampoline_size + VDSO_SYMBOL_MAX * sizeof(uint64_t);

	for (i = 0; i < ARRAY_SIZE(sym->symbols); i++) {
		if (vdso_symbol_empty(&sym->symbols[i]))
			continue;

		pr_debug("Checking '%s' at %lx\n", sym->symbols[i].name, sym->symbols[i].offset);

		/* find the nearest following symbol we are interested in */
		for (j = 0; j < ARRAY_SIZE(sym->symbols); j++) {
			if (i == j || vdso_symbol_empty(&sym->symbols[j]))
				continue;

			if (sym->symbols[j].offset <= sym->symbols[i].offset)
				/* this symbol is above the current one */
				continue;

			if ((sym->symbols[i].offset + TRAMP_CALL_SIZE) > sym->symbols[j].offset) {
				/* we have a major issue here since we cannot
				 * even put the trampoline call for this symbol
				 */
				pr_err("Can't handle small vDSO symbol %s\n", sym->symbols[i].name);
				return 0;
			}

			if (trampoline)
				/* no need to put it twice */
				continue;

			if ((sym->symbols[j].offset - (sym->symbols[i].offset + TRAMP_CALL_SIZE)) <= total_size)
				/* not enough place */
				continue;

			/* We can put the trampoline there */
			trampoline = at + sym->symbols[i].offset;
			trampoline += TRAMP_CALL_SIZE;

			pr_debug("Putting vDSO trampoline in %s at %lx\n", sym->symbols[i].name, trampoline);
			memcpy((void *)trampoline, &riscv_vdso_lookup, trampoline_size);
			invalidate_caches();
			return trampoline;
		}
	}

	return 0;
}

static inline void put_trampoline_call(uint64_t from, uint64_t to, uint64_t trampoline, unsigned int idx)
{
	size_t trampoline_size = vdso_trampoline_size();
	uint64_t *lookup_table = NULL;
	/*
	 *  li t0, INDEX
	 *  addi t0, x0 INDEX
	 *  jal x0, riscv_vdso_lookup
	 */
	uint32_t trampoline_call[2] = {
		0x00000293,
		0x0000006f,
	};
	const size_t insts_len = ARRAY_SIZE(trampoline_call);
	uint32_t *call_addr = (uint32_t *)from;
	// Offset from the jal instruction to the lookup trampoline.
	ssize_t trampoline_offset = trampoline - (from + sizeof(uint32_t));

	trampoline_call[0] = trampoline_call[0] | (idx << 24);
	trampoline_call[1] = trampoline_call[1] | riscv_j_imm(trampoline_offset);

	for (unsigned int i = 0; i < insts_len; i++) {
		call_addr[i] = trampoline_call[i];
	}

	// Set the lookup table pointer for this vdso symbol.
	lookup_table = (uint64_t *)(trampoline + trampoline_size);
	lookup_table[idx] = to;
}

int vdso_redirect_calls(uint64_t base_to, uint64_t base_from, struct vdso_symtable *to, struct vdso_symtable *from,
			bool __always_unused compat_vdso)
{
	unsigned int i, valid_idx = 0;

	uint64_t trampoline = (uint64_t)put_trampoline(base_from, from);
	if (!trampoline)
		return 1;

	for (i = 0; i < ARRAY_SIZE(to->symbols); i++) {
		if (vdso_symbol_empty(&from->symbols[i]))
			continue;

		pr_debug("br: %lx/%lx -> %lx/%lx (index %d) '%s'\n", base_from, from->symbols[i].offset, base_to,
			 to->symbols[i].offset, i, from->symbols[i].name);

		put_trampoline_call(base_from + from->symbols[i].offset, base_to + to->symbols[i].offset, trampoline,
				    valid_idx);
		valid_idx++;
	}

	invalidate_caches();

	return 0;
}