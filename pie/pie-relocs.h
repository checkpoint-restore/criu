#ifndef __PIE_RELOCS_H__
#define __PIE_RELOCS_H__

#include "piegen/uapi/types.h"

#include "compiler.h"
#include "config.h"

#if defined(CONFIG_X86_64) || defined(CONFIG_X86_32)
extern __maybe_unused void elf_relocs_apply(void *mem, void *vbase, size_t size, elf_reloc_t *elf_relocs, size_t nr_relocs);
#else
static always_inline void elf_relocs_apply(void *mem, void *vbase, size_t size, elf_reloc_t *elf_relocs, size_t nr_relocs) { }
#endif

#endif /* __PIE_RELOCS_H__ */
