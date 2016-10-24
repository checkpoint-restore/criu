#ifndef __PIE_RELOCS_H__
#define __PIE_RELOCS_H__

#include "piegen/uapi/types.h"

#include "common/compiler.h"
#include "config.h"

#ifdef CONFIG_PIEGEN

extern __maybe_unused void elf_relocs_apply(void *mem, void *vbase, size_t size,
					    elf_reloc_t *elf_relocs, size_t nr_relocs);
#define pie_size(__blob_name)	(round_up(sizeof(__blob_name) + nr_gotpcrel * sizeof(long), page_size()))
#define ELF_RELOCS_APPLY_PARASITE(__mem, __vbase)			\
	elf_relocs_apply(__mem, __vbase, sizeof(parasite_blob),		\
			 parasite_relocs, ARRAY_SIZE(parasite_relocs))
#define ELF_RELOCS_APPLY_RESTORER(__mem, __vbase)			\
	elf_relocs_apply(__mem, __vbase, sizeof(restorer_blob),		\
			 restorer_relocs, ARRAY_SIZE(restorer_relocs))

#else

#define pie_size(__blob_name)	(round_up(sizeof(__blob_name), page_size()))
#define ELF_RELOCS_APPLY_PARASITE(__mem, __vbase)
#define ELF_RELOCS_APPLY_RESTORER(__mem, __vbase)

#endif

#endif /* __PIE_RELOCS_H__ */
