#ifndef __PIEGEN_TYPES_H__
#define __PIEGEN_TYPES_H__

#define PIEGEN_TYPE_INT		(1u << 0)
#define PIEGEN_TYPE_LONG	(1u << 1)
#define PIEGEN_TYPE_GOTPCREL	(1u << 2)

typedef struct {
	unsigned int	offset;
	unsigned int	type;
	long		addend;
	long		value;
} elf_reloc_t;

#endif /* __PIEGEN_TYPES_H__ */
