#ifndef __COMPEL_UAPI_HANDLE_ELF__
#define __COMPEL_UAPI_HANDLE_ELF__

#define COMPEL_TYPE_INT		(1u << 0)
#define COMPEL_TYPE_LONG	(1u << 1)
#define COMPEL_TYPE_GOTPCREL	(1u << 2)
#ifdef CONFIG_MIPS
#define COMPEL_TYPE_MIPS_26	  (1u << 3)
#define COMPEL_TYPE_MIPS_HI16	  (1u << 4)
#define COMPEL_TYPE_MIPS_LO16	  (1u << 5)
#define COMPEL_TYPE_MIPS_HIGHER	  (1u << 6)
#define COMPEL_TYPE_MIPS_HIGHEST  (1u << 7)
#define COMPEL_TYPE_MIPS_64	  (1u << 8)
#endif
typedef struct {
	unsigned int	offset;
	unsigned int	type;
	long		addend;
	long		value;
} compel_reloc_t;

#endif
