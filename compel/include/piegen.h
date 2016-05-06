#ifndef __ELFTIL_H__
#define __ELFTIL_H__

#include <stdio.h>
#include <unistd.h>

#include <elf.h>
#include "compiler.h"

typedef struct {
	char		*input_filename;
	char		*output_filename;
	char		*uapi_dir;
	char		*stream_name;
	char		*prefix_name;
	char		*var_name;
	char		*nrgotpcrel_name;
	FILE		*fout;
	FILE		*ferr;
	FILE		*fdebug;
} piegen_opt_t;

extern piegen_opt_t opts;

#define pr_out(fmt, ...)							\
do {										\
	if (opts.fout)								\
		fprintf(opts.fout, fmt, ##__VA_ARGS__);				\
} while (0)

#define pr_debug(fmt, ...)							\
do {										\
	if (opts.fdebug)							\
		fprintf(opts.fdebug, "%s: "fmt,					\
			opts.stream_name, ##__VA_ARGS__);			\
} while (0)

#define pr_err(fmt, ...)							\
do {										\
	if (opts.ferr)								\
		fprintf(opts.ferr, "%s: Error (%s:%d): "fmt,			\
			opts.stream_name, __FILE__, __LINE__, ##__VA_ARGS__);	\
} while (0)

#define pr_perror(fmt, ...)							\
do {										\
	if (opts.ferr)								\
		fprintf(opts.ferr, "%s: Error (%s:%d): "fmt ": %m\n",		\
			opts.stream_name, __FILE__, __LINE__, ##__VA_ARGS__);	\
} while (0)

extern int handle_binary(void *mem, size_t size);

static const unsigned char __maybe_unused
elf_ident_32[EI_NIDENT] = {
	0x7f, 0x45, 0x4c, 0x46, 0x01, 0x01, 0x01, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const unsigned char __maybe_unused
elf_ident_64_le[EI_NIDENT] = {
	0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const unsigned char __maybe_unused
elf_ident_64_be[EI_NIDENT] = {
	0x7f, 0x45, 0x4c, 0x46, 0x02, 0x02, 0x01, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

#endif /* __ELFTIL_H__ */
