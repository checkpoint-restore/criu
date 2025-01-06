#ifndef COMPEL_PIEGEN_H__
#define COMPEL_PIEGEN_H__

#include <stdio.h>
#include <unistd.h>

#include <elf.h>

#include "common/compiler.h"

typedef struct {
	char *input_filename;
	char *output_filename;
	char *prefix;
	FILE *fout;
} piegen_opt_t;

extern piegen_opt_t opts;

#define pr_out(fmt, ...)                                        \
	do {                                                    \
		if (opts.fout)                                  \
			fprintf(opts.fout, fmt, ##__VA_ARGS__); \
	} while (0)

extern int handle_binary(void *mem, size_t size);

#endif /* COMPEL_PIEGEN_H__ */
