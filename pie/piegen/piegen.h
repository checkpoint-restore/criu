#ifndef __ELFTIL_H__
#define __ELFTIL_H__

#include <stdio.h>
#include <unistd.h>

typedef struct {
	char		*input_filename;
	char		*output_filename;
	char		*stream_name;
	char		*prefix_name;
	char		*var_name;
	char		*nrgotpcrel_name;
} piegen_opt_t;

extern piegen_opt_t opts;
extern FILE *fout;

#if defined(CONFIG_X86_32) || defined(CONFIG_X86_64)
extern int handle_elf_x86_32(const piegen_opt_t *opts, void *mem, size_t size);
extern int handle_elf_x86_64(const piegen_opt_t *opts, void *mem, size_t size);
#endif

#if defined(CONFIG_PPC64)
extern int handle_elf_ppc64(const piegen_opt_t *opts, void *mem, size_t size);
#endif

#define pr_out(fmt, ...)	fprintf(fout, fmt, ##__VA_ARGS__)

#define pr_debug(fmt, ...)	fprintf(stdout, fmt, ##__VA_ARGS__)

#define pr_err(fmt, ...)	fprintf(stderr, "Error (%s:%d): "fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#define pr_perror(fmt, ...)	fprintf(stderr, "Error (%s:%d): "fmt "%m\n", __FILE__, __LINE__, ##__VA_ARGS__)

#endif /* __ELFTIL_H__ */
