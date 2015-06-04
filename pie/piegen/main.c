#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdint.h>
#include <getopt.h>
#include <string.h>

#include <fcntl.h>
#include <elf.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "compiler.h"
#include "config.h"
#include "piegen.h"

piegen_opt_t opts = {
	.input_filename		= "file.o",
	.stream_name		= "stream",
	.prefix_name		= "__",
	.var_name		= "elf_relocs",
	.nrgotpcrel_name	= "nr_gotpcrel",
};

static int handle_elf(const piegen_opt_t *opts, void *mem, size_t size)
{
#if defined(CONFIG_X86_32) || defined(CONFIG_X86_64)
	unsigned char elf_ident_x86_32[EI_NIDENT] = {
		0x7f, 0x45, 0x4c, 0x46, 0x01, 0x01, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};

	unsigned char elf_ident_x86_64[EI_NIDENT] = {
		0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};

	if (memcmp(mem, elf_ident_x86_32, sizeof(elf_ident_x86_32)) == 0)
		return handle_elf_x86_32(opts, mem, size);
	else if (memcmp(mem, elf_ident_x86_64, sizeof(elf_ident_x86_64)) == 0)
		return handle_elf_x86_64(opts, mem, size);
#endif

	pr_err("Unsupported Elf format detected\n");
	return -1;
}

/*
 * That;s the tool to generate patches object files.
 */
int main(int argc, char *argv[])
{
	struct stat st;
	int opt, idx;
	void *mem;
	int fd;

	static const char short_opts[] = "f:s:p:v:h";
	static struct option long_opts[] = {
		{ "file",	required_argument,	0, 'f' },
		{ "stream",	required_argument,	0, 's' },
		{ "sym-prefix",	required_argument,	0, 'p' },
		{ "variable",	required_argument,	0, 'v' },
		{ "help",	required_argument,	0, 'h' },
		{ },
	};

	if (argc < 3)
		goto usage;

	while (1) {
		idx = -1;
		opt = getopt_long(argc, argv, short_opts, long_opts, &idx);
		if (opt == -1)
			break;
		switch (opt) {
		case 'f':
			opts.input_filename = optarg;
			break;
		case 's':
			opts.stream_name = optarg;
			break;
		case 'p':
			opts.prefix_name = optarg;
			break;
		case 'v':
			opts.var_name = optarg;
			break;
		case 'h':
		default:
			goto usage;
		}
	}

	fd = open(opts.input_filename, O_RDONLY);
	if (fd < 0) {
		pr_perror("Can't open file %s", opts.input_filename);
		goto err;
	}

	if (fstat(fd, &st)) {
		pr_perror("Can't stat file %s", opts.input_filename);
		goto err;
	}

	mem = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FILE, fd, 0);
	if (mem == MAP_FAILED) {
		pr_perror("Can't mmap file %s", opts.input_filename);
		goto err;
	}

	if (handle_elf(&opts, mem, st.st_size))
		goto err;
	return 1;
usage:
	printf("Usage: %s -f filename\n", argv[0]);
err:
	return 0;
}
