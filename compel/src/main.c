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

#include "common/compiler.h"
#include "piegen.h"

static const char compel_cflags_pie[] = "-fpie -Wa,--noexecstack -fno-stack-protector";
static const char compel_cflags_nopic[] = "-fno-pic -Wa,--noexecstack -fno-stack-protector";
static const char compel_ldflags[] = "-r";

piegen_opt_t opts = {
	.input_filename		= NULL,
	.uapi_dir		= "piegen/uapi",
	.stream_name		= "stream",
	.prefix_name		= "__",
	.var_name		= "elf_relocs",
	.nrgotpcrel_name	= "nr_gotpcrel",
};

FILE *fout;

static int handle_elf(void *mem, size_t size)
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
		return handle_elf_x86_32(mem, size);
	else if (memcmp(mem, elf_ident_x86_64, sizeof(elf_ident_x86_64)) == 0)
		return handle_elf_x86_64(mem, size);
#endif

#if defined(CONFIG_PPC64)
	const unsigned char elf_ident[EI_NIDENT] = {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
                0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
#else
		0x7f, 0x45, 0x4c, 0x46, 0x02, 0x02, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
#endif
	};

	if (memcmp(mem, elf_ident, sizeof(elf_ident)) == 0)
		return handle_elf_ppc64(mem, size);
#endif /* CONFIG_PPC64 */

	pr_err("Unsupported Elf format detected\n");
	return -1;
}

static int piegen(void)
{
	struct stat st;
	void *mem;
	int fd;

	fd = open(opts.input_filename, O_RDONLY);
	if (fd < 0) {
		pr_perror("Can't open file %s", opts.input_filename);
		goto err;
	}

	if (fstat(fd, &st)) {
		pr_perror("Can't stat file %s", opts.input_filename);
		goto err;
	}

	fout = fopen(opts.output_filename, "w");
	if (fout == NULL) {
		pr_perror("Can't open %s", opts.output_filename);
		goto err;
	}

	mem = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FILE, fd, 0);
	if (mem == MAP_FAILED) {
		pr_perror("Can't mmap file %s", opts.input_filename);
		goto err;
	}

	if (handle_elf(mem, st.st_size)) {
		fclose(fout);
		unlink(opts.output_filename);
		goto err;
	}

err:
	fclose(fout);
	printf("%s generated successfully.\n", opts.output_filename);
	return 0;
}

int main(int argc, char *argv[])
{
	const char *current_cflags = NULL;
	int opt, idx, i;
	char *action;

	typedef struct {
		const char	*arch;
		const char	*cflags;
	} compel_cflags_t;

	static const compel_cflags_t compel_cflags[] = {
		{
			.arch	= "x86",
			.cflags	= compel_cflags_pie,
		}, {
			.arch	= "ia32",
			.cflags	= compel_cflags_nopic,
		}, {
			.arch	= "aarch64",
			.cflags	= compel_cflags_pie,
		}, {
			.arch	= "arm",
			.cflags	= compel_cflags_pie,
		}, {
			.arch	= "ppc64",
			.cflags	= compel_cflags_pie,
		},
	};

	static const char short_opts[] = "a:f:o:s:p:v:r:u:h";
	static struct option long_opts[] = {
		{ "arch",	required_argument,	0, 'a' },
		{ "file",	required_argument,	0, 'f' },
		{ "output",	required_argument,	0, 'o' },
		{ "stream",	required_argument,	0, 's' },
		{ "uapi-dir",	required_argument,	0, 'u' },
		{ "sym-prefix",	required_argument,	0, 'p' },
		{ "variable",	required_argument,	0, 'v' },
		{ "pcrelocs",	required_argument,	0, 'r' },
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
		case 'a':
			for (i = 0; i < ARRAY_SIZE(compel_cflags); i++) {
				if (!strcmp(optarg, compel_cflags[i].arch)) {
					current_cflags = compel_cflags[i].cflags;
					break;
				}
			}

			if (!current_cflags)
				goto usage;
			break;
		case 'f':
			opts.input_filename = optarg;
			break;
		case 'o':
			opts.output_filename = optarg;
			break;
		case 'u':
			opts.uapi_dir = optarg;
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
		case 'r':
			opts.nrgotpcrel_name = optarg;
			break;
		case 'h':
			goto usage;
		default:
			break;
		}
	}

	if (optind >= argc)
		goto usage;

	action = argv[optind++];

	if (!strcmp(action, "cflags")) {
		if (!current_cflags)
			goto usage;
		printf("%s", current_cflags);
		return 0;
	}

	if (!strcmp(action, "ldflags")) {
		printf("%s", compel_ldflags);
		return 0;
	}

	if (!strcmp(action, "piegen")) {
		if (!opts.input_filename)
			goto usage;
		return piegen();
	}

usage:
	printf("Usage:\n");
	printf("  compel --arch=(x86|ia32|aarch64|arm|ppc64) cflags\n");
	printf("  compel --arch=(x86|ia32|aarch64|arm|ppc64) ldflags\n");
	printf("  compel -f filename piegen\n");
	return 1;
}
