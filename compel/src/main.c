#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdint.h>
#include <getopt.h>
#include <string.h>

#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "uapi/compel/compel.h"

#include "version.h"
#include "piegen.h"
#include "log.h"

#define CFLAGS_DEFAULT_SET					\
	"-Wstrict-prototypes "					\
	"-fno-stack-protector -nostdlib -fomit-frame-pointer "

#define COMPEL_CFLAGS_PIE	CFLAGS_DEFAULT_SET "-fpie"
#define COMPEL_CFLAGS_NOPIC	CFLAGS_DEFAULT_SET "-fno-pic"

#define COMPEL_LDFLAGS_DEFAULT "-r -z noexecstack"

piegen_opt_t opts = {
	.input_filename		= NULL,
	.uapi_dir		= "piegen/uapi",
	.stream_name		= "stream",
	.prefix_name		= "__",
	.var_name		= "elf_relocs",
	.nrgotpcrel_name	= "nr_gotpcrel",
	.fout			= NULL,
};

static int piegen(void)
{
	struct stat st;
	void *mem;
	int fd, ret = -1;

	fd = open(opts.input_filename, O_RDONLY);
	if (fd < 0) {
		pr_perror("Can't open file %s", opts.input_filename);
		return -1;
	}

	if (fstat(fd, &st)) {
		pr_perror("Can't stat file %s", opts.input_filename);
		goto err;
	}

	opts.fout = fopen(opts.output_filename, "w");
	if (opts.fout == NULL) {
		pr_perror("Can't open %s", opts.output_filename);
		goto err;
	}

	mem = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FILE, fd, 0);
	if (mem == MAP_FAILED) {
		pr_perror("Can't mmap file %s", opts.input_filename);
		goto err;
	}

	if (handle_binary(mem, st.st_size)) {
		close(fd), fd = -1;
		unlink(opts.output_filename);
		goto err;
	}

	ret = 0;

err:
	if (fd >= 0)
		close(fd);
	if (opts.fout)
		fclose(opts.fout);
	if (!ret)
		printf("%s generated successfully.\n", opts.output_filename);
	return ret;
}

static void cli_log(unsigned int lvl, const char *fmt, va_list parms)
{
	if (!pr_quelled(lvl))
		vprintf(fmt, parms);
}

int main(int argc, char *argv[])
{
	const char *current_cflags = NULL;
	int log_level = DEFAULT_LOGLEVEL;
	int opt, idx, i;
	char *action;

	typedef struct {
		const char	*arch;
		const char	*cflags;
	} compel_cflags_t;

	static const compel_cflags_t compel_cflags[] = {
		{
			.arch	= "x86",
			.cflags	= COMPEL_CFLAGS_PIE,
		}, {
			.arch	= "ia32",
			.cflags	= COMPEL_CFLAGS_NOPIC,
		}, {
			.arch	= "aarch64",
			.cflags	= COMPEL_CFLAGS_PIE,
		}, {
			.arch	= "arm",
			.cflags	= COMPEL_CFLAGS_PIE,
		}, {
			.arch	= "ppc64",
			.cflags	= COMPEL_CFLAGS_PIE,
		},
	};

	static const char short_opts[] = "a:f:o:s:p:v:r:u:hVl:";
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
		{ "version",	no_argument,		0, 'V' },
		{ "log-level",	required_argument,	0, 'l' },
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
		case 'l':
			break;
			log_level = atoi(optarg);
		case 'h':
			goto usage;
		case 'V':
			printf("Version: %d.%d.%d\n",
			       COMPEL_SO_VERSION_MAJOR,
			       COMPEL_SO_VERSION_MINOR,
			       COMPEL_SO_VERSION_SUBLEVEL);
			exit(0);
			break;
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
		printf("%s", COMPEL_LDFLAGS_DEFAULT);
		return 0;
	}

	if (!strcmp(action, "hgen")) {
		if (!opts.input_filename)
			goto usage;
		compel_log_init(&cli_log, log_level);
		return piegen();
	}

usage:
	printf("Usage:\n");
	printf("  compel --arch=(x86|ia32|aarch64|arm|ppc64) cflags\n");
	printf("  compel --arch=(x86|ia32|aarch64|arm|ppc64) ldflags\n");
	printf("  compel -f filename hgen\n");
	return 1;
}
