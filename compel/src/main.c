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

typedef struct {
	const char	*cflags;
	const char	*cflags_compat;
} flags_t;

static const flags_t flags = {
#if defined CONFIG_X86_64
	.cflags		= COMPEL_CFLAGS_PIE,
	.cflags_compat	= COMPEL_CFLAGS_NOPIC,
#elif defined CONFIG_AARCH64
	.cflags		= COMPEL_CFLAGS_PIE,
#elif defined(CONFIG_ARMV6) || defined(CONFIG_ARMV7)
	.cflags		= COMPEL_CFLAGS_PIE,
#elif defined CONFIG_PPC64
	.cflags		= COMPEL_CFLAGS_PIE,
#else
#error "CONFIG_<ARCH> not defined, or unsupported ARCH"
#endif
};

piegen_opt_t opts = {};
const char *uninst_root;

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
	FILE *f = stdout;

	if (pr_quelled(lvl))
		return;

	if ((lvl == LOG_ERROR) || (lvl == LOG_WARN))
		f = stderr;

	vfprintf(f, fmt, parms);
}

static int usage(int rc) {
	FILE *out = (rc == 0) ? stdout : stderr;

	fprintf(out,
"Usage:\n"
"  compel [--compat] includes | cflags | ldflags\n"
"  compel -f FILE -o FILE -p NAME [-l N] hgen\n"
"    -f, --file FILE		input (parasite object) file name\n"
"    -o, --output FILE		output (header) file name\n"
"    -p, --prefix NAME		prefix for var names\n"
"    -l, --log-level NUM		log level (default: %d)\n"
"  compel -h|--help\n"
"  compel -V|--version\n"
, DEFAULT_LOGLEVEL
);

	return rc;
}

static void print_includes(void)
{
	int i;
	/* list of standard include dirs (built into C preprocessor) */
	const char *standard_includes[] = {
		"/usr/include",
		"/usr/local/include",
	};

	/* I am not installed, called via a wrapper */
	if (uninst_root) {
		printf("-I %s/include/uapi\n", uninst_root);
		return;
	}

	/* I am installed
	 * Make sure to not print banalities */
	for (i = 0; i < ARRAY_SIZE(standard_includes); i++)
		if (strcmp(INCLUDEDIR, standard_includes[i]) == 0)
			return;

	/* Finally, print our non-standard include path */
	printf("%s\n", "-I " INCLUDEDIR);
}

static void print_cflags(bool compat)
{
	printf("%s\n", compat ? flags.cflags_compat : flags.cflags);
	print_includes();
}

int main(int argc, char *argv[])
{
	int log_level = DEFAULT_LOGLEVEL;
	bool compat = false;
	int opt, idx;
	char *action;

	static const char short_opts[] = "cf:o:p:hVl:";
	static struct option long_opts[] = {
		{ "compat",	no_argument,		0, 'c' },
		{ "file",	required_argument,	0, 'f' },
		{ "output",	required_argument,	0, 'o' },
		{ "prefix",	required_argument,	0, 'p' },
		{ "help",	no_argument,		0, 'h' },
		{ "version",	no_argument,		0, 'V' },
		{ "log-level",	required_argument,	0, 'l' },
		{ },
	};

	uninst_root = getenv("COMPEL_UNINSTALLED_ROOTDIR");

	while (1) {
		idx = -1;
		opt = getopt_long(argc, argv, short_opts, long_opts, &idx);
		if (opt == -1)
			break;
		switch (opt) {
		case 'c':
			compat = true;
			break;
		case 'f':
			opts.input_filename = optarg;
			break;
		case 'o':
			opts.output_filename = optarg;
			break;
		case 'p':
			opts.prefix = optarg;
			break;
		case 'l':
			log_level = atoi(optarg);
			break;
		case 'h':
			return usage(0);
		case 'V':
			printf("Version: %d.%d.%d\n",
			       COMPEL_SO_VERSION_MAJOR,
			       COMPEL_SO_VERSION_MINOR,
			       COMPEL_SO_VERSION_SUBLEVEL);
			exit(0);
			break;
		default: // '?'
			// error message already printed by getopt_long()
			return usage(1);
			break;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Error: action argument required\n");
		return usage(1);
	}
	action = argv[optind++];

	if (!strcmp(action, "includes")) {
		print_includes();
		return 0;
	}
	if (!strcmp(action, "cflags")) {
		print_cflags(compat);
		return 0;
	}

	if (!strcmp(action, "ldflags")) {
		printf("%s", COMPEL_LDFLAGS_DEFAULT);
		return 0;
	}

	if (!strcmp(action, "hgen")) {
		if (!opts.input_filename) {
			fprintf(stderr, "Error: option --file required\n");
			return usage(1);
		}
		if (!opts.output_filename) {
			fprintf(stderr, "Error: option --output required\n");
			return usage(1);
		}
		if (!opts.prefix) {
			fprintf(stderr, "Error: option --prefix required\n");
			return usage(1);
		}
		compel_log_init(&cli_log, log_level);
		return piegen();
	}

	fprintf(stderr, "Error: unknown action '%s'\n", action);
	return usage(1);
}
