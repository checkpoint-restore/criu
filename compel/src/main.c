#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdint.h>
#include <getopt.h>
#include <string.h>
#include <ctype.h>

#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "version.h"
#include "piegen.h"
#include "log.h"

#define CFLAGS_DEFAULT_SET     \
	"-Wstrict-prototypes " \
	"-ffreestanding "      \
	"-fno-stack-protector -nostdlib -fomit-frame-pointer "

#define COMPEL_CFLAGS_PIE   CFLAGS_DEFAULT_SET "-fpie"
#define COMPEL_CFLAGS_NOPIC CFLAGS_DEFAULT_SET "-fno-pic"

#ifdef NO_RELOCS
#define COMPEL_LDFLAGS_COMMON "-z noexecstack -T "
#else
#define COMPEL_LDFLAGS_COMMON "-r -z noexecstack -T "
#endif

typedef struct {
	const char *arch; // dir name under arch/
	const char *cflags;
	const char *cflags_compat;
} flags_t;

static const flags_t flags = {
#if defined CONFIG_X86_64
	.arch = "x86",
	.cflags = COMPEL_CFLAGS_PIE,
	.cflags_compat = COMPEL_CFLAGS_NOPIC,
#elif defined CONFIG_AARCH64
	.arch = "aarch64",
	.cflags = COMPEL_CFLAGS_PIE,
#elif defined(CONFIG_ARMV6) || defined(CONFIG_ARMV7)
	.arch = "arm",
	.cflags = COMPEL_CFLAGS_PIE,
#elif defined CONFIG_PPC64
	.arch = "ppc64",
	.cflags = COMPEL_CFLAGS_PIE,
#elif defined CONFIG_S390
	.arch = "s390",
	.cflags = COMPEL_CFLAGS_PIE,
#elif defined CONFIG_MIPS
	.arch = "mips",
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
		unlink(opts.output_filename);
		goto err;
	}

	ret = 0;

err:
	close(fd);
	if (opts.fout)
		fclose(opts.fout);
	if (!ret)
		pr_info("%s generated successfully.\n", opts.output_filename);
	return ret;
}

static void cli_log(unsigned int lvl, const char *fmt, va_list parms)
{
	FILE *f = stdout;

	if (pr_quelled(lvl))
		return;

	if ((lvl == COMPEL_LOG_ERROR) || (lvl == COMPEL_LOG_WARN))
		f = stderr;

	vfprintf(f, fmt, parms);
}

static int usage(int rc)
{
	FILE *out = (rc == 0) ? stdout : stderr;

	fprintf(out,
		"Usage:\n"
		"  compel [--compat] includes | cflags | ldflags\n"
		"  compel plugins [PLUGIN_NAME ...]\n"
		"  compel [--compat] [--static] libs\n"
		"  compel -f FILE -o FILE [-p NAME] [-l N] hgen\n"
		"    -f, --file FILE		input (parasite object) file name\n"
		"    -o, --output FILE		output (header) file name\n"
		"    -p, --prefix NAME		prefix for var names\n"
		"    -l, --log-level NUM		log level (default: %d)\n"
		"  compel -h|--help\n"
		"  compel -V|--version\n",
		COMPEL_DEFAULT_LOGLEVEL);

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

static void print_ldflags(bool compat)
{
	const char *compat_str = (compat) ? "-compat" : "";

	printf("%s", COMPEL_LDFLAGS_COMMON);

	if (uninst_root) {
		printf("%s/arch/%s/scripts/compel-pack%s.lds.S\n", uninst_root, flags.arch, compat_str);
	} else {
		printf("%s/compel/scripts/compel-pack%s.lds.S\n", LIBEXECDIR, compat_str);
	}
}

static void print_plugin(const char *name)
{
	const char suffix[] = ".lib.a";

	if (uninst_root)
		printf("%s/plugins/%s%s\n", uninst_root, name, suffix);
	else
		printf("%s/compel/%s%s\n", LIBEXECDIR, name, suffix);
}

static void print_plugins(char *const list[])
{
	char *builtin_list[] = { "std", NULL };
	char **p = builtin_list;

	while (*p != NULL)
		print_plugin(*p++);

	while (*list != NULL)
		print_plugin(*list++);
}

static int print_libs(bool is_static)
{
	if (uninst_root) {
		if (!is_static) {
			fprintf(stderr, "Compel is not installed, can "
					"only link with static libraries "
					"(use --static)\n");
			return 1;
		}
		printf("%s/%s\n", uninst_root, STATIC_LIB);
	} else {
		printf("%s/%s\n", LIBDIR, (is_static) ? STATIC_LIB : DYN_LIB);
	}

	return 0;
}

/* Extracts the file name (removing directory path and suffix,
 * and checks the result for being a valid C identifier
 * (replacing - with _ along the way).
 *
 * If everything went fine, return the resulting string,
 * otherwise NULL.
 *
 * Example: get_prefix("./some/path/to/file.c") ==> "file"
 */
static char *gen_prefix(const char *path)
{
	const char *p1 = NULL, *p2 = NULL;
	size_t len;
	int i;
	char *p, *ret;

	len = strlen(path);
	if (len == 0)
		return NULL;

	// Find the last slash (p1)
	// and  the first dot after it (p2)
	for (i = len - 1; i >= 0; i--) {
		if (!p1 && path[i] == '.') {
			p2 = path + i - 1;
		} else if (!p1 && path[i] == '/') {
			p1 = path + i + 1;
			break;
		}
	}

	if (!p1) // no slash in path
		p1 = path;
	if (!p2) // no dot (after slash)
		p2 = path + len;

	len = p2 - p1 + 1;
	if (len < 1)
		return NULL;

	ret = strndup(p1, len);

	// Now, check if we got a valid C identifier. We don't need to care
	// about C reserved keywords, as this is only used as a prefix.
	for (p = ret; *p != '\0'; p++) {
		if (isalpha(*p))
			continue;
		// digit is fine, except the first character
		if (isdigit(*p) && p > ret)
			continue;
		// only allowed special character is _
		if (*p == '_')
			continue;
		// as a courtesy, replace - with _
		if (*p == '-') {
			*p = '_';
			continue;
		}
		// invalid character!
		free(ret);
		return NULL;
	}

	return ret;
}

int main(int argc, char *argv[])
{
	int log_level = COMPEL_DEFAULT_LOGLEVEL;
	bool compat = false;
	bool is_static = false;
	int opt, idx;
	char *action;

	static const char short_opts[] = "csf:o:p:hVl:";
	static struct option long_opts[] = {
		{ "compat", no_argument, 0, 'c' },
		{ "static", no_argument, 0, 's' },
		{ "file", required_argument, 0, 'f' },
		{ "output", required_argument, 0, 'o' },
		{ "prefix", required_argument, 0, 'p' },
		{ "help", no_argument, 0, 'h' },
		{ "version", no_argument, 0, 'V' },
		{ "log-level", required_argument, 0, 'l' },
		{},
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
		case 's':
			is_static = true;
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
			printf("Version: %d.%d.%d\n", COMPEL_SO_VERSION_MAJOR, COMPEL_SO_VERSION_MINOR,
			       COMPEL_SO_VERSION_SUBLEVEL);
			exit(0);
		default: // '?'
			// error message already printed by getopt_long()
			return usage(1);
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
		print_ldflags(compat);
		return 0;
	}

	if (!strcmp(action, "plugins")) {
		print_plugins(argv + optind);
		return 0;
	}

	if (!strcmp(action, "libs")) {
		return print_libs(is_static);
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
			// prefix not provided, let's autogenerate
			opts.prefix = gen_prefix(opts.input_filename);
			if (!opts.prefix)
				opts.prefix = gen_prefix(opts.output_filename);
			if (!opts.prefix) {
				fprintf(stderr, "Error: can't autogenerate "
						"prefix (supply --prefix)");
				return 2;
			}
		}
		compel_log_init(&cli_log, log_level);
		return piegen();
	}

	fprintf(stderr, "Error: unknown action '%s'\n", action);
	return usage(1);
}
