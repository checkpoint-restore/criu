#include <ctype.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "log.h"
#include "common/list.h"

#include "action-scripts.h"
#include "cgroup.h"
#include "cgroup-props.h"
#include "common/bug.h"
#include "cpu.h"
#include "crtools.h"
#include "cr_options.h"
#include "filesystems.h"
#include "file-lock.h"
#include "irmap.h"
#include "mount.h"
#include "namespaces.h"
#include "net.h"
#include "sk-inet.h"
#include "sockets.h"
#include "tty.h"
#include "version.h"

#include "common/xmalloc.h"

struct cr_options opts;
char *rpc_cfg_file;

static int count_elements(char **to_count)
{
	int count = 0;
	if (to_count != NULL)
		while (to_count[count] != NULL)
			count++;
	return count;
}

/* Parse one statement in configuration file */
int parse_statement(int i, char *line, char **configuration)
{
	int offset = 0, len = 0;
	bool was_newline = true;
	char *tmp_string, *quoted, *quotedptr;

	while (1) {
		/* Ignore white-space */
		while ((isspace(*(line + offset)) && (*(line + offset) != '\n'))) offset++;

		/* Read a single word. A word is everything
		 * that doesn't contain white-space characters. */
		if (sscanf(line + offset, "%m[^ \t\n]s", &configuration[i]) != 1) {
			configuration[i] = NULL;
			break;
		}

		/* Ignore comments - everything between '#' and '\n' */
		if (configuration[i][0] == '#') {
			configuration[i] = NULL;
			break;
		}

		if ((configuration[i][0] == '\"') && (strchr(line + offset + 1, '"'))) {
			/* Handle empty strings which strtok ignores */
			if (!strcmp(configuration[i], "\"\"")) {
				configuration[i] = "";
				offset += strlen("\"\"");
			} else if ((configuration[i] = strtok_r(line + offset, "\"", &quotedptr))) {
				/* Handle escaping of quotes in quoted string */
				while (configuration[i][strlen(configuration[i]) - 1] == '\\') {
					offset++;
					len = strlen(configuration[i]);
					configuration[i][len - 1] = '"';
					if (*quotedptr == '"') {
						quotedptr++;
						break;
					}
					quoted = strtok_r(NULL, "\"", &quotedptr);
					tmp_string = xmalloc(len + strlen(quoted) + 1);
					if (tmp_string == NULL)
						return -1;

					memmove(tmp_string, configuration[i], len);
					memmove(tmp_string + len, quoted, strlen(quoted) + 1);
					configuration[i] = tmp_string;
				}
				offset += 2;
			}
		}

		offset += strlen(configuration[i]);

		if (was_newline) {
			was_newline = false;
			len = strlen(configuration[i]);
			tmp_string = xrealloc(configuration[i], len + strlen("--") + 1);
			if (tmp_string == NULL)
				return -1;

			memmove(tmp_string + strlen("--"), tmp_string, len + 1);
			memmove(tmp_string, "--", strlen("--"));
			configuration[i] = tmp_string;
		}
		i++;
	}

	return i;
}

/* Parse a configuration file */
static char ** parse_config(char *filepath)
{
#define DEFAULT_CONFIG_SIZE	10
	FILE* configfile = fopen(filepath, "r");
	int config_size = DEFAULT_CONFIG_SIZE;
	int i = 1;
	size_t line_size = 0;
	char *line = NULL;
	char **configuration;

	if (!configfile)
		return NULL;

	pr_debug("Parsing config file %s\n", filepath);

	configuration = xmalloc(config_size * sizeof(char *));
	if (configuration == NULL) {
		fclose(configfile);
		exit(1);
	}
	/*
	 * Initialize first element, getopt ignores it.
	 */
	configuration[0] = "criu";

	while (getline(&line, &line_size, configfile) != -1) {
		/* Extend configuration buffer if necessary */
		if (i >= config_size - 1) {
			config_size *= 2;
			configuration = xrealloc(configuration, config_size * sizeof(char *));
			if (configuration == NULL) {
				fclose(configfile);
				exit(1);
			}
		}

		i = parse_statement(i, line, configuration);
		if (i < 0) {
			fclose(configfile);
			exit(1);
		}

		free(line);
		line = NULL;
	}
	/* Initialize the last element */
	configuration[i] = NULL;

	free(line);
	fclose(configfile);
	return configuration;
}

static int next_config(char **argv, char ***_argv, bool no_default_config,
		int state, char *cfg_file)
{
	char local_filepath[PATH_MAX + 1];
	char *home_dir = NULL;
	char *cfg_from_env = NULL;

	if (state >= PARSING_LAST)
		return 0;

	switch(state) {
		case PARSING_GLOBAL_CONF:
			if (no_default_config)
				break;
			*_argv = parse_config(GLOBAL_CONFIG_DIR DEFAULT_CONFIG_FILENAME);
			break;
		case PARSING_USER_CONF:
			if (no_default_config)
				break;
			home_dir = getenv("HOME");
			if (!home_dir) {
				pr_info("Unable to get $HOME directory, local configuration file will not be used.");
			} else {
				snprintf(local_filepath, PATH_MAX, "%s/%s%s",
						home_dir, USER_CONFIG_DIR, DEFAULT_CONFIG_FILENAME);
				*_argv = parse_config(local_filepath);
			}
			break;
		case PARSING_ENV_CONF:
			cfg_from_env = getenv("CRIU_CONFIG_FILE");
			if (!cfg_from_env)
				break;
			*_argv = parse_config(cfg_from_env);
			break;
		case PARSING_CMDLINE_CONF:
			if (!cfg_file)
				break;
			*_argv = parse_config(cfg_file);
			break;
		case PARSING_ARGV:
			*_argv = argv;
			break;
		case PARSING_RPC_CONF:
			if (!rpc_cfg_file)
				break;
			*_argv = parse_config(rpc_cfg_file);
			break;
		default:
			break;
	}

	return ++state;
}

static int pre_parse(int argc, char **argv, bool *usage_error, bool *no_default_config,
		char **cfg_file)
{
	int i;
	/*
	 * We are running before getopt(), so we need to pre-parse
	 * the command line.
	 *
	 * Check for --help / -h on commandline before parsing, otherwise
	 * the help message won't be displayed if there is an error in
	 * configuration file syntax. Checks are kept in parser in case of
	 * option being put in the configuration file itself.
	 *
	 * Check also whether default configfiles are forbidden to lower
	 * number of argv iterations, but checks for help have higher priority.
	 */
	for (i = 0; i < argc; i++) {
		if ((!strcmp(argv[i], "--help")) || (!strcmp(argv[i], "-h"))) {
			*usage_error = false;
			return 1;
		} else if (!strcmp(argv[i], "--no-default-config")) {
			*no_default_config = true;
		} else if (!strcmp(argv[i], "--config")) {
			/*
			 * getopt takes next string as required
			 * argument automatically, we do the same
			 */
			*cfg_file = argv[i + 1];
			*no_default_config = true;
		} else if (strstr(argv[i], "--config=") != NULL) {
			*cfg_file = argv[i] + strlen("--config=");
			*no_default_config = true;
		}
	}

	return 0;
}

void init_opts(void)
{
	memset(&opts, 0, sizeof(opts));

	/* Default options */
	opts.final_state = TASK_DEAD;
	INIT_LIST_HEAD(&opts.ext_mounts);
	INIT_LIST_HEAD(&opts.inherit_fds);
	INIT_LIST_HEAD(&opts.external);
	INIT_LIST_HEAD(&opts.join_ns);
	INIT_LIST_HEAD(&opts.new_cgroup_roots);
	INIT_LIST_HEAD(&opts.irmap_scan_paths);

	opts.cpu_cap = CPU_CAP_DEFAULT;
	opts.manage_cgroups = CG_MODE_DEFAULT;
	opts.ps_socket = -1;
	opts.ghost_limit = DEFAULT_GHOST_LIMIT;
	opts.timeout = DEFAULT_TIMEOUT;
	opts.empty_ns = 0;
	opts.status_fd = -1;
	opts.log_level = DEFAULT_LOGLEVEL;
	opts.pre_dump_mode = PRE_DUMP_SPLICE;
	opts.file_validation_method = FILE_VALIDATION_DEFAULT;
}

bool deprecated_ok(char *what)
{
	if (opts.deprecated_ok)
		return true;

	pr_err("Deprecated functionality (%s) rejected.\n", what);
	pr_err("Use the --deprecated option or set CRIU_DEPRECATED environment.\n");
	pr_err("For details visit https://criu.org/Deprecation\n");
	return false;
}

static int parse_cpu_cap(struct cr_options *opts, const char *optarg)
{
	bool inverse = false;

#define ____cpu_set_cap(__opts, __cap, __inverse)	\
	do {						\
		if ((__inverse))			\
			(__opts)->cpu_cap &= ~(__cap);	\
		else					\
			(__opts)->cpu_cap |=  (__cap);	\
	} while (0)

	if (!optarg) {
		____cpu_set_cap(opts, CPU_CAP_ALL, false);
		____cpu_set_cap(opts, CPU_CAP_IMAGE, false);
		return 0;
	}

	while (*optarg) {
		if (optarg[0] == '^') {
			inverse = !inverse;
			optarg++;
			continue;
		} else if (optarg[0] == ',') {
			inverse = false;
			optarg++;
			continue;
		}

		if (!strncmp(optarg, "fpu", 3)) {
			____cpu_set_cap(opts, CPU_CAP_FPU, inverse);
			optarg += 3;
		} else if (!strncmp(optarg, "all", 3)) {
			____cpu_set_cap(opts, CPU_CAP_ALL, inverse);
			optarg += 3;
		} else if (!strncmp(optarg, "none", 4)) {
			if (inverse)
				opts->cpu_cap = CPU_CAP_ALL;
			else
				opts->cpu_cap = CPU_CAP_NONE;
			optarg += 4;
		} else if (!strncmp(optarg, "cpu", 3)) {
			____cpu_set_cap(opts, CPU_CAP_CPU, inverse);
			optarg += 3;
		} else if (!strncmp(optarg, "ins", 3)) {
			____cpu_set_cap(opts, CPU_CAP_INS, inverse);
			optarg += 3;
		} else
			goto Esyntax;
	}

	if (opts->cpu_cap != CPU_CAP_NONE)
		____cpu_set_cap(opts, CPU_CAP_IMAGE, false);
#undef ____cpu_set_cap

	return 0;

Esyntax:
	pr_err("Unknown FPU mode `%s' selected\n", optarg);
	return -1;
}

static int parse_manage_cgroups(struct cr_options *opts, const char *optarg)
{
	if (!optarg) {
		opts->manage_cgroups = CG_MODE_SOFT;
		return 0;
	}

	if (!strcmp(optarg, "none")) {
		opts->manage_cgroups = CG_MODE_NONE;
	} else if (!strcmp(optarg, "props")) {
		opts->manage_cgroups = CG_MODE_PROPS;
	} else if (!strcmp(optarg, "soft")) {
		opts->manage_cgroups = CG_MODE_SOFT;
	} else if (!strcmp(optarg, "full")) {
		opts->manage_cgroups = CG_MODE_FULL;
	} else if (!strcmp(optarg, "strict")) {
		opts->manage_cgroups = CG_MODE_STRICT;
	} else if (!strcmp(optarg, "ignore")) {
		opts->manage_cgroups = CG_MODE_IGNORE;
	} else
		goto Esyntax;

	return 0;

Esyntax:
	pr_err("Unknown cgroups mode `%s' selected\n", optarg);
	return -1;
}

extern char *index(const char *s, int c);

static size_t parse_size(char *optarg)
{
	if (index(optarg, 'K'))
		return (size_t)KILO(atol(optarg));
	else if (index(optarg, 'M'))
		return (size_t)MEGA(atol(optarg));
	else if (index(optarg, 'G'))
		return (size_t)GIGA(atol(optarg));
	return (size_t)atol(optarg);
}

static int parse_join_ns(const char *ptr)
{
	char *aux, *ns_file, *extra_opts = NULL;

	aux = strchr(ptr, ':');
	if (aux == NULL)
		return -1;
	*aux = '\0';

	ns_file = aux + 1;
	aux = strchr(ns_file, ',');
	if (aux != NULL) {
		*aux = '\0';
		extra_opts = aux + 1;
	} else {
		extra_opts = NULL;
	}
	if (join_ns_add(ptr, ns_file, extra_opts))
		return -1;

	return 0;
}

static int parse_file_validation_method(struct cr_options *opts, const char *optarg)
{
	if (!strcmp(optarg, "filesize"))
		opts->file_validation_method = FILE_VALIDATION_FILE_SIZE;
	else if (!strcmp(optarg, "buildid"))
		opts->file_validation_method = FILE_VALIDATION_BUILD_ID;
	else
		goto Esyntax;

	return 0;

Esyntax:
	pr_err("Unknown file validation method `%s' selected\n", optarg);
	return -1;
}

/*
 * parse_options() is the point where the getopt parsing happens. The CLI
 * parsing as well as the configuration file parsing happens here.
 * This used to be all part of main() and to integrate the new code flow
 * in main() this function (parse_options()) returns '0' if everything is
 * correct, '1' if something failed and '2' if the CRIU help text should
 * be displayed.
 */
int parse_options(int argc, char **argv, bool *usage_error,
		bool *has_exec_cmd, int state)
{
	int ret;
	int opt = -1;
	int idx;
	bool no_default_config = false;
	char *cfg_file = NULL;
	char **_argv = NULL;
	int _argc = 0;


#define BOOL_OPT(OPT_NAME, SAVE_TO) \
		{OPT_NAME, no_argument, SAVE_TO, true},\
		{"no-" OPT_NAME, no_argument, SAVE_TO, false}

	static const char short_opts[] = "dSsRt:hD:o:v::x::Vr:jJ:lW:L:M:";
	static struct option long_opts[] = {
		{ "tree",			required_argument,	0, 't'	},
		{ "leave-stopped",		no_argument,		0, 's'	},
		{ "leave-running",		no_argument,		0, 'R'	},
		BOOL_OPT("restore-detached", &opts.restore_detach),
		BOOL_OPT("restore-sibling", &opts.restore_sibling),
		BOOL_OPT("daemon", &opts.restore_detach),
		{ "images-dir",			required_argument,	0, 'D'	},
		{ "work-dir",			required_argument,	0, 'W'	},
		{ "log-file",			required_argument,	0, 'o'	},
		{ "join-ns",			required_argument,	0, 'J'	},
		{ "root",			required_argument,	0, 'r'	},
		{ USK_EXT_PARAM,		optional_argument,	0, 'x'	},
		{ "help",			no_argument,		0, 'h'	},
		BOOL_OPT(SK_EST_PARAM, &opts.tcp_established_ok),
		{ "close",			required_argument,	0, 1043	},
		BOOL_OPT("log-pid", &opts.log_file_per_pid),
		{ "version",			no_argument,		0, 'V'	},
		BOOL_OPT("evasive-devices", &opts.evasive_devices),
		{ "pidfile",			required_argument,	0, 1046	},
		{ "veth-pair",			required_argument,	0, 1047	},
		{ "action-script",		required_argument,	0, 1049	},
		BOOL_OPT(LREMAP_PARAM, &opts.link_remap_ok),
		BOOL_OPT(OPT_SHELL_JOB, &opts.shell_job),
		BOOL_OPT(OPT_FILE_LOCKS, &opts.handle_file_locks),
		BOOL_OPT("page-server", &opts.use_page_server),
		{ "address",			required_argument,	0, 1051	},
		{ "port",			required_argument,	0, 1052	},
		{ "prev-images-dir",		required_argument,	0, 1053	},
		{ "ms",				no_argument,		0, 1054	},
		BOOL_OPT("track-mem", &opts.track_mem),
		BOOL_OPT("auto-dedup", &opts.auto_dedup),
		{ "libdir",			required_argument,	0, 'L'	},
		{ "cpu-cap",			optional_argument,	0, 1057	},
		BOOL_OPT("force-irmap", &opts.force_irmap),
		{ "ext-mount-map",		required_argument,	0, 'M'	},
		{ "exec-cmd",			no_argument,		0, 1059	},
		{ "manage-cgroups",		optional_argument,	0, 1060	},
		{ "cgroup-root",		required_argument,	0, 1061	},
		{ "inherit-fd",			required_argument,	0, 1062	},
		{ "feature",			required_argument,	0, 1063	},
		{ "skip-mnt",			required_argument,	0, 1064 },
		{ "enable-fs",			required_argument,	0, 1065 },
		{ "enable-external-sharing",	no_argument,		&opts.enable_external_sharing, true	},
		{ "enable-external-masters",	no_argument,		&opts.enable_external_masters, true	},
		{ "freeze-cgroup",		required_argument,	0, 1068 },
		{ "ghost-limit",		required_argument,	0, 1069 },
		{ "irmap-scan-path",		required_argument,	0, 1070 },
		{ "lsm-profile",		required_argument,	0, 1071 },
		{ "timeout",			required_argument,	0, 1072 },
		{ "external",			required_argument,	0, 1073	},
		{ "empty-ns",			required_argument,	0, 1074	},
		{ "lazy-pages",			no_argument,		0, 1076 },
		BOOL_OPT("extra", &opts.check_extra_features),
		BOOL_OPT("experimental", &opts.check_experimental_features),
		{ "all",			no_argument,		0, 1079	},
		{ "cgroup-props",		required_argument,	0, 1080	},
		{ "cgroup-props-file",		required_argument,	0, 1081	},
		{ "cgroup-dump-controller",	required_argument,	0, 1082	},
		BOOL_OPT(SK_INFLIGHT_PARAM, &opts.tcp_skip_in_flight),
		BOOL_OPT("deprecated", &opts.deprecated_ok),
		BOOL_OPT("display-stats", &opts.display_stats),
		BOOL_OPT("weak-sysctls", &opts.weak_sysctls),
		{ "status-fd",			required_argument,	0, 1088 },
		BOOL_OPT(SK_CLOSE_PARAM, &opts.tcp_close),
		{ "verbosity",			optional_argument,	0, 'v'	},
		{ "ps-socket",			required_argument,	0, 1091},
		BOOL_OPT("stream", &opts.stream),
		{ "config",			required_argument,	0, 1089},
		{ "no-default-config",		no_argument,		0, 1090},
		{ "tls-cacert",			required_argument,	0, 1092},
		{ "tls-cacrl",			required_argument,	0, 1093},
		{ "tls-cert",			required_argument,	0, 1094},
		{ "tls-key",			required_argument,	0, 1095},
		BOOL_OPT("tls", &opts.tls),
		{"tls-no-cn-verify",		no_argument,		&opts.tls_no_cn_verify, true},
		{ "cgroup-yard",		required_argument,	0, 1096 },
		{ "pre-dump-mode",		required_argument,	0, 1097},
		{ "file-validation",		required_argument,	0, 1098	},
		{ },
	};

#undef BOOL_OPT

	ret = pre_parse(argc, argv, usage_error, &no_default_config,
			&cfg_file);

	if (ret)
		return 2;

	while (1) {
		idx = -1;
		/* Only if opt is -1 we are going to the next configuration input */
		if (opt == -1) {
			/* Do not free any memory if it points to argv */
			if (state != PARSING_ARGV + 1) {
				int i;
				for (i=1; i < _argc; i++) {
					free(_argv[i]);
				}
				free(_argv);
			}
			/* This needs to be reset for a new getopt() run */
			_argc = 0;
			_argv = NULL;

			state = next_config(argv, &_argv, no_default_config, state, cfg_file);

			/* if next_config() returns 0 it means no more configs found */
			if (state == 0)
				break;

			if (!_argv)
				continue;

			_argc = count_elements(_argv);
			optind = 0;
		}

		opt = getopt_long(_argc, _argv, short_opts, long_opts, &idx);

		/*
		 * The end of the current _argv has been reached,
		 * let's go to the next _argv
		 */
		if (opt == -1)
			continue;

		/*
		 * If opt == 0 then getopt will directly fill out the corresponding
		 * field in CRIU's opts structure.
		 */
		if (!opt)
			continue;

		switch (opt) {
		case 's':
			opts.final_state = TASK_STOPPED;
			break;
		case 'R':
			opts.final_state = TASK_ALIVE;
			break;
		case 'x':
			if (optarg && unix_sk_ids_parse(optarg) < 0) {
				pr_err("Failed to parse unix socket inode from optarg: %s\n", optarg);
				return 1;
			}
			opts.ext_unix_sk = true;
			break;
		case 't':
			opts.tree_id = atoi(optarg);
			if (opts.tree_id <= 0)
				goto bad_arg;
			break;
		case 'r':
			SET_CHAR_OPTS(root, optarg);
			break;
		case 'd':
			opts.restore_detach = true;
			break;
		case 'S':
			opts.restore_sibling = true;
			break;
		case 'D':
			SET_CHAR_OPTS(imgs_dir, optarg);
			break;
		case 'W':
			SET_CHAR_OPTS(work_dir, optarg);
			break;
		case 'o':
			SET_CHAR_OPTS(output, optarg);
			break;
		case 'J':
			if (parse_join_ns(optarg))
				goto bad_arg;
			break;
		case 'v':
			if (optarg) {
				if (optarg[0] == 'v')
					/* handle -vvvvv */
					opts.log_level += strlen(optarg) + 1;
				else
					opts.log_level = atoi(optarg);
			} else
				opts.log_level++;
			break;
		case 1043: {
			int fd;

			fd = atoi(optarg);
			pr_info("Closing fd %d\n", fd);
			close(fd);
			break;
		}
		case 1046:
			SET_CHAR_OPTS(pidfile, optarg);
			break;
		case 1047:
			{
				char *aux;

				aux = strchr(optarg, '=');
				if (aux == NULL)
					goto bad_arg;

				*aux = '\0';
				if (veth_pair_add(optarg, aux + 1)) {
					pr_err("Failed to add veth pair: %s, %s.\n", optarg, aux + 1);
					return 1;
				}
			}
			break;
		case 1049:
			if (add_script(optarg)) {
				pr_err("Failed to add action-script: %s.\n", optarg);
				return 1;
			}
			break;
		case 1051:
			SET_CHAR_OPTS(addr, optarg);
			break;
		case 1052:
			opts.port = atoi(optarg);
			if (!opts.port)
				goto bad_arg;
			break;
		case 'j':
			opts.shell_job = true;
			break;
		case 'l':
			opts.handle_file_locks = true;
			break;
		case 1053:
			SET_CHAR_OPTS(img_parent, optarg);
			break;
		case 1057:
			if (parse_cpu_cap(&opts, optarg))
				return 2;
			break;
		case 1058:
			opts.force_irmap = true;
			break;
		case 1054:
			pr_err("--ms is deprecated; see \"Check options\" of criu --help\n");
			return 1;
		case 'L':
			SET_CHAR_OPTS(libdir, optarg);
			opts.libdir = optarg;
			break;
		case 1059:
			*has_exec_cmd = true;
			break;
		case 1060:
			if (parse_manage_cgroups(&opts, optarg))
				return 2;
			break;
		case 1061:
			{
				char *path, *ctl;

				path = strchr(optarg, ':');
				if (path) {
					*path = '\0';
					path++;
					ctl = optarg;
				} else {
					path = optarg;
					ctl = NULL;
				}

				if (new_cg_root_add(ctl, path))
					return -1;
			}
			break;
		case 1062:
			if (inherit_fd_parse(optarg) < 0)
				return 1;
			break;
		case 1063:
			ret = check_add_feature(optarg);
			if (ret < 0)	/* invalid kernel feature name */
				return 1;
			if (ret > 0)	/* list kernel features and exit */
				return 0;
			break;
		case 1064:
			if (!add_skip_mount(optarg)) {
				pr_err("Failed to add skip-mnt: %s\n", optarg);
				return 1;
			}
			break;
		case 1065:
			if (!add_fsname_auto(optarg)) {
				pr_err("Failed while parsing --enable-fs option: %s", optarg);
				return 1;
			}
			break;
		case 1068:
			SET_CHAR_OPTS(freeze_cgroup, optarg);
			break;
		case 1069:
			opts.ghost_limit = parse_size(optarg);
			break;
		case 1070:
			if (irmap_scan_path_add(optarg)) {
				pr_err("Failed while parsing --irmap-scan-path option: %s", optarg);
				return -1;
			}
			break;
		case 1071:
			SET_CHAR_OPTS(lsm_profile, optarg);
			opts.lsm_supplied = true;
			break;
		case 1072:
			opts.timeout = atoi(optarg);
			break;
		case 1076:
			opts.lazy_pages = true;
			break;
		case 'M':
			{
				char *aux;

				if (strcmp(optarg, "auto") == 0) {
					opts.autodetect_ext_mounts = true;
					break;
				}

				aux = strchr(optarg, ':');
				if (aux == NULL)
					goto bad_arg;

				*aux = '\0';
				if (ext_mount_add(optarg, aux + 1)) {
					pr_err("Could not add external mount when initializing config: %s, %s\n", optarg, aux + 1);
					return 1;
				}
			}
			break;
		case 1073:
			if (add_external(optarg)) {
				pr_err("Could not add external resource when initializing config: %s\n", optarg);
				return 1;
			}
			break;
		case 1074:
			if (!strcmp("net", optarg))
				opts.empty_ns |= CLONE_NEWNET;
			else {
				pr_err("Unsupported empty namespace: %s\n",
						optarg);
				return 1;
			}
			break;
		case 1079:
			opts.check_extra_features = true;
			opts.check_experimental_features = true;
			break;
		case 1080:
			SET_CHAR_OPTS(cgroup_props, optarg);
			break;
		case 1081:
			SET_CHAR_OPTS(cgroup_props_file, optarg);
			break;
		case 1082:
			if (!cgp_add_dump_controller(optarg))
				return 1;
			break;
		case 1088:
			if (sscanf(optarg, "%d", &opts.status_fd) != 1) {
				pr_err("Unable to parse a value of --status-fd\n");
				return 1;
			}
			break;
		case 1089:
			break;
		case 1090:
			break;
		case 1091:
			opts.ps_socket = atoi(optarg);
			break;
		case 1092:
			SET_CHAR_OPTS(tls_cacert, optarg);
			break;
		case 1093:
			SET_CHAR_OPTS(tls_cacrl, optarg);
			break;
		case 1094:
			SET_CHAR_OPTS(tls_cert, optarg);
			break;
		case 1095:
			SET_CHAR_OPTS(tls_key, optarg);
			break;
		case 1096:
			SET_CHAR_OPTS(cgroup_yard, optarg);
			break;
		case 1097:
			if (!strcmp("read", optarg)) {
				opts.pre_dump_mode = PRE_DUMP_READ;
			} else if (strcmp("splice", optarg)) {
				pr_err("Unable to parse value of --pre-dump-mode\n");
				return 1;
			}
			break;
		case 1098:
			if (parse_file_validation_method(&opts, optarg))
				return 2;
			break;
		case 'V':
			pr_msg("Version: %s\n", CRIU_VERSION);
			if (strcmp(CRIU_GITID, "0"))
				pr_msg("GitID: %s\n", CRIU_GITID);
			exit(0);
		case 'h':
			*usage_error = false;
			return 2;
		default:
			return 2;
		}
	}

	return 0;

bad_arg:
	if (idx < 0) /* short option */
		pr_err("invalid argument for -%c: %s\n",
				opt, optarg);
	else /* long option */
		pr_err("invalid argument for --%s: %s\n",
				long_opts[idx].name, optarg);
	return 1;
}

int check_options(void)
{
	if (opts.tcp_established_ok)
		pr_info("Will dump/restore TCP connections\n");
	if (opts.tcp_skip_in_flight)
		pr_info("Will skip in-flight TCP connections\n");
	if (opts.tcp_close)
		pr_info("Will drop all TCP connections on restore\n");
	if (opts.link_remap_ok)
		pr_info("Will allow link remaps on FS\n");
	if (opts.weak_sysctls)
		pr_info("Will skip non-existant sysctls on restore\n");

	if (opts.deprecated_ok)
		pr_info("Turn deprecated stuff ON\n");
	else if (getenv("CRIU_DEPRECATED")) {
		pr_info("Turn deprecated stuff ON via env\n");
		opts.deprecated_ok = true;
	}

	if (!opts.restore_detach && opts.restore_sibling) {
		pr_err("--restore-sibling only makes sense with --restore-detached\n");
		return 1;
	}

	if (opts.ps_socket != -1) {
		if (opts.addr || opts.port)
			pr_warn("Using --address or --port in "
				"combination with --ps-socket is obsolete\n");
		if (opts.ps_socket <= STDERR_FILENO && opts.daemon_mode) {
			pr_err("Standard file descriptors will be closed"
				" in daemon mode\n");
			return 1;
		}
	}

#ifndef CONFIG_GNUTLS
	if (opts.tls) {
		pr_err("CRIU was built without TLS support\n");
		return 1;
	}
#endif

	if (check_namespace_opts()) {
		pr_err("Error: namespace flags conflict\n");
		return 1;
	}

	return 0;
}
