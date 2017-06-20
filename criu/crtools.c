#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <string.h>
#include <ctype.h>
#include <sched.h>

#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <dlfcn.h>

#include "int.h"
#include "page.h"
#include "common/compiler.h"
#include "crtools.h"
#include "cr_options.h"
#include "external.h"
#include "files.h"
#include "sk-inet.h"
#include "net.h"
#include "version.h"
#include "page-xfer.h"
#include "tty.h"
#include "file-lock.h"
#include "cr-service.h"
#include "plugin.h"
#include "criu-log.h"
#include "util.h"
#include "mount.h"
#include "filesystems.h"
#include "namespaces.h"
#include "cgroup.h"
#include "cgroup-props.h"
#include "cpu.h"
#include "action-scripts.h"
#include "irmap.h"
#include "fault-injection.h"
#include "lsm.h"
#include "proc_parse.h"

#include "setproctitle.h"
#include "sysctl.h"

#include "../soccr/soccr.h"

struct cr_options opts;

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
	} else
		goto Esyntax;

	return 0;

Esyntax:
	pr_err("Unknown cgroups mode `%s' selected\n", optarg);
	return -1;
}

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

bool deprecated_ok(char *what)
{
	if (opts.deprecated_ok)
		return true;

	pr_err("Deprecated functionality (%s) rejected.\n", what);
	pr_err("Use the --deprecated option or set CRIU_DEPRECATED environment.\n");
	pr_err("For details visit https://criu.org/Deprecation\n");
	return false;
}

int main(int argc, char *argv[], char *envp[])
{

#define BOOL_OPT(OPT_NAME, SAVE_TO) \
		{OPT_NAME, no_argument, SAVE_TO, true},\
		{"no-" OPT_NAME, no_argument, SAVE_TO, false}

	pid_t pid = 0, tree_id = 0;
	int ret = -1;
	bool usage_error = true;
	bool has_exec_cmd = false;
	bool has_sub_command;
	int opt, idx;
	int log_level = DEFAULT_LOGLEVEL;
	char *imgs_dir = ".";
	static const char short_opts[] = "dSsRf:F:t:p:hcD:o:v::x::Vr:jJ:lW:L:M:";
	static struct option long_opts[] = {
		{ "tree",			required_argument,	0, 't'	},
		{ "pid",			required_argument,	0, 'p'	},
		{ "leave-stopped",		no_argument,		0, 's'	},
		{ "leave-running",		no_argument,		0, 'R'	},
		BOOL_OPT("restore-detached", &opts.restore_detach),
		BOOL_OPT("restore-sibling", &opts.restore_sibling),
		BOOL_OPT("daemon", &opts.restore_detach),
		{ "contents",			no_argument,		0, 'c'	},
		{ "file",			required_argument,	0, 'f'	},
		{ "fields",			required_argument,	0, 'F'	},
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
		{ "enable-external-sharing", 	no_argument, 		&opts.enable_external_sharing, true	},
		{ "enable-external-masters", 	no_argument, 		&opts.enable_external_masters, true	},
		{ "freeze-cgroup",		required_argument,	0, 1068 },
		{ "ghost-limit",		required_argument,	0, 1069 },
		{ "irmap-scan-path",		required_argument,	0, 1070 },
		{ "lsm-profile",		required_argument,	0, 1071 },
		{ "timeout",			required_argument,	0, 1072 },
		{ "external",			required_argument,	0, 1073	},
		{ "empty-ns",			required_argument,	0, 1074	},
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
		{ },
	};

#undef BOOL_OPT

	BUILD_BUG_ON(PAGE_SIZE != PAGE_IMAGE_SIZE);
	BUILD_BUG_ON(CTL_32 != SYSCTL_TYPE__CTL_32);
	BUILD_BUG_ON(__CTL_STR != SYSCTL_TYPE__CTL_STR);

	if (fault_injection_init())
		return 1;

	cr_pb_init();
	setproctitle_init(argc, argv, envp);

	if (argc < 2)
		goto usage;

	init_opts();

	if (init_service_fd())
		return 1;

	if (!strcmp(argv[1], "swrk")) {
		if (argc < 3)
			goto usage;
		/*
		 * This is to start criu service worker from libcriu calls.
		 * The usage is "criu swrk <fd>" and is not for CLI/scripts.
		 * The arguments semantics can change at any time with the
		 * corresponding lib call change.
		 */
		opts.swrk_restore = true;
		return cr_service_work(atoi(argv[2]));
	}

	while (1) {
		idx = -1;
		opt = getopt_long(argc, argv, short_opts, long_opts, &idx);
		if (opt == -1)
			break;
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
			if (optarg && unix_sk_ids_parse(optarg) < 0)
				return 1;
			opts.ext_unix_sk = true;
			break;
		case 'p':
			pid = atoi(optarg);
			if (pid <= 0)
				goto bad_arg;
			break;
		case 't':
			tree_id = atoi(optarg);
			if (tree_id <= 0)
				goto bad_arg;
			break;
		case 'c':
			opts.show_pages_content	= true;
			break;
		case 'f':
			opts.show_dump_file = optarg;
			break;
		case 'F':
			opts.show_fmt = optarg;
			break;
		case 'r':
			opts.root = optarg;
			break;
		case 'd':
			opts.restore_detach = true;
			break;
		case 'S':
			opts.restore_sibling = true;
			break;
		case 'D':
			imgs_dir = optarg;
			break;
		case 'W':
			opts.work_dir = optarg;
			break;
		case 'o':
			opts.output = optarg;
			break;
		case 'J':
			if (parse_join_ns(optarg))
				goto bad_arg;
			break;
		case 'v':
			if (optarg) {
				if (optarg[0] == 'v')
					/* handle -vvvvv */
					log_level += strlen(optarg) + 1;
				else
					log_level = atoi(optarg);
			} else
				log_level++;
			break;
		case 1043: {
			int fd;

			fd = atoi(optarg);
			pr_info("Closing fd %d\n", fd);
			close(fd);
			break;
		}
		case 1046:
			opts.pidfile = optarg;
			break;
		case 1047:
			{
				char *aux;

				aux = strchr(optarg, '=');
				if (aux == NULL)
					goto bad_arg;

				*aux = '\0';
				if (veth_pair_add(optarg, aux + 1))
					return 1;
			}
			break;
		case 1049:
			if (add_script(optarg))
				return 1;

			break;
		case 1051:
			opts.addr = optarg;
			break;
		case 1052:
			opts.port = htons(atoi(optarg));
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
			opts.img_parent = optarg;
			break;
		case 1057:
			if (parse_cpu_cap(&opts, optarg))
				goto usage;
			break;
		case 1058:
			opts.force_irmap = true;
			break;
		case 1054:
			pr_err("--ms is deprecated; see \"Check options\" of criu --help\n");
			return 1;
		case 'L':
			opts.libdir = optarg;
			break;
		case 1059:
			has_exec_cmd = true;
			break;
		case 1060:
			if (parse_manage_cgroups(&opts, optarg))
				goto usage;
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
			if (!add_skip_mount(optarg))
				return 1;
			break;
		case 1065:
			if (!add_fsname_auto(optarg))
				return 1;
			break;
		case 1068:
			opts.freeze_cgroup = optarg;
			break;
		case 1069:
			opts.ghost_limit = parse_size(optarg);
			break;
		case 1070:
			if (irmap_scan_path_add(optarg))
				return -1;
			break;
		case 1071:
			opts.lsm_profile = optarg;
			opts.lsm_supplied = true;
			break;
		case 1072:
			opts.timeout = atoi(optarg);
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
				if (ext_mount_add(optarg, aux + 1))
					return 1;
			}
			break;
		case 1073:
			if (add_external(optarg))
				return 1;
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
			opts.cgroup_props = optarg;
			break;
		case 1081:
			opts.cgroup_props_file = optarg;
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
		case 'V':
			pr_msg("Version: %s\n", CRIU_VERSION);
			if (strcmp(CRIU_GITID, "0"))
				pr_msg("GitID: %s\n", CRIU_GITID);
			return 0;
		case 'h':
			usage_error = false;
			goto usage;
		default:
			goto usage;
		}
	}

	if (opts.deprecated_ok)
		pr_msg("Turn deprecated stuff ON\n");
	if (opts.tcp_skip_in_flight)
		pr_msg("Will skip in-flight TCP connections\n");
	if (opts.tcp_established_ok)
		pr_info("Will dump TCP connections\n");
	if (opts.link_remap_ok)
		pr_info("Will allow link remaps on FS\n");
	if (opts.weak_sysctls)
		pr_msg("Will skip non-existant sysctls on restore\n");

	if (getenv("CRIU_DEPRECATED")) {
		pr_msg("Turn deprecated stuff ON via env\n");
		opts.deprecated_ok = true;
	}

	if (check_namespace_opts()) {
		pr_msg("Error: namespace flags conflict\n");
		return 1;
	}

	if (!opts.restore_detach && opts.restore_sibling) {
		pr_msg("--restore-sibling only makes sense with --restore-detach\n");
		return 1;
	}

	if (opts.work_dir == NULL)
		opts.work_dir = imgs_dir;

	if (optind >= argc) {
		pr_msg("Error: command is required\n");
		goto usage;
	}

	if (!strcmp(argv[optind], "exec")) {
		pr_msg("The \"exec\" action is deprecated by the Compel library.\n");
		return -1;
	}

	has_sub_command = (argc - optind) > 1;

	if (has_exec_cmd) {
		if (!has_sub_command) {
			pr_msg("Error: --exec-cmd requires a command\n");
			goto usage;
		}

		if (strcmp(argv[optind], "restore")) {
			pr_msg("Error: --exec-cmd is available for the restore command only\n");
			goto usage;
		}

		if (opts.restore_detach) {
			pr_msg("Error: --restore-detached and --exec-cmd cannot be used together\n");
			goto usage;
		}

		opts.exec_cmd = xmalloc((argc - optind) * sizeof(char *));
		if (!opts.exec_cmd)
			return 1;
		memcpy(opts.exec_cmd, &argv[optind + 1], (argc - optind - 1) * sizeof(char *));
		opts.exec_cmd[argc - optind - 1] = NULL;
	} else {
		/* No subcommands except for cpuinfo and restore --exec-cmd */
		if (strcmp(argv[optind], "cpuinfo") && has_sub_command) {
			pr_msg("Error: excessive parameter%s for command %s\n",
				(argc - optind) > 2 ? "s" : "", argv[optind]);
			goto usage;
		}
	}

	/* We must not open imgs dir, if service is called */
	if (strcmp(argv[optind], "service")) {
		ret = open_image_dir(imgs_dir);
		if (ret < 0)
			return 1;
	}

	/*
	 * When a process group becomes an orphan,
	 * its processes are sent a SIGHUP signal
	 */
	if (!strcmp(argv[optind], "restore") &&
			opts.restore_detach &&
			opts.final_state == TASK_STOPPED &&
			opts.shell_job)
		pr_warn("Stopped and detached shell job will get SIGHUP from OS.");

	if (chdir(opts.work_dir)) {
		pr_perror("Can't change directory to %s", opts.work_dir);
		return 1;
	}

	log_set_loglevel(log_level);

	if (log_init(opts.output))
		return 1;
	libsoccr_set_log(log_level, print_on_level);
	compel_log_init(vprint_on_level, log_get_loglevel());

	pr_debug("Version: %s (gitid %s)\n", CRIU_VERSION, CRIU_GITID);
	if (opts.deprecated_ok)
		pr_debug("DEPRECATED ON\n");

	if (!list_empty(&opts.inherit_fds)) {
		if (strcmp(argv[optind], "restore")) {
			pr_err("--inherit-fd is restore-only option\n");
			return 1;
		}
		/* now that log file is set up, print inherit fd list */
		inherit_fd_log();
	}

	if (opts.img_parent)
		pr_info("Will do snapshot from %s\n", opts.img_parent);

	if (!strcmp(argv[optind], "dump")) {
		if (!tree_id)
			goto opt_pid_missing;
		return cr_dump_tasks(tree_id);
	}

	if (!strcmp(argv[optind], "pre-dump")) {
		if (!tree_id)
			goto opt_pid_missing;

		return cr_pre_dump_tasks(tree_id) != 0;
	}

	if (!strcmp(argv[optind], "restore")) {
		if (tree_id)
			pr_warn("Using -t with criu restore is obsoleted\n");

		ret = cr_restore_tasks();
		if (ret == 0 && opts.exec_cmd) {
			close_pid_proc();
			execvp(opts.exec_cmd[0], opts.exec_cmd);
			pr_perror("Failed to exec command %s", opts.exec_cmd[0]);
			ret = 1;
		}

		return ret != 0;
	}

	if (!strcmp(argv[optind], "show")) {
		pr_msg("The \"show\" action is deprecated by the CRIT utility.\n");
		pr_msg("To view an image use the \"crit decode -i $name --pretty\" command.\n");
		return -1;
	}

	if (!strcmp(argv[optind], "check"))
		return cr_check() != 0;

	if (!strcmp(argv[optind], "page-server"))
		return cr_page_server(opts.daemon_mode, -1) != 0;

	if (!strcmp(argv[optind], "service"))
		return cr_service(opts.daemon_mode);

	if (!strcmp(argv[optind], "dedup"))
		return cr_dedup() != 0;

	if (!strcmp(argv[optind], "cpuinfo")) {
		if (!argv[optind + 1]) {
			pr_msg("Error: cpuinfo requires an action: dump or check\n");
			goto usage;
		}
		if (!strcmp(argv[optind + 1], "dump"))
			return cpuinfo_dump();
		else if (!strcmp(argv[optind + 1], "check"))
			return cpuinfo_check();
	}

	pr_msg("Error: unknown command: %s\n", argv[optind]);
usage:
	pr_msg("\n"
"Usage:\n"
"  criu dump|pre-dump -t PID [<options>]\n"
"  criu restore [<options>]\n"
"  criu check [--feature FEAT]\n"
"  criu page-server\n"
"  criu service [<options>]\n"
"  criu dedup\n"
"\n"
"Commands:\n"
"  dump           checkpoint a process/tree identified by pid\n"
"  pre-dump       pre-dump task(s) minimizing their frozen time\n"
"  restore        restore a process/tree\n"
"  check          checks whether the kernel support is up-to-date\n"
"  page-server    launch page server\n"
"  service        launch service\n"
"  dedup          remove duplicates in memory dump\n"
"  cpuinfo dump   writes cpu information into image file\n"
"  cpuinfo check  validates cpu information read from image file\n"
	);

	if (usage_error) {
		pr_msg("\nTry -h|--help for more info\n");
		return 1;
	}

	pr_msg("\n"

"Most of the true / false long options (the ones without arguments) can be\n"
"prefixed with --no- to negate the option (example: --display-stats and\n"
"--no-display-stats).\n"
"\n"
"Dump/Restore options:\n"
"\n"
"* Generic:\n"
"  -t|--tree PID         checkpoint a process tree identified by PID\n"
"  -d|--restore-detached detach after restore\n"
"  -S|--restore-sibling  restore root task as sibling\n"
"  -s|--leave-stopped    leave tasks in stopped state after checkpoint\n"
"  -R|--leave-running    leave tasks in running state after checkpoint\n"
"  -D|--images-dir DIR   directory for image files\n"
"     --pidfile FILE     write root task, service or page-server pid to FILE\n"
"  -W|--work-dir DIR     directory to cd and write logs/pidfiles/stats to\n"
"                        (if not specified, value of --images-dir is used)\n"
"     --cpu-cap [CAP]    CPU capabilities to write/check. CAP is comma-separated\n"
"                        list of: cpu, fpu, all, ins, none. To disable\n"
"                        a capability, use ^CAP. Empty argument implies all\n"
"     --exec-cmd         execute the command specified after '--' on successful\n"
"                        restore making it the parent of the restored process\n"
"  --freeze-cgroup       use cgroup freezer to collect processes\n"
"  --weak-sysctls        skip restoring sysctls that are not available\n"
"\n"
"* External resources support:\n"
"  --external RES        dump objects from this list as external resources:\n"
"                        Formats of RES on dump:\n"
"                            tty[rdev:dev]\n"
"                            file[mnt_id:inode]\n"
"                            dev[major/minor]:NAME\n"
"                            unix[ino]\n"
"                            mnt[MOUNTPOINT]:COOKIE\n"
"                            mnt[]{:AUTO_OPTIONS}\n"
"                        Formats of RES on restore:\n"
"                            dev[NAME]:DEVPATH\n"
"                            veth[IFNAME]:OUTNAME{@BRIDGE}\n"
"                            macvlan[IFNAME]:OUTNAME\n"
"                            mnt[COOKIE]:ROOT\n"
"\n"
"* Special resources support:\n"
"     --" SK_EST_PARAM "  checkpoint/restore established TCP connections\n"
"     --" SK_INFLIGHT_PARAM "   skip (ignore) in-flight TCP connections\n"
"     --" SK_CLOSE_PARAM "        restore connected TCP sockets in closed state\n"
"  -r|--root PATH        change the root filesystem (when run in mount namespace)\n"
"  --evasive-devices     use any path to a device file if the original one\n"
"                        is inaccessible\n"
"  --link-remap          allow one to link unlinked files back when possible\n"
"  --ghost-limit size    limit max size of deleted file contents inside image\n"
"  --action-script FILE  add an external action script\n"
"  -j|--" OPT_SHELL_JOB "        allow one to dump and restore shell jobs\n"
"  -l|--" OPT_FILE_LOCKS "       handle file locks, for safety, only used for container\n"
"  -L|--libdir           path to a plugin directory (by default " CR_PLUGIN_DEFAULT ")\n"
"  --force-irmap         force resolving names for inotify/fsnotify watches\n"
"  --irmap-scan-path FILE\n"
"                        add a path the irmap hints to scan\n"
"  --manage-cgroups [m]  dump/restore process' cgroups; argument can be one of\n"
"                        'none', 'props', 'soft' (default), 'full' or 'strict'\n"
"  --cgroup-root [controller:]/newroot\n"
"                        on dump: change the root for the controller that will\n"
"                        be dumped. By default, only the paths with tasks in\n"
"                        them and below will be dumped.\n"
"                        on restore: change the root cgroup the controller will\n"
"                        be installed into. No controller means that root is the\n"
"                        default for all controllers not specified\n"
"  --cgroup-props STRING\n"
"                        define cgroup controllers and properties\n"
"                        to be checkpointed, which are described\n"
"                        via STRING using simplified YAML format\n"
"  --cgroup-props-file FILE\n"
"                        same as --cgroup-props, but taking description\n"
"                        from the path specified\n"
"  --cgroup-dump-controller NAME\n"
"                        define cgroup controller to be dumped\n"
"                        and skip anything else present in system\n"
"  --skip-mnt PATH       ignore this mountpoint when dumping the mount namespace\n"
"  --enable-fs FSNAMES   a comma separated list of filesystem names or \"all\"\n"
"                        force criu to (try to) dump/restore these filesystem's\n"
"                        mountpoints even if fs is not supported\n"
"  --inherit-fd fd[NUM]:RES\n"
"                        Inherit file descriptors, treating fd NUM as being\n"
"                        already opened via an existing RES, which can be:\n"
"                            tty[rdev:dev]\n"
"                            pipe[inode]\n"
"                            socket[inode]\n"
"                            file[mnt_id:inode]\n"
"                            path/to/file\n"
"  --empty-ns net        Create a namespace, but don't restore its properties\n"
"                        (assuming it will be restored by action scripts)\n"
"  -J|--join-ns NS:{PID|NS_FILE}[,OPTIONS]\n"
"			Join existing namespace and restore process in it.\n"
"			Namespace can be specified as either pid or file path.\n"
"			OPTIONS can be used to specify parameters for userns:\n"
"			    user:PID,UID,GID\n"
"\n"
"Check options:\n"
"  Without options, \"criu check\" checks availability of absolutely required\n"
"  kernel features, critical for performing dump and restore.\n"
"  --extra               add check for extra kernel features\n"
"  --experimental        add check for experimental kernel features\n"
"  --all                 same as --extra --experimental\n"
"  --feature FEAT        only check a particular feature, one of:"
	);
	pr_check_features("                            ", ", ", 80);
	pr_msg(
"\n"
"* Logging:\n"
"  -o|--log-file FILE    log file name\n"
"     --log-pid          enable per-process logging to separate FILE.pid files\n"
"  -v[v...]|--verbosity  increase verbosity (can use multiple v)\n"
"  -vNUM|--verbosity=NUM set verbosity to NUM (higher level means more output):\n"
"                          -v1 - only errors and messages\n"
"                          -v2 - also warnings (default level)\n"
"                          -v3 - also information messages and timestamps\n"
"                          -v4 - lots of debug\n"
"  --display-stats       print out dump/restore stats\n"
"\n"
"* Memory dumping options:\n"
"  --track-mem           turn on memory changes tracker in kernel\n"
"  --prev-images-dir DIR path to images from previous dump (relative to -D)\n"
"  --page-server         send pages to page server (see options below as well)\n"
"  --auto-dedup          when used on dump it will deduplicate \"old\" data in\n"
"                        pages images of previous dump\n"
"                        when used on restore, as soon as page is restored, it\n"
"                        will be punched from the image\n"
"\n"
"Page/Service server options:\n"
"  --address ADDR        address of server or service\n"
"  --port PORT           port of page server\n"
"  -d|--daemon           run in the background after creating socket\n"
"  --status-fd FD        write \\0 to the FD and close it once process is ready\n"
"                        to handle requests\n"
"\n"
"Other options:\n"
"  -h|--help             show this text\n"
"  -V|--version          show version\n"
	);

	return 0;

opt_pid_missing:
	pr_msg("Error: pid not specified\n");
	return 1;

bad_arg:
	if (idx < 0) /* short option */
		pr_msg("Error: invalid argument for -%c: %s\n",
				opt, optarg);
	else /* long option */
		pr_msg("Error: invalid argument for --%s: %s\n",
				long_opts[idx].name, optarg);
	return 1;
}
