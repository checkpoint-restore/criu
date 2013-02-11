#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <string.h>
#include <ctype.h>

#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "asm/types.h"

#include "compiler.h"
#include "crtools.h"
#include "sockets.h"
#include "syscall.h"
#include "files.h"
#include "sk-inet.h"
#include "net.h"
#include "version.h"

struct cr_options opts;

static int parse_ns_string(const char *ptr)
{
	const char *end = ptr + strlen(ptr);

	do {
		if (ptr[3] != ',' && ptr[3] != '\0')
			goto bad_ns;
		if (!strncmp(ptr, "uts", 3))
			opts.rst_namespaces_flags |= CLONE_NEWUTS;
		else if (!strncmp(ptr, "ipc", 3))
			opts.rst_namespaces_flags |= CLONE_NEWIPC;
		else if (!strncmp(ptr, "mnt", 3))
			opts.rst_namespaces_flags |= CLONE_NEWNS;
		else if (!strncmp(ptr, "pid", 3))
			opts.rst_namespaces_flags |= CLONE_NEWPID;
		else if (!strncmp(ptr, "net", 3))
			opts.rst_namespaces_flags |= CLONE_NEWNET;
		else
			goto bad_ns;
		ptr += 4;
	} while (ptr < end);
	return 0;

bad_ns:
	pr_err("Unknown namespace '%s'\n", ptr);
	return -1;
}

int main(int argc, char *argv[])
{
	pid_t pid = 0;
	int ret = -1;
	int opt, idx;
	int log_inited = 0;
	int log_level = 0;

	static const char short_opts[] = "dsf:t:hcD:o:n:vxVr:jl";

	BUILD_BUG_ON(PAGE_SIZE != PAGE_IMAGE_SIZE);

	cr_pb_init();

	if (argc < 2)
		goto usage;

	/* Default options */
	opts.final_state = TASK_DEAD;
	INIT_LIST_HEAD(&opts.veth_pairs);
	INIT_LIST_HEAD(&opts.scripts);

	if (init_service_fd())
		return -1;

	while (1) {
		static struct option long_opts[] = {
			{ "tree", required_argument, 0, 't' },
			{ "leave-stopped", no_argument, 0, 's' },
			{ "restore-detached", no_argument, 0, 'd' },
			{ "contents", no_argument, 0, 'c' },
			{ "file", required_argument, 0, 'f' },
			{ "images-dir", required_argument, 0, 'D' },
			{ "log-file", required_argument, 0, 'o' },
			{ "namespaces", required_argument, 0, 'n' },
			{ "root", required_argument, 0, 'r' },
			{ "ext-unix-sk", no_argument, 0, 'x' },
			{ "help", no_argument, 0, 'h' },
			{ SK_EST_PARAM, no_argument, 0, 42 },
			{ "close", required_argument, 0, 43 },
			{ "log-pid", no_argument, 0, 44},
			{ "version", no_argument, 0, 'V'},
			{ "evasive-devices", no_argument, 0, 45},
			{ "pidfile", required_argument, 0, 46},
			{ "veth-pair", required_argument, 0, 47},
			{ "action-script", required_argument, 0, 49},
			{ LREMAP_PARAM, no_argument, 0, 41},
			{ "shell-job", no_argument, 0, 'j'},
			{ "file-locks", no_argument, 0, 'l'},
			{ },
		};

		opt = getopt_long(argc, argv, short_opts, long_opts, &idx);
		if (opt == -1)
			break;

		switch (opt) {
		case 's':
			opts.final_state = TASK_STOPPED;
			break;
		case 'x':
			opts.ext_unix_sk = true;
			break;
		case 't':
			pid = atoi(optarg);
			break;
		case 'c':
			opts.show_pages_content	= true;
			break;
		case 'f':
			opts.show_dump_file = optarg;
			break;
		case 'r':
			opts.root = optarg;
			break;
		case 'd':
			opts.restore_detach = true;
			break;
		case 'D':
			if (chdir(optarg)) {
				pr_perror("Can't change directory to %s",
						optarg);
				return -1;
			}
			break;
		case 'o':
			opts.output = strdup(optarg);
			if (log_init(optarg))
				return -1;
			log_inited = 1;
			break;
		case 'n':
			if (parse_ns_string(optarg))
				return -1;
			break;
		case 'v':
			if (optind < argc) {
				char *opt = argv[optind];

				if (isdigit(*opt)) {
					log_level = -atoi(opt);
					optind++;
				} else {
					if (log_level >= 0)
						log_level++;
				}
			} else {
				if (log_level >= 0)
					log_level++;
			}
			break;
		case 41:
			pr_info("Will allow link remaps on FS\n");
			opts.link_remap_ok = true;
			break;
		case 42:
			pr_info("Will dump TCP connections\n");
			opts.tcp_established_ok = true;
			break;
		case 43: {
			int fd;

			fd = atoi(optarg);
			pr_info("Closing fd %d\n", fd);
			close(fd);
			break;
		}
		case 44:
			opts.log_file_per_pid = 1;
			break;
		case 45:
			opts.evasive_devices = true;
			break;
		case 46:
			opts.pidfile = optarg;
			break;
		case 47:
			{
				struct veth_pair *n;

				n = xmalloc(sizeof(*n));
				if (n == NULL)
					return -1;
				n->outside = strchr(optarg, '=');
				if (n->outside == NULL) {
					xfree(n);
					pr_err("Invalid agument for --veth-pair\n");
					goto usage;
				}

				*n->outside++ = '\0';
				n->inside = optarg;
				list_add(&n->node, &opts.veth_pairs);
			}
			break;
		case 49:
			{
				struct script *script;

				script = xmalloc(sizeof(struct script));
				if (script == NULL)
					return -1;

				script->path = optarg;
				list_add(&script->node, &opts.scripts);
			}
			break;
		case 'j':
			opts.shell_job = true;
			break;
		case 'l':
			opts.handle_file_locks = true;
			break;
		case 'V':
			pr_msg("Version: %s\n", version);
			return 0;
		case 'h':
		default:
			goto usage;
		}
	}

	if (log_level < 0)
		log_level = -log_level;
	log_set_loglevel(log_level);

	if (!log_inited) {
		ret = log_init(NULL);
		if (ret)
			return ret;
	}

	ret = open_image_dir();
	if (ret < 0) {
		pr_perror("can't open currect directory");
		return -1;
	}

	if (optind >= argc)
		goto usage;

	if (strcmp(argv[optind], "dump") &&
	    strcmp(argv[optind], "restore") &&
	    strcmp(argv[optind], "show") &&
	    strcmp(argv[optind], "check") &&
	    strcmp(argv[optind], "exec")) {
		pr_err("Unknown command %s\n", argv[optind]);
		goto usage;
	}

	switch (argv[optind][0]) {
	case 'd':
		if (!pid)
			goto opt_pid_missing;
		ret = cr_dump_tasks(pid, &opts);
		break;
	case 'r':
		if (!pid)
			goto opt_pid_missing;
		ret = cr_restore_tasks(pid, &opts);
		break;
	case 's':
		ret = cr_show(&opts);
		break;
	case 'c':
		ret = cr_check();
		break;
	case 'e':
		if (!pid)
			goto opt_pid_missing;
		ret = cr_exec(pid, argv + optind + 1);
		break;
	default:
		goto usage;
		break;
	}

	return ret;

usage:
	pr_msg("\nUsage:\n");
	pr_msg("  %s dump -t pid [<options>]\n", argv[0]);
	pr_msg("  %s restore -t pid [<options>]\n", argv[0]);
	pr_msg("  %s show (-D dir)|(-f file) [<options>]\n", argv[0]);
	pr_msg("  %s check\n", argv[0]);
	pr_msg("  %s exec -t pid <syscall-string>\n", argv[0]);

	pr_msg("\nCommands:\n");
	pr_msg("  dump           checkpoint a process/tree identified by pid\n");
	pr_msg("  restore        restore a process/tree identified by pid\n");
	pr_msg("  show           show dump file(s) contents\n");
	pr_msg("  check          checks whether the kernel support is up-to-date\n");
	pr_msg("  exec           execute a system call by other task\n");

	if (argc < 2) {
		pr_msg("\nTry -h|--help for more info\n");
		return -1;
	}

	pr_msg("\nDump/Restore options:\n");

	pr_msg("\n* Generic:\n");
	pr_msg("  -t|--tree             checkpoint/restore the whole process tree identified by pid\n");
	pr_msg("  -d|--restore-detached detach after restore\n");
	pr_msg("  -s|--leave-stopped    leave tasks in stopped state after checkpoint instead of killing them\n");
	pr_msg("  -D|--images-dir       directory where to put images to\n");
	pr_msg("     --pidfile [FILE]	write a pid of a root task in this file\n");

	pr_msg("\n* Special resources support:\n");
	pr_msg("  -n|--namespaces       checkpoint/restore namespaces - values must be separated by comma\n");
	pr_msg("                        supported: uts, ipc, mnt, pid, net\n");
	pr_msg("  -x|--ext-unix-sk      allow external unix connections\n");
	pr_msg("     --%s  checkpoint/restore established TCP connections\n", SK_EST_PARAM);
	pr_msg("  -r|--root [PATH]	change the root filesystem (when run in mount namespace)\n");
	pr_msg("  --evasive-devices	use any path to a device file if the original one is inaccessible\n");
	pr_msg("  --veth-pair [IN=OUT]	correspondence between outside and inside names of veth devices\n");
	pr_msg("  --link-remap          allow to link unlinked files back when possible (modifies FS till restore)\n");
	pr_msg("  --action-script [SCR]	add an external action script\n");
	pr_msg("			The environment variable CRTOOL_SCRIPT_ACTION contains one of the actions:\n");
	pr_msg("			* network-lock - lock network in a target network namespace\n");
	pr_msg("			* network-unlock - unlock network in a target network namespace\n");
	pr_msg("  -j|--shell-job        allow to dump and restore shell jobs\n");
	pr_msg("  -l|--file-locks	handle file locks, for safety, only used for container\n");

	pr_msg("\n* Logging:\n");
	pr_msg("  -o|--log-file [NAME]  log file name (relative path is relative to --images-dir)\n");
	pr_msg("     --log-pid		if the -o option is in effect, each restored processes is\n");
	pr_msg("			written to the [NAME].pid file\n");
	pr_msg("  -v [num]              set logging level\n");
	pr_msg("                          0 - messages regardless of log level\n");
	pr_msg("                          1 - errors, when we are in trouble\n");
	pr_msg("                          2 - warnings (default)\n");
	pr_msg("                          3 - informative, everything is fine\n");
	pr_msg("                          4 - debug only\n");
	pr_msg("  -v             same as -v 1\n");
	pr_msg("  -vv            same as -v 2\n");
	pr_msg("  -vvv           same as -v 3\n");
	pr_msg("  -vvvv          same as -v 4\n");

	pr_msg("\nShow options:\n");
	pr_msg("  -f|--file             show contents of a checkpoint file\n");
	pr_msg("  -D|--images-dir       directory where to get images from\n");
	pr_msg("  -c|--contents         show contents of pages dumped in hexdump format\n");

	pr_msg("\nOther options:\n");
	pr_msg("  -h|--help             show this text\n");
	pr_msg("  -V|--version          show version\n");

	return -1;

opt_pid_missing:
	pr_msg("No pid specified (-t option missing)\n");
	return -1;
}
