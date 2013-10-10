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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "asm/types.h"

#include "compiler.h"
#include "crtools.h"
#include "sockets.h"
#include "syscall.h"
#include "files.h"
#include "sk-inet.h"
#include "net.h"
#include "version.h"
#include "page-xfer.h"
#include "tty.h"
#include "file-lock.h"
#include "cr-service.h"

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
	pid_t pid = 0, tree_id = 0;
	int ret = -1;
	int opt, idx;
	int log_inited = 0;
	int log_level = 0;

	BUILD_BUG_ON(PAGE_SIZE != PAGE_IMAGE_SIZE);

	cr_pb_init();
	restrict_uid(getuid(), getgid());

	if (argc < 2)
		goto usage;

	/* Default options */
	opts.final_state = TASK_DEAD;
	INIT_LIST_HEAD(&opts.veth_pairs);
	INIT_LIST_HEAD(&opts.scripts);

	if (init_service_fd())
		return -1;

	while (1) {
		static const char short_opts[] = "dsRf:t:p:hcD:o:n:v::xVr:jl";
		static struct option long_opts[] = {
			{ "tree", required_argument, 0, 't' },
			{ "pid", required_argument, 0, 'p' },
			{ "leave-stopped", no_argument, 0, 's' },
			{ "leave-running", no_argument, 0, 'R' },
			{ "restore-detached", no_argument, 0, 'd' },
			{ "daemon", no_argument, 0, 'd' },
			{ "contents", no_argument, 0, 'c' },
			{ "file", required_argument, 0, 'f' },
			{ "images-dir", required_argument, 0, 'D' },
			{ "log-file", required_argument, 0, 'o' },
			{ "namespaces", required_argument, 0, 'n' },
			{ "root", required_argument, 0, 'r' },
			{ USK_EXT_PARAM, no_argument, 0, 'x' },
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
			{ OPT_SHELL_JOB, no_argument, 0, 'j'},
			{ OPT_FILE_LOCKS, no_argument, 0, 'l'},
			{ "page-server", no_argument, 0, 50},
			{ "address", required_argument, 0, 51},
			{ "port", required_argument, 0, 52},
			{ "prev-images-dir", required_argument, 0, 53},
			{ "ms", no_argument, 0, 54},
			{ "track-mem", no_argument, 0, 55},
			{ },
		};

		opt = getopt_long(argc, argv, short_opts, long_opts, &idx);
		if (opt == -1)
			break;

		switch (opt) {
		case 's':
			opts.final_state = TASK_STOPPED;
			break;
		case 'R':
			opts.final_state = TASK_ALIVE;
			break;
		case 'x':
			opts.ext_unix_sk = true;
			break;
		case 'p':
			pid = atoi(optarg);
			break;
		case 't':
			tree_id = atoi(optarg);
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
			opts.output = optarg;
			if (log_init(optarg))
				return -1;
			log_inited = 1;
			break;
		case 'n':
			if (parse_ns_string(optarg))
				return -1;
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
					pr_err("Invalid argument for --veth-pair\n");
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
		case 50:
			opts.use_page_server = true;
			break;
		case 51:
			opts.addr = optarg;
			break;
		case 52:
			opts.ps_port = htons(atoi(optarg));
			if (!opts.ps_port) {
				pr_err("Bad port\n");
				return -1;
			}
			break;
		case 'j':
			opts.shell_job = true;
			break;
		case 'l':
			opts.handle_file_locks = true;
			break;
		case 53:
			opts.img_parent = optarg;
			break;
		case 55:
			opts.track_mem = true;
			break;
		case 54:
			opts.check_ms_kernel = true;
			break;
		case 'V':
			pr_msg("Version: %s\n", CRIU_VERSION);
			if (strcmp(CRIU_GITID, "0"))
				pr_msg("GitID: %s\n", CRIU_GITID);
			return 0;
		case 'h':
		default:
			goto usage;
		}
	}

	log_set_loglevel(log_level);

	if (!log_inited) {
		ret = log_init(NULL);
		if (ret)
			return ret;
	}

	if (opts.img_parent)
		pr_info("Will do snapshot from %s\n", opts.img_parent);

	ret = open_image_dir();
	if (ret < 0) {
		pr_perror("Can't open current directory");
		return -1;
	}

	if (optind >= argc)
		goto usage;

	if (!strcmp(argv[optind], "dump")) {
		if (!tree_id)
			goto opt_pid_missing;
		return cr_dump_tasks(tree_id);
	}

	if (!strcmp(argv[optind], "pre-dump")) {
		if (!tree_id)
			goto opt_pid_missing;

		if (!opts.track_mem) {
			pr_info("Enforcing memory tracking for pre-dump.\n");
			opts.track_mem = true;
		}

		if (opts.final_state == TASK_DEAD) {
			pr_info("Enforcing tasks run after pre-dump.\n");
			opts.final_state = TASK_ALIVE;
		}

		return cr_pre_dump_tasks(tree_id);
	}

	if (!strcmp(argv[optind], "restore")) {
		if (tree_id)
			pr_warn("Using -t with criu restore is obsoleted\n");
		return cr_restore_tasks();
	}

	if (!strcmp(argv[optind], "show"))
		return cr_show(pid);

	if (!strcmp(argv[optind], "check"))
		return cr_check();

	if (!strcmp(argv[optind], "exec")) {
		if (!pid)
			pid = tree_id; /* old usage */
		if (!pid)
			goto opt_pid_missing;
		return cr_exec(pid, argv + optind + 1);
	}

	if (!strcmp(argv[optind], "page-server"))
		return cr_page_server(opts.restore_detach);

	if (!strcmp(argv[optind], "service"))
		return cr_service(opts.restore_detach);

	pr_msg("Unknown command \"%s\"\n", argv[optind]);
usage:
	pr_msg("\n"
"Usage:\n"
"  criu dump|pre-dump -t PID [<options>]\n"
"  criu restore [<options>]\n"
"  criu show (-D DIR)|(-f FILE) [<options>]\n"
"  criu check [--ms]\n"
"  criu exec -p PID <syscall-string>\n"
"  criu page-server\n"
"  criu service [<options>]\n"
"\n"
"Commands:\n"
"  dump           checkpoint a process/tree identified by pid\n"
"  pre-dump       pre-dump task(s) minimizing their frozen time\n"
"  restore        restore a process/tree\n"
"  show           show dump file(s) contents\n"
"  check          checks whether the kernel support is up-to-date\n"
"  exec           execute a system call by other task\n"
"  page-server    launch page server\n"
"  service        launch service\n"
	);

	if (argc < 2) {
		pr_msg("\nTry -h|--help for more info\n");
		return -1;
	}

	pr_msg("\n"
"Dump/Restore options:\n"
"\n"
"* Generic:\n"
"  -t|--tree PID         checkpoint a process tree identified by PID\n"
"  -d|--restore-detached detach after restore\n"
"  -s|--leave-stopped    leave tasks in stopped state after checkpoint\n"
"  -R|--leave-running    leave tasks in running state after checkpoint\n"
"  -D|--images-dir DIR   directory for image files\n"
"     --pidfile FILE     write a pid of a root task, service or page-server\n"
"                        to this file\n"
"\n"
"* Special resources support:\n"
"  -x|--" USK_EXT_PARAM "      allow external unix connections\n"
"     --" SK_EST_PARAM "  checkpoint/restore established TCP connections\n"
"  -r|--root PATH        change the root filesystem (when run in mount namespace)\n"
"  --evasive-devices     use any path to a device file if the original one\n"
"                        is inaccessible\n"
"  --veth-pair IN=OUT    map inside veth device name to outside one\n"
"  --link-remap          allow to link unlinked files back when possible\n"
"  --action-script FILE  add an external action script\n"
"  -j|--" OPT_SHELL_JOB "        allow to dump and restore shell jobs\n"
"  -l|--" OPT_FILE_LOCKS "       handle file locks, for safety, only used for container\n"
"\n"
"* Logging:\n"
"  -o|--log-file FILE    log file name (path is relative to --images-dir)\n"
"     --log-pid          enable per-process logging to separate FILE.pid files\n"
"  -v[NUM]               set logging level:\n"
"                          -v0        - messages regardless of log level\n"
"                          -v1, -v    - errors, when we are in trouble\n"
"                          -v2, -vv   - warnings (default)\n"
"                          -v3, -vvv  - informative, everything is fine\n"
"                          -v4, -vvvv - debug only\n"
"\n"
"* Memory dumping options:\n"
"  --track-mem           turn on memory changes tracker in kernel\n"
"  --prev-images-dir DIR path to images from previous dump (relative to -D)\n"
"  --page-server         send pages to page server (see options below as well)\n"
"\n"
"Page/Service server options\n"
"  --address ADDR        address of server or service\n"
"  --port PORT           port of page server\n"
"  -d|--daemon           run in the background after creating socket\n"
"\n"
"Show options:\n"
"  -f|--file FILE        show contents of a checkpoint file\n"
"  -D|--images-dir DIR   directory where to get images from\n"
"  -c|--contents         show contents of pages dumped in hexdump format\n"
"  -p|--pid PID          show files relevant to PID (filter -D flood)\n"
"\n"
"Other options:\n"
"  -h|--help             show this text\n"
"  -V|--version          show version\n"
"     --ms               don't check not yet merged kernel features\n"
	);

	return -1;

opt_pid_missing:
	pr_msg("No pid specified (-t option missing)\n");
	return -1;
}
