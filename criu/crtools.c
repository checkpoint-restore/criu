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

#include <sys/utsname.h>

#include <sys/time.h>
#include <sys/resource.h>

#include "int.h"
#include "page.h"
#include "common/compiler.h"
#include "crtools.h"
#include "cr_options.h"
#include "external.h"
#include "files.h"
#include "sk-inet.h"
#include "net.h"
#include "page-xfer.h"
#include "tty.h"
#include "file-lock.h"
#include "cr-service.h"
#include "plugin.h"
#include "criu-log.h"
#include "util.h"
#include "protobuf-desc.h"
#include "namespaces.h"
#include "cgroup.h"
#include "cpu.h"
#include "fault-injection.h"
#include "lsm.h"
#include "proc_parse.h"
#include "kerndat.h"

#include "setproctitle.h"
#include "sysctl.h"

static int early_init(void)
{
	if (init_service_fd())
		return 1;

	return 0;
}

int main(int argc, char *argv[], char *envp[])
{
	int ret = -1;
	bool usage_error = true;
	bool has_exec_cmd = false;
	bool has_sub_command;
	int state = PARSING_GLOBAL_CONF;

	BUILD_BUG_ON(CTL_32 != SYSCTL_TYPE__CTL_32);
	BUILD_BUG_ON(__CTL_STR != SYSCTL_TYPE__CTL_STR);
	/* We use it for fd overlap handling in clone_service_fd() */
	BUG_ON(get_service_fd(SERVICE_FD_MIN+1) <
	       get_service_fd(SERVICE_FD_MAX-1));

	if (fault_injection_init())
		return 1;

	cr_pb_init();
	setproctitle_init(argc, argv, envp);

	if (argc < 2)
		goto usage;

	init_opts();


	ret = parse_options(argc, argv, &usage_error, &has_exec_cmd, state);

	if (ret == 1)
		return 1;
	if (ret == 2)
		goto usage;

	log_set_loglevel(opts.log_level);

	if (early_init())
		return -1;

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

	if (opts.imgs_dir == NULL)
		SET_CHAR_OPTS(imgs_dir, ".");

	if (opts.work_dir == NULL)
		SET_CHAR_OPTS(work_dir, opts.imgs_dir);

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
		ret = open_image_dir(opts.imgs_dir);
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
		pr_warn("Stopped and detached shell job will get SIGHUP from OS.\n");

	if (chdir(opts.work_dir)) {
		pr_perror("Can't change directory to %s", opts.work_dir);
		return 1;
	}

	if (log_init(opts.output))
		return 1;

	if (kerndat_init())
		return 1;

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
		if (!opts.tree_id)
			goto opt_pid_missing;
		return cr_dump_tasks(opts.tree_id);
	}

	if (!strcmp(argv[optind], "pre-dump")) {
		if (!opts.tree_id)
			goto opt_pid_missing;

		return cr_pre_dump_tasks(opts.tree_id) != 0;
	}

	if (!strcmp(argv[optind], "restore")) {
		if (opts.tree_id)
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

	if (!strcmp(argv[optind], "lazy-pages"))
		return cr_lazy_pages(opts.daemon_mode) != 0;

	if (!strcmp(argv[optind], "check"))
		return cr_check() != 0;

	if (!strcmp(argv[optind], "page-server"))
		return cr_page_server(opts.daemon_mode, false, -1) != 0;

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
"  criu lazy-pages -D DIR [<options>]\n"
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
"  --lazy-pages          restore pages on demand\n"
"                        this requires running a second instance of criu\n"
"                        in lazy-pages mode: 'criu lazy-pages -D DIR'\n"
"                        --lazy-pages and lazy-pages mode require userfaultfd\n"
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
"  --ps-socket FD        use specified FD as page server socket\n"
"  -d|--daemon           run in the background after creating socket\n"
"  --status-fd FD        write \\0 to the FD and close it once process is ready\n"
"                        to handle requests\n"
"\n"
"Configuration file options:\n"
"  --config FILEPATH     pass a specific configuration file\n"
"  --no-default-config   forbid usage of default configuration files\n"
"\n"
"Other options:\n"
"  -h|--help             show this text\n"
"  -V|--version          show version\n"
	);

	return 0;

opt_pid_missing:
	pr_msg("Error: pid not specified\n");
	return 1;
}
