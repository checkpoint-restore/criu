#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <termios.h>
#include <string.h>
#include <sys/wait.h>
#include <criu/criu.h>

enum action {
	ACT_DUMP,
	ACT_PRE_DUMP,
	ACT_RESTORE
};

static struct option long_opts[] = {
	{ "tree", required_argument, 0, 't' },
	{ "images-dir", required_argument, 0, 'D' },
	{ "prev-images-dir", required_argument, 0, 7 },
	{ "shell-job", no_argument, 0, 'j' },
	{ "leave-running", no_argument, 0, 'R' },
	{ "tcp-established", no_argument, 0, 1 },
	{ "tcp-close", no_argument, 0, 6 },
	{ "ext-unix-sk", no_argument, 0, 'x' },
	{ "file-locks", no_argument, 0, 'l' },
	{ "manage-cgroups", no_argument, 0, 2 },
	{ "track-mem", no_argument, 0, 3 },
	{ "auto-dedup", no_argument, 0, 4 },
	{ "log-file", required_argument, 0, 'o' },
	{ "verbosity", optional_argument, 0, 'v' },
	{ "service-address", required_argument, 0, 5 },
	{ "help", no_argument, 0, 'h' },
	{ 0, 0, 0, 0 }
};

static void print_usage(FILE *out)
{
	fprintf(out, "Usage: criu-service-client <dump|pre-dump|restore> [OPTIONS]\n\n");
	fprintf(out, "Options:\n");
	fprintf(out, "  -t, --tree <PID>              Target PID to checkpoint (dump/pre-dump only)\n");
	fprintf(out, "  -D, --images-dir <DIR>        Directory to store/load checkpoint images\n");
	fprintf(out, "      --prev-images-dir <DIR>   Path to parent images from a previous dump\n");
	fprintf(out, "  -j, --shell-job               Allow dumping processes with TTY\n");
	fprintf(out, "  -R, --leave-running           Leave the process running after dump\n");
	fprintf(out, "      --tcp-established         Dump established TCP connections\n");
	fprintf(out, "      --tcp-close               Close TCP connections on restore\n");
	fprintf(out, "  -x, --ext-unix-sk             Dump external Unix sockets\n");
	fprintf(out, "  -l, --file-locks              Dump file locks\n");
	fprintf(out, "      --manage-cgroups          Manage cgroups\n");
	fprintf(out, "      --track-mem               Track memory changes\n");
	fprintf(out, "      --auto-dedup              Deduplicate memory pages automatically\n");
	fprintf(out, "  -o, --log-file <FILE>         Log file path (default: criu.log)\n");
	fprintf(out, "  -v[N], --verbosity[=N]        Log level 0-4 (default: 2); -v raises by 1\n");
	fprintf(out, "      --service-address <SOCK>  CRIU service Unix socket path\n");
	fprintf(out, "  -h, --help                    Show this help message\n");
}

static void print_criu_error(const char *op, int ret)
{
	const char *msg;

	switch (ret) {
	case -EBADE:
		msg = "RPC returned failure (check the CRIU log)";
		break;
	case -ECONNREFUSED:
		msg = "Unable to connect to CRIU service";
		break;
	case -ECOMM:
		msg = "Unable to send/recv message to/from CRIU";
		break;
	case -EINVAL:
		msg = "CRIU rejected the request (bad sequence or unsupported request type)";
		break;
	case -EBADMSG:
		msg = "Unexpected response from CRIU (consider updating CRIU)";
		break;
	default:
		msg = "Unknown error";
		break;
	}

	if (errno)
		fprintf(stderr, "CRIU %s failed: %s (ret=%d, errno=%d: %s)\n",
			op, msg, ret, errno, strerror(errno));
	else
		fprintf(stderr, "CRIU %s failed: %s (ret=%d)\n",
			op, msg, ret);
}

static int parse_int(const char *str, const char *name, int *val)
{
	char *end;
	long v;

	errno = 0;
	v = strtol(str, &end, 10);
	if (errno || *end != '\0' || end == str || v < INT_MIN || v > INT_MAX) {
		fprintf(stderr, "Invalid value for %s: '%s'\n", name, str);
		return -1;
	}

	*val = (int)v;
	return 0;
}

int main(int argc, char *argv[])
{
	enum action action;
	int opt, option_index = 0;
	int pid = -1;
	const char *images_dir = NULL;
	const char *prev_images_dir = NULL;
	const char *log_file = "criu.log";
	int log_level = CRIU_LOG_WARN;
	const char *service_socket = NULL;
	int dirfd = -1;
	int ret = 1;

	bool shell_job = false;
	bool leave_running = false;
	bool tcp_established = false;
	bool tcp_close = false;
	bool ext_unix_sk = false;
	bool file_locks = false;
	bool manage_cgroups = false;
	bool track_mem = false;
	bool auto_dedup = false;

	if (argc < 2) {
		print_usage(stderr);
		return 1;
	}

	if (strcmp(argv[1], "dump") == 0) {
		action = ACT_DUMP;
	} else if (strcmp(argv[1], "pre-dump") == 0) {
		action = ACT_PRE_DUMP;
	} else if (strcmp(argv[1], "restore") == 0) {
		action = ACT_RESTORE;
	} else if (strcmp(argv[1], "help") == 0 || strcmp(argv[1], "--help") == 0) {
		print_usage(stdout);
		return 0;
	} else {
		fprintf(stderr, "Unknown command '%s'; expected dump, pre-dump, restore, or help\n",
			argv[1]);
		return 1;
	}

	/* Skip the subcommand so getopt_long() only sees the options. */
	argc--;
	argv++;

	while ((opt = getopt_long(argc, argv, "t:D:jRxlo:v::h", long_opts,
				  &option_index)) != -1) {
		switch (opt) {
		case 't':
			if (parse_int(optarg, "tree", &pid))
				return 1;
			if (pid <= 0) {
				fprintf(stderr, "PID must be positive\n");
				return 1;
			}
			break;
		case 'D':
			images_dir = optarg;
			break;
		case 'j':
			shell_job = true;
			break;
		case 'R':
			leave_running = true;
			break;
		case 1:
			tcp_established = true;
			break;
		case 6:
			tcp_close = true;
			break;
		case 'x':
			ext_unix_sk = true;
			break;
		case 'l':
			file_locks = true;
			break;
		case 2:
			manage_cgroups = true;
			break;
		case 3:
			track_mem = true;
			break;
		case 4:
			auto_dedup = true;
			break;
		case 7:
			prev_images_dir = optarg;
			break;
		case 'o':
			log_file = optarg;
			break;
		case 'v':
			if (optarg) {
				if (optarg[0] == 'v')
					log_level += strlen(optarg) + 1;
				else if (parse_int(optarg, "verbosity", &log_level))
					return 1;
			} else {
				log_level++;
			}
			break;
		case 5:
			service_socket = optarg;
			break;
		case 'h':
			print_usage(stdout);
			return 0;
		default:
			print_usage(stderr);
			return 1;
		}
	}

	if (!images_dir) {
		fprintf(stderr, "Images directory required (-D)\n");
		return 1;
	}

	if (action != ACT_RESTORE && pid <= 0) {
		fprintf(stderr, "%s requires -t <pid>\n",
			action == ACT_DUMP ? "Dump" : "Pre-dump");
		return 1;
	}

	if (log_level < CRIU_LOG_MSG || log_level > CRIU_LOG_DEBUG) {
		fprintf(stderr, "Verbosity must be in the range 0-4\n");
		return 1;
	}

	if (criu_init_opts() < 0) {
		perror("criu_init_opts");
		return 1;
	}

	if (service_socket && criu_set_service_address(service_socket)) {
		perror("criu_set_service_address");
		goto out;
	}

	dirfd = open(images_dir, O_RDONLY | O_DIRECTORY);
	if (dirfd < 0) {
		fprintf(stderr, "Failed to open images dir '%s': %s\n",
			images_dir, strerror(errno));
		goto out;
	}

	criu_set_images_dir_fd(dirfd);
	if (prev_images_dir && criu_set_parent_images(prev_images_dir)) {
		perror("criu_set_parent_images");
		goto out;
	}
	if (criu_set_log_file(log_file)) {
		perror("criu_set_log_file");
		goto out;
	}
	criu_set_log_level(log_level);

	if (shell_job)
		criu_set_shell_job(true);
	if (leave_running)
		criu_set_leave_running(true);
	if (tcp_established)
		criu_set_tcp_established(true);
	if (tcp_close)
		criu_set_tcp_close(true);
	if (ext_unix_sk)
		criu_set_ext_unix_sk(true);
	if (file_locks)
		criu_set_file_locks(true);
	if (manage_cgroups)
		criu_set_manage_cgroups(true);
	if (track_mem)
		criu_set_track_mem(true);
	if (auto_dedup)
		criu_set_auto_dedup(true);

	switch (action) {
	case ACT_PRE_DUMP:
		criu_set_pid(pid);
		fprintf(stderr, "Pre-dumping PID %d to '%s'\n", pid, images_dir);
		ret = criu_pre_dump();
		break;
	case ACT_DUMP:
		criu_set_pid(pid);
		fprintf(stderr, "Dumping PID %d to '%s'\n", pid, images_dir);
		ret = criu_dump();
		break;
	case ACT_RESTORE:
		fprintf(stderr, "Restoring from '%s'\n", images_dir);
		ret = criu_restore_child();
		if (ret <= 0)
			break;

		pid = ret;
		ret = 0;

		/*
		 * When the restored process shares our session and
		 * stdin is a terminal, hand the terminal over to the
		 * restored process so it can read input and receive
		 * signals (Ctrl-C, etc.). We temporarily ignore
		 * SIGTTOU because tcsetpgrp() would otherwise stop
		 * this process since it is no longer in the foreground.
		 *
		 * Skip this when the restored process lives in a
		 * different session since tcsetpgrp() only works
		 * within the same session.
		 */
		if (shell_job && isatty(STDIN_FILENO) &&
		    getsid(pid) == getsid(0)) {
			struct sigaction sa, old_sa;
			pid_t pgrp;

			pgrp = getpgid(pid);
			if (pgrp < 0) {
				perror("getpgid");
				ret = 1;
				goto out;
			}

			sa.sa_handler = SIG_IGN;
			sigemptyset(&sa.sa_mask);
			sa.sa_flags = 0;
			if (sigaction(SIGTTOU, &sa, &old_sa) < 0) {
				perror("sigaction");
				ret = 1;
				goto out;
			}

			if (tcsetpgrp(STDIN_FILENO, pgrp) < 0)
				perror("tcsetpgrp");

			sigaction(SIGTTOU, &old_sa, NULL);
		}

		if (waitpid(pid, &ret, 0) < 0) {
			perror("waitpid");
			ret = 1;
			goto out;
		}

		if (WIFEXITED(ret))
			ret = WEXITSTATUS(ret);
		else if (WIFSIGNALED(ret))
			ret = 128 + WTERMSIG(ret);
		else
			ret = 1;
		goto out;
	}

	if (ret < 0) {
		const char *names[] = {
			[ACT_DUMP] = "dump",
			[ACT_PRE_DUMP] = "pre-dump",
			[ACT_RESTORE] = "restore",
		};

		print_criu_error(names[action], ret);
		ret = 1;
		goto out;
	}

	ret = 0;
out:
	if (dirfd >= 0)
		close(dirfd);
	return ret;
}
