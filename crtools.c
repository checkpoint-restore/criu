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

#include "types.h"

#include "compiler.h"
#include "crtools.h"
#include "util.h"
#include "log.h"
#include "sockets.h"
#include "syscall.h"
#include "uts_ns.h"
#include "ipc_ns.h"
#include "files.h"
#include "sk-inet.h"

struct cr_options opts;

/*
 * The cr fd set is the set of files where the information
 * about dumped processes is stored. Each file carries some
 * small portion of info about the whole picture, see below
 * for more details.
 */

struct cr_fd_desc_tmpl fdset_template[CR_FD_MAX] = {

	 /* info about file descriptiors */
	[CR_FD_FDINFO] = {
		.fmt	= FMT_FNAME_FDINFO,
		.magic	= FDINFO_MAGIC,
		.show	= show_files,
	},

	/* private memory pages data */
	[CR_FD_PAGES] = {
		.fmt	= FMT_FNAME_PAGES,
		.magic	= PAGES_MAGIC,
		.show	= show_pages,
	},

	/* shared memory pages data */
	[CR_FD_SHMEM_PAGES] = {
		.fmt	= FMT_FNAME_SHMEM_PAGES,
		.magic	= PAGES_MAGIC,
		.show	= show_pages,
	},

	[CR_FD_REG_FILES] = {
		.fmt	= FMT_FNAME_REG_FILES,
		.magic	= REG_FILES_MAGIC,
		.show	= show_reg_files,
	},

	/* core data, such as regs and vmas and such */
	[CR_FD_CORE] = {
		.fmt	= FMT_FNAME_CORE,
		.magic	= CORE_MAGIC,
		.show	= show_core,
	},

	[CR_FD_MM] = {
		.fmt	= FMT_FNAME_MM,
		.magic	= MM_MAGIC,
		.show	= show_mm,
	},

	[CR_FD_VMAS] = {
		.fmt	= FMT_FNAME_VMAS,
		.magic	= VMAS_MAGIC,
		.show	= show_vmas,
	},

	/* info about pipes - fds, pipe id and pipe data */
	[CR_FD_PIPES] = {
		.fmt	= FMT_FNAME_PIPES,
		.magic	= PIPES_MAGIC,
		.show	= show_pipes,
	},

	/* info about pipes - fds, pipe id and pipe data */
	[CR_FD_PIPES_DATA] = {
		.fmt	= FMT_FNAME_PIPES_DATA,
		.magic	= PIPES_DATA_MAGIC,
		.show	= show_pipes_data,
	},

	 /* info about process linkage */
	[CR_FD_PSTREE] = {
		.fmt	= FMT_FNAME_PSTREE,
		.magic	= PSTREE_MAGIC,
		.show	= show_pstree,
	},

	/* info about signal handlers */
	[CR_FD_SIGACT] = {
		.fmt	= FMT_FNAME_SIGACTS,
		.magic	= SIGACT_MAGIC,
		.show	= show_sigacts,
	},

	/* info about unix sockets */
	[CR_FD_UNIXSK] = {
		.fmt	= FMT_FNAME_UNIXSK,
		.magic	= UNIXSK_MAGIC,
		.show	= show_unixsk,
	},

	/* info about inet sockets */
	[CR_FD_INETSK] = {
		.fmt	= FMT_FNAME_INETSK,
		.magic	= INETSK_MAGIC,
		.show	= show_inetsk,
	},

	[CR_FD_SK_QUEUES] = {
		.fmt	= FMT_FNAME_SK_QUEUES,
		.magic	= SK_QUEUES_MAGIC,
		.show	= show_sk_queues,
	},

	/* interval timers (itimers) */
	[CR_FD_ITIMERS] = {
		.fmt	= FMT_FNAME_ITIMERS,
		.magic	= ITIMERS_MAGIC,
		.show	= show_itimers,
	},

	/* creds */
	[CR_FD_CREDS] = {
		.fmt	= FMT_FNAME_CREDS,
		.magic	= CREDS_MAGIC,
		.show	= show_creds,
	},

	/* UTS namespace */
	[CR_FD_UTSNS] = {
		.fmt	= FMT_FNAME_UTSNS,
		.magic	= UTSNS_MAGIC,
		.show	= show_utsns,
	},

	/* IPC namespace variables */
	[CR_FD_IPCNS_VAR] = {
		.fmt	= FMT_FNAME_IPCNS_VAR,
		.magic	= IPCNS_VAR_MAGIC,
		.show	= show_ipc_var,
	},

	/* IPC namespace shared memory */
	[CR_FD_IPCNS_SHM] = {
		.fmt	= FMT_FNAME_IPCNS_SHM,
		.magic	= IPCNS_SHM_MAGIC,
		.show	= show_ipc_shm,
	},

	/* IPC namespace message queues */
	[CR_FD_IPCNS_MSG] = {
		.fmt	= FMT_FNAME_IPCNS_MSG,
		.magic	= IPCNS_MSG_MAGIC,
		.show	= show_ipc_msg,
	},

	/* IPC namespace semaphores sets */
	[CR_FD_IPCNS_SEM] = {
		.fmt	= FMT_FNAME_IPCNS_SEM,
		.magic	= IPCNS_SEM_MAGIC,
		.show	= show_ipc_sem,
	},

	[CR_FD_FS] = {
		.fmt	= FMT_FNAME_FS,
		.magic	= FS_MAGIC,
		.show	= show_fs,
	},

	[CR_FD_REMAP_FPATH] = {
		.fmt	= FMT_FNAME_REMAP_FPATH,
		.magic	= REMAP_FPATH_MAGIC,
		.show	= show_remap_files,
	},

	[CR_FD_GHOST_FILE] = {
		.fmt	= FMT_FNAME_GHOST_FILE,
		.magic	= GHOST_FILE_MAGIC,
		.show	= show_ghost_file,
	},

	[CR_FD_TCP_STREAM] = {
		.fmt	= FMT_FNAME_TCP_STREAM,
		.magic	= TCP_STREAM_MAGIC,
		.show	= show_tcp_stream,
	},
};

static struct cr_fdset *alloc_cr_fdset(int nr)
{
	struct cr_fdset *cr_fdset;
	unsigned int i;

	cr_fdset = xmalloc(sizeof(*cr_fdset));
	if (cr_fdset == NULL)
		return NULL;

	cr_fdset->_fds = xmalloc(nr * sizeof(int));
	if (cr_fdset->_fds == NULL) {
		xfree(cr_fdset);
		return NULL;
	}

	for (i = 0; i < nr; i++)
		cr_fdset->_fds[i] = -1;
	cr_fdset->fd_nr = nr;
	return cr_fdset;
}

static void __close_cr_fdset(struct cr_fdset *cr_fdset)
{
	unsigned int i;

	if (!cr_fdset)
		return;

	for (i = 0; i < cr_fdset->fd_nr; i++) {
		if (cr_fdset->_fds[i] == -1)
			continue;
		close_safe(&cr_fdset->_fds[i]);
		cr_fdset->_fds[i] = -1;
	}
}

void close_cr_fdset(struct cr_fdset **cr_fdset)
{
	if (!cr_fdset || !*cr_fdset)
		return;

	__close_cr_fdset(*cr_fdset);

	xfree((*cr_fdset)->_fds);
	xfree(*cr_fdset);
	*cr_fdset = NULL;
}

static struct cr_fdset *cr_fdset_open(int pid, int from, int to,
			       unsigned long flags)
{
	struct cr_fdset *fdset;
	unsigned int i;
	int ret = -1;

	fdset = alloc_cr_fdset(to - from);
	if (!fdset)
		goto err;

	from++;
	fdset->fd_off = from;
	for (i = from; i < to; i++) {
		ret = open_image(i, flags, pid);
		if (ret < 0) {
			if (!(flags & O_CREAT))
				/* caller should check himself */
				continue;
			goto err;
		}

		fdset->_fds[i - from] = ret;
	}

	return fdset;

err:
	close_cr_fdset(&fdset);
	return NULL;
}

struct cr_fdset *cr_task_fdset_open(int pid, int mode)
{
	return cr_fdset_open(pid, _CR_FD_TASK_FROM, _CR_FD_TASK_TO, mode);
}

struct cr_fdset *cr_ns_fdset_open(int pid, int mode)
{
	return cr_fdset_open(pid, _CR_FD_NS_FROM, _CR_FD_NS_TO, mode);
}

struct cr_fdset *cr_glob_fdset_open(int mode)
{
	return cr_fdset_open(-1 /* ignored */, _CR_FD_GLOB_FROM, _CR_FD_GLOB_TO, mode);
}

static int parse_ns_string(const char *ptr, unsigned int *flags)
{
	const char *end = ptr + strlen(ptr);

	do {
		if (ptr[3] != ',' && ptr[3] != '\0')
			goto bad_ns;
		if (!strncmp(ptr, "uts", 3))
			opts.namespaces_flags |= CLONE_NEWUTS;
		else if (!strncmp(ptr, "ipc", 3))
			opts.namespaces_flags |= CLONE_NEWIPC;
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
	int action = -1;
	int log_inited = 0;
	int log_level = 0;

	static const char short_opts[] = "dsf:p:t:hcD:o:n:vx";

	BUILD_BUG_ON(PAGE_SIZE != PAGE_IMAGE_SIZE);

	if (argc < 2)
		goto usage;

	action = argv[1][0];

	/* Default options */
	opts.final_state = TASK_DEAD;

	while (1) {
		static struct option long_opts[] = {
			{ "pid", required_argument, 0, 'p' },
			{ "tree", required_argument, 0, 't' },
			{ "leave-stopped", no_argument, 0, 's' },
			{ "restore-detached", no_argument, 0, 'd' },
			{ "contents", no_argument, 0, 'c' },
			{ "file", required_argument, 0, 'f' },
			{ "images-dir", required_argument, 0, 'D' },
			{ "log-file", required_argument, 0, 'o' },
			{ "namespaces", required_argument, 0, 'n' },
			{ "ext-unix-sk", no_argument, 0, 'x' },
			{ "help", no_argument, 0, 'h' },
			{ SK_EST_PARAM, no_argument, 0, 42 },
			{ "close", required_argument, 0, 43 },
			{ },
		};

		opt = getopt_long(argc - 1, argv + 1, short_opts, long_opts, &idx);
		if (opt == -1)
			break;

		switch (opt) {
		case 's':
			opts.final_state = TASK_STOPPED;
			break;
		case 'x':
			opts.ext_unix_sk = true;
			break;
		case 'p':
			pid = atoi(optarg);
			opts.leader_only = true;
			break;
		case 't':
			pid = atoi(optarg);
			opts.leader_only = false;
			break;
		case 'c':
			opts.show_pages_content	= true;
			break;
		case 'f':
			opts.show_dump_file = optarg;
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
			if (log_init(optarg))
				return -1;
			log_inited = 1;
			break;
		case 'n':
			if (parse_ns_string(optarg, &opts.namespaces_flags))
				return -1;
			break;
		case 'v':
			if (optind < argc - 1) {
				char *opt = argv[optind + 1];

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

	if (strcmp(argv[1], "dump") &&
	    strcmp(argv[1], "restore") &&
	    strcmp(argv[1], "show") &&
	    strcmp(argv[1], "check")) {
		pr_err("Unknown command");
		goto usage;
	}

	switch (action) {
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
	default:
		goto usage;
		break;
	}

	return ret;

usage:
	pr_msg("\nUsage:\n");
	pr_msg("  %s dump -p|-t pid [<options>]\n", argv[0]);
	pr_msg("  %s restore -p|-t pid [<options>]\n", argv[0]);
	pr_msg("  %s show (-D dir)|(-f file) [<options>]\n", argv[0]);
	pr_msg("  %s check\n", argv[0]);

	pr_msg("\nCommands:\n");
	pr_msg("  dump           checkpoint a process/tree identified by pid\n");
	pr_msg("  restore        restore a process/tree identified by pid\n");
	pr_msg("  show           show dump file(s) contents\n");
	pr_msg("  check          checks whether the kernel support is up-to-date\n");

	pr_msg("\nDump/Restore options:\n");

	pr_msg("\n* Generic:\n");
	pr_msg("  -p|--pid              checkpoint/restore only a single process identified by pid\n");
	pr_msg("  -t|--tree             checkpoint/restore the whole process tree identified by pid\n");
	pr_msg("  -d|--restore-detached detach after restore\n");
	pr_msg("  -s|--leave-stopped    leave tasks in stopped state after checkpoint instead of killing them\n");
	pr_msg("  -D|--images-dir       directory where to put images to\n");

	pr_msg("\n* Special resources support:\n");
	pr_msg("  -n|--namespaces       checkpoint/restore namespaces - values must be separated by comma\n");
	pr_msg("                        supported: uts, ipc\n");
	pr_msg("  -x|--ext-unix-sk      allow external unix connections\n");
	pr_msg("     --%s  checkpoint/restore established TCP connections\n", SK_EST_PARAM);

	pr_msg("\n* Logging:\n");
	pr_msg("  -o|--log-file         log file name (relative path is relative to --images-dir)\n");
	pr_msg("  -v [num]              set logging level\n");
	pr_msg("                          0 - silent (only error messages)\n");
	pr_msg("                          1 - informative (default)\n");
	pr_msg("                          2 - debug\n");
	pr_msg("  -vv            same as -v 1\n");
	pr_msg("  -vvv           same as -v 2\n");

	pr_msg("\nShow options:\n");
	pr_msg("  -f|--file             show contents of a checkpoint file\n");
	pr_msg("  -D|--images-dir       directory where to get images from\n");
	pr_msg("  -c|--contents         show contents of pages dumped in hexdump format\n");

	return -1;

opt_pid_missing:
	pr_msg("No pid specified (-t or -p option missing)\n");
	return -1;
}
