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

static struct cr_options opts;
struct page_entry zero_page_entry;

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
	},

	/* private memory pages data */
	[CR_FD_PAGES] = {
		.fmt	= FMT_FNAME_PAGES,
		.magic	= PAGES_MAGIC,
	},

	/* shared memory pages data */
	[CR_FD_PAGES_SHMEM] = {
		.fmt	= FMT_FNAME_PAGES_SHMEM,
		.magic	= PAGES_MAGIC,
	},

	/* core data, such as regs and vmas and such */
	[CR_FD_CORE] = {
		.fmt	= FMT_FNAME_CORE,
		.magic	= CORE_MAGIC,
	},

	/* info about pipes - fds, pipe id and pipe data */
	[CR_FD_PIPES] = {
		.fmt	= FMT_FNAME_PIPES,
		.magic	= PIPES_MAGIC,
	},

	 /* info about process linkage */
	[CR_FD_PSTREE] = {
		.fmt	= FMT_FNAME_PSTREE,
		.magic	= PSTREE_MAGIC,
	},

	/* info about which memory areas are shared */
	[CR_FD_SHMEM] = {
		.fmt	= FMT_FNAME_SHMEM,
		.magic	= SHMEM_MAGIC,
	},

	/* info about signal handlers */
	[CR_FD_SIGACT] = {
		.fmt	= FMT_FNAME_SIGACTS,
		.magic	= SIGACT_MAGIC,
	},

	/* info about unix sockets */
	[CR_FD_UNIXSK] = {
		.fmt	= FMT_FNAME_UNIXSK,
		.magic	= UNIXSK_MAGIC,
	},

	/* info about inet sockets */
	[CR_FD_INETSK] = {
		.fmt	= FMT_FNAME_INETSK,
		.magic	= INETSK_MAGIC,
	},

	[CR_FD_SK_QUEUES] = {
		.fmt	= FMT_FNAME_SK_QUEUES,
		.magic	= SK_QUEUES_MAGIC,
	},

	/* interval timers (itimers) */
	[CR_FD_ITIMERS] = {
		.fmt	= FMT_FNAME_ITIMERS,
		.magic	= ITIMERS_MAGIC,
	},

	/* creds */
	[CR_FD_CREDS] = {
		.fmt	= FMT_FNAME_CREDS,
		.magic	= CREDS_MAGIC,
	},

	/* UTS namespace */
	[CR_FD_UTSNS] = {
		.fmt	= FMT_FNAME_UTSNS,
		.magic	= UTSNS_MAGIC,
	},

	/* IPC namespace variables */
	[CR_FD_IPCNS_VAR] = {
		.fmt	= FMT_FNAME_IPCNS_VAR,
		.magic	= IPCNS_VAR_MAGIC,
	},

	/* IPC namespace shared memory */
	[CR_FD_IPCNS_SHM] = {
		.fmt	= FMT_FNAME_IPCNS_SHM,
		.magic	= IPCNS_SHM_MAGIC,
	},

	/* IPC namespace message queues */
	[CR_FD_IPCNS_MSG] = {
		.fmt	= FMT_FNAME_IPCNS_MSG,
		.magic	= IPCNS_MSG_MAGIC,
	},

	/* IPC namespace semaphores sets */
	[CR_FD_IPCNS_SEM] = {
		.fmt	= FMT_FNAME_IPCNS_SEM,
		.magic	= IPCNS_SEM_MAGIC,
	},
};

static struct cr_fdset *alloc_cr_fdset(void)
{
	struct cr_fdset *cr_fdset;
	unsigned int i;

	cr_fdset = xmalloc(sizeof(*cr_fdset));
	if (cr_fdset)
		for (i = 0; i < CR_FD_PID_MAX; i++)
			cr_fdset->fds[i] = -1;
	return cr_fdset;
}

void __close_cr_fdset(struct cr_fdset *cr_fdset)
{
	unsigned int i;

	if (!cr_fdset)
		return;

	for (i = 0; i < CR_FD_PID_MAX; i++) {
		if (cr_fdset->fds[i] == -1)
			continue;
		close_safe(&cr_fdset->fds[i]);
		cr_fdset->fds[i] = -1;
	}
}

void close_cr_fdset(struct cr_fdset **cr_fdset)
{
	if (!cr_fdset || !*cr_fdset)
		return;

	__close_cr_fdset(*cr_fdset);

	xfree(*cr_fdset);
	*cr_fdset = NULL;
}

static struct cr_fdset *cr_fdset_open(int pid, unsigned long use_mask,
			       unsigned long flags, struct cr_fdset *cr_fdset)
{
	struct cr_fdset *fdset;
	unsigned int i;
	int ret = -1;

	/*
	 * We either reuse existing fdset or create new one.
	 */
	if (!cr_fdset) {
		fdset = alloc_cr_fdset();
		if (!fdset)
			goto err;
	} else
		fdset = cr_fdset;

	for (i = 0; i < CR_FD_PID_MAX; i++) {
		if (!(use_mask & CR_FD_DESC_USE(i)))
			continue;

		if (fdset->fds[i] != -1)
			continue;

		ret = open_image(i, flags, pid);
		if (ret < 0) {
			if (!(flags & O_CREAT))
				/* caller should check himself */
				continue;
			goto err;
		}

		fdset->fds[i] = ret;
	}

	return fdset;

err:
	if (fdset != cr_fdset)
		__close_cr_fdset(fdset);
	else
		close_cr_fdset(&fdset);
	return NULL;
}

struct cr_fdset *cr_dump_fdset_open(int pid, unsigned long use_mask,
				     struct cr_fdset *cr_fdset)
{
	return cr_fdset_open(pid, use_mask, O_RDWR | O_CREAT | O_EXCL,
			     cr_fdset);
}

struct cr_fdset *cr_show_fdset_open(int pid, unsigned long use_mask)
{
	return cr_fdset_open(pid, use_mask, O_RDONLY, NULL);
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

	static const char short_opts[] = "dsf:p:t:hcD:o:n:v";

	BUILD_BUG_ON(PAGE_SIZE != PAGE_IMAGE_SIZE);

	if (argc < 2)
		goto usage;

	action = argv[1][0];

	memzero_p(&zero_page_entry);

	/* Default options */
	opts.final_state = TASK_DEAD;

	for (opt = getopt_long(argc - 1, argv + 1, short_opts, NULL, &idx); opt != -1;
	     opt = getopt_long(argc - 1, argv + 1, short_opts, NULL, &idx)) {
		switch (opt) {
		case 's':
			opts.final_state = TASK_STOPPED;
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

	if (!pid && (action != 'c') && (action != 's' || !opts.show_dump_file))
		goto opt_pid_missing;

	if (strcmp(argv[1], "dump") &&
	    strcmp(argv[1], "restore") &&
	    strcmp(argv[1], "show") &&
	    strcmp(argv[1], "check")) {
		pr_err("Unknown command");
		goto usage;
	}

	switch (action) {
	case 'd':
		ret = cr_dump_tasks(pid, &opts);
		break;
	case 'r':
		ret = cr_restore_tasks(pid, &opts);
		break;
	case 's':
		ret = cr_show(pid, &opts);
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
	pr_msg("  %s dump [-c] -p|-t pid [-n ns]\n", argv[0]);
	pr_msg("  %s restore -p|-t pid [-n ns]\n", argv[0]);
	pr_msg("  %s show [-c] (-p|-t pid)|(-f file)\n", argv[0]);
	pr_msg("  %s check\n", argv[0]);

	pr_msg("\nCommands:\n");
	pr_msg("  dump           checkpoint a process identified by pid\n");
	pr_msg("  restore        restore a process identified by pid\n");
	pr_msg("  show           show dump contents of a process identified by pid\n");
	pr_msg("  check          checks whether the kernel support is up-to-date\n");
	pr_msg("\nGeneral parameters:\n");
	pr_msg("  -p             checkpoint/restore only a single process identified by pid\n");
	pr_msg("  -t             checkpoint/restore the whole process tree identified by pid\n");
	pr_msg("  -f             show contents of a checkpoint file\n");
	pr_msg("  -c             show contents of pages dumped in hexdump format\n");
	pr_msg("  -d             detach after restore\n");
	pr_msg("  -s             leave tasks in stopped state after checkpoint instead of killing them\n");
	pr_msg("  -n             checkpoint/restore namespaces - values must be separated by comma\n");
	pr_msg("                 supported: uts, ipc\n");

	pr_msg("\nAdditional common parameters:\n");
	pr_msg("  -D dir         save checkpoint files in specified directory\n");
	pr_msg("  -v [num]       set logging level\n");
	pr_msg("                 0 - silent (only error messages)\n");
	pr_msg("                 1 - informative (default)\n");
	pr_msg("                 2 - debug\n");
	pr_msg("  -vv            same as -v 1\n");
	pr_msg("  -vvv           same as -v 2\n");
	pr_msg("\n");

	return -1;

opt_pid_missing:
	pr_msg("No pid specified (-t or -p option missing)\n");
	return -1;
}
