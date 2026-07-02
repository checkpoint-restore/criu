/*
 * CLONE Phase 2/3 - Phased migration page handling
 *
 * Phase 2: Buffer pages from the source before the skeleton dump exists
 * Phase 3: After dirty bitmap arrives, start restore with buffered pages
 *
 * Entry point: cr_clone_receive() (criu clone-receive command)
 */

#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>
#include <signal.h>
#include <limits.h>
#include <spawn.h>

#include "types.h"
#include "cr_options.h"
#include "criu-log.h"
#include "page-xfer.h"
#include "util.h"
#include "xmalloc.h"
#include "common/list.h"
#include "servicefd.h"
#include "uffd.h"
#include "clone/clone-uffd.h"
#include "clone/clone-bulk-send.h"
#include "clone/clone-bulk-recv.h"
#include "clone/clone-page-xfer.h"
#include "pstree.h"
#include "clone/pf-tracker.h"
#include "clone/unmapped-tracker.h"
#include "rst_info.h"
#include "clone/clone-phase2.h"
#include "clone/clone-conf.h"
#include "common/bug.h"

#undef LOG_PREFIX
#define LOG_PREFIX "clone-phase2: "

/* List of discovered task PIDs from pagemap files */
struct clone_task {
	int pid;
	struct list_head l;
};

static LIST_HEAD(clone_tasks);
static int nr_clone_tasks;

/*
 * Discover tasks by scanning for pagemap-*.img files in images directory.
 * Returns 0 on success, -1 on error.
 */
static int discover_tasks_from_pagemaps(void)
{
	DIR *dir;
	struct dirent *de;
	int img_dir_fd;

	if (opts.tree_id) {
		struct clone_task *ct = xmalloc(sizeof(*ct));
		BUG_ON(!ct);
		ct->pid = opts.tree_id;
		list_add_tail(&ct->l, &clone_tasks);
		nr_clone_tasks = 1;
		pr_info("Using task pid=%d from --tree option\n", opts.tree_id);
		return 0;
	}

	img_dir_fd = get_service_fd(IMG_FD_OFF);
	if (img_dir_fd < 0) {
		pr_err("No image directory fd\n");
		return -1;
	}

	dir = fdopendir(dup(img_dir_fd));
	if (!dir) {
		pr_perror("Cannot open images directory");
		return -1;
	}

	while ((de = readdir(dir)) != NULL) {
		int pid;
		struct clone_task *ct;

		/* Look for pagemap-NNNN.img files */
		if (strncmp(de->d_name, "pagemap-", 8) != 0)
			continue;
		if (sscanf(de->d_name, "pagemap-%d.img", &pid) != 1)
			continue;

		ct = xmalloc(sizeof(*ct));
		BUG_ON(!ct);

		ct->pid = pid;
		list_add_tail(&ct->l, &clone_tasks);
		nr_clone_tasks++;
		pr_info("Discovered task pid=%d from %s\n", pid, de->d_name);
	}

	closedir(dir);

	if (nr_clone_tasks == 0) {
		pr_err("No pagemap files found in images directory\n");
		return -1;
	}

	pr_info("Discovered %d tasks from pagemap files\n", nr_clone_tasks);
	return 0;
}

static void free_clone_tasks(void)
{
	struct clone_task *ct, *tmp;

	list_for_each_entry_safe(ct, tmp, &clone_tasks, l) {
		list_del(&ct->l);
		xfree(ct);
	}
	nr_clone_tasks = 0;
}

extern char **environ;

static pid_t clone_start_restore(void)
{
	pid_t pid;
	char log_path[PATH_MAX];
	char log_level[8];
	int ret;
	char *argv[16];

	snprintf(log_path, sizeof(log_path), "%s/clone-restore.log", opts.imgs_dir);
	snprintf(log_level, sizeof(log_level), "-v%d", opts.log_level);

	pr_info("Starting restore: log_level=%d, log_level_str=%s, log_path=%s\n",
		opts.log_level, log_level, log_path);

	argv[0] = opts.argv_0;
	argv[1] = "restore";
	argv[2] = "--images-dir";
	argv[3] = opts.imgs_dir;
	argv[4] = "--tcp-close";
	argv[5] = "--clone-dump";
	argv[6] = "--restore-detached";
	argv[7] = "--skip-file-rwx-check";
	argv[8] = "--skip-file-size-check";
	argv[9] = "--file-validation";
	argv[10] = "filesize";
	argv[11] = log_level;
	argv[12] = "-o";
	argv[13] = log_path;
	argv[14] = NULL;

	ret = posix_spawn(&pid, opts.argv_0, NULL, NULL, argv, environ);
	if (ret != 0) {
		pr_err("posix_spawn of criu restore failed: %s\n", strerror(ret));
		return -1;
	}

	pr_info("Started criu restore (PID: %d)\n", pid);
	return pid;
}

/*
 * criu clone-receive entry point.
 */
int cr_clone_receive(bool daemon)
{
	/* clone-receive implies page-server mode */
	opts.use_page_server = true;

	return cr_clone_phase2(daemon);
}

/*
 * CLONE Phase 2/3 entry point (internal).
 *
 * Phase 2:
 *   1. Discovers tasks from pagemap files (no pstree needed)
 *   2. Connects to page server, buffers all pages
 *   3. Waits for dirty bitmap (signals Phase 3 skeleton dump ready)
 *
 * Phase 3:
 *   4. Now inventory.img exists - call prepare_dummy_pstree()
 *   5. Start restore with buffered pages
 *   6. Handle page faults (WP_SYNC convergence)
 */
int cr_clone_phase2(bool daemon)
{
	struct epoll_event *events = NULL;
	struct clone_task *ct;
	int epollfd;
	int ret = -1;
	int nr_fds;

	pr_info("clone-receive: Phase 2 (page buffering)\n");

	/* 1. Discover tasks from pagemap files */
	if (discover_tasks_from_pagemaps())
		return -1;

	/* 2. Initialize CLONE page buffer (thread-safe version in clone-uffd.c) */
	if (clone_page_buffer_init()) {
		pr_err("Failed to initialize page buffer\n");
		goto err_tasks;
	}

	/* Initialize page state tracker */
	BUG_ON(page_state_init());

	/* Initialize hung page tracker */
	BUG_ON(pf_tracker_init());

	/* Initialize unmapped pages tracker */
	BUG_ON(unmapped_tracker_init());

	/* 3. Daemonize if requested */
	if (daemon) {
		ret = cr_daemon(1, 0, -1);
		if (ret == -1) {
			pr_err("Can't run in the background\n");
			goto err_tasks;
		}
		if (ret > 0) {
			/* Parent - daemon started successfully */
			if (opts.pidfile) {
				if (write_pidfile(ret) == -1) {
					pr_perror("Can't write pidfile");
					kill(ret, SIGKILL);
					waitpid(ret, NULL, 0);
					goto err_tasks;
				}
			}
			return 0;
		}
		/* Child continues */
	}

	/* 4. Set up epoll with fixed large buffer */
	nr_fds = CLONE_MAX_EPOLL_FDS;
	epollfd = epoll_prepare(nr_fds, &events);
	if (epollfd < 0)
		goto err_tasks;

	/* 5. Connect to page server */
	if (connect_to_page_server_to_recv(epollfd)) {
		pr_err("Failed to connect to page server\n");
		goto err_epoll;
	}

	/* 6. Set up async bulk reader (uses prebuffer_io_complete in uffd.c) */
	if (clone_setup_prebuffer_reader()) {
		pr_err("Failed to setup prebuffer reader\n");
		goto err_disconnect;
	}

	/* 7. Request all pages for each discovered task */
	list_for_each_entry(ct, &clone_tasks, l) {
		pr_info("Requesting all pages for pid=%d\n", ct->pid);
		if (clone_request_all_remote_pages(ct->pid) < 0) {
			pr_err("Failed to request pages for pid=%d\n", ct->pid);
			goto err_disconnect;
		}
	}

	/*
	 * 7b. Create P3 parallel connections AFTER sending page requests.
	 * The source is now in unified_page_server_thread and ready to accept.
	 */
	if (start_p3_receiver_connections(clone_cfg.num_p3_threads) > 0) {
		pr_info("P3 parallel receiver enabled\n");
	}

	pr_info("Waiting to receive pages from source...\n");

	/* 8. Phase 2 event loop - buffer pages until dirty bitmap arrives */
	ret = clone_phase2_handle_pages(epollfd, events, nr_fds);
	if (ret < 0) {
		pr_err("Phase 2 failed\n");
		goto err_disconnect;
	}

	pr_info("clone-receive: starting restore\n");

	/*
	 * All pages received, source closed connection.
	 * No reconnect needed - serve everything from buffer.
	 * Remove page server fd from epoll to avoid hangup events.
	 */
	stop_p3_receiver_connections();
	remove_page_server_from_epoll(epollfd);

	/*
	 * Now inventory.img and pstree.img exist on disk.
	 * The all_pages_sent signal indicates all pages are sent
	 * and skeleton dump is complete.
	 */
	if (!clone_is_all_pages_sent_received()) {
		pr_err("Completion signal (all_pages_sent) not received!\n");
		goto err_disconnect;
	}

	if (prepare_dummy_pstree()) {
		pr_err("Failed to prepare pstree\n");
		goto err_disconnect;
	}

	pr_info("Pstree loaded, ready to accept restore connection\n");

	/*
	 * Verify nr_fds fits in our fixed buffer.
	 * Fds: task uffd (nr_tasks) + restore listen + restore client = nr_tasks + 2
	 */
	BUG_ON(task_entries->nr_tasks + 2 > CLONE_MAX_EPOLL_FDS);

	if (clone_start_restore() < 0)
		goto err_disconnect;

	ret = clone_phase3_restore_loop(epollfd, &events, nr_fds);
	if (ret < 0)
		pr_err("Phase 3 restore loop failed\n");

err_disconnect:
	stop_p3_receiver_connections();
	pf_tracker_destroy();
	page_state_verify_all_terminal();
	page_state_destroy();
err_epoll:
	xfree(events);
err_tasks:
	free_clone_tasks();
	return ret;
}

/*
 * Phase 2 event loop - receive pages until dirty bitmap arrives.
 * Dirty bitmap signals that Phase 3 skeleton dump is complete.
 */
int clone_phase2_handle_pages(int epollfd, struct epoll_event *events, int nr_fds)
{
	int ret;

	while (1) {
		ret = epoll_run_rfds(epollfd, events, nr_fds, -1);
		if (ret < 0) {
			pr_err("epoll_run_rfds failed\n");
			return -1;
		}


		/* All pages sent = completion signal, ready for restore */
		if (clone_is_all_pages_sent_received()) {
			pr_debug("Completion signal received, ready for restore\n");
			BUG_ON(send_all_pages_sent_ack() < 0);
			/* Clean up async bulk reader before socket is closed */
			page_server_cleanup_async_bulk();
			return 0;
		}
	}

	return 0;
}
