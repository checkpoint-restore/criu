#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>

#include "int.h"
#include "common/compiler.h"
#include "cr_options.h"
#include "cr-errno.h"
#include "pstree.h"
#include "criu-log.h"
#include <compel/ptrace.h>
#include "plugin.h"
#include "proc_parse.h"
#include "seccomp.h"
#include "seize.h"
#include "stats.h"
#include "string.h"
#include "xmalloc.h"
#include "util.h"

static bool compel_interrupt_only_mode;

/*
 * Disables the use of freeze cgroups for process seizing, even if explicitly
 * requested via the --freeze-cgroup option or already set in a frozen state.
 * This is necessary for plugins (e.g., CUDA) that do not function correctly
 * when processes are frozen using cgroups.
 */
void __attribute__((used)) set_compel_interrupt_only_mode(void)
{
	compel_interrupt_only_mode = true;
}

char *task_comm_info(pid_t pid, char *comm, size_t size)
{
	bool is_read = false;

	if (!pr_quelled(LOG_INFO)) {
		int saved_errno = errno;
		char path[32];
		int fd;

		snprintf(path, sizeof(path), "/proc/%d/comm", pid);
		fd = open(path, O_RDONLY);
		if (fd >= 0) {
			ssize_t n = read(fd, comm, size);
			if (n > 0) {
				is_read = true;
				/* Replace '\n' printed by kernel with '\0' */
				comm[n - 1] = '\0';
			} else {
				pr_warn("Failed to read %s: %s\n", path, strerror(errno));
			}
			close(fd);
		} else {
			pr_warn("Failed to open %s: %s\n", path, strerror(errno));
		}
		errno = saved_errno;
	}

	if (!is_read)
		comm[0] = '\0';

	return comm;
}

/*
 * NOTE: Don't run simultaneously, it uses local static buffer!
 */
char *__task_comm_info(pid_t pid)
{
	static char comm[32];

	return task_comm_info(pid, comm, sizeof(comm));
}

#define NR_ATTEMPTS 5

static const char frozen[] = "FROZEN";
static const char freezing[] = "FREEZING";
static const char thawed[] = "THAWED";

enum freezer_state { FREEZER_ERROR = -1,
		     THAWED,
		     FROZEN,
		     FREEZING };

/* Track if we are running on cgroup v2 system. */
static bool cgroup_v2 = false;

static enum freezer_state get_freezer_v1_state(int fd)
{
	char state[32];
	int ret;

	BUILD_BUG_ON((sizeof(state) < sizeof(frozen)) || (sizeof(state) < sizeof(freezing)) ||
		     (sizeof(state) < sizeof(thawed)));

	lseek(fd, 0, SEEK_SET);
	ret = read(fd, state, sizeof(state) - 1);
	if (ret <= 0) {
		pr_perror("Unable to get a current state");
		goto err;
	}
	if (state[ret - 1] == '\n')
		state[ret - 1] = 0;
	else
		state[ret] = 0;

	pr_debug("freezer.state=%s\n", state);
	if (strcmp(state, frozen) == 0)
		return FROZEN;
	else if (strcmp(state, freezing) == 0)
		return FREEZING;
	else if (strcmp(state, thawed) == 0)
		return THAWED;

	pr_err("Unknown freezer state: %s\n", state);
err:
	return FREEZER_ERROR;
}

static enum freezer_state get_freezer_v2_state(int fd)
{
	int exit_code = FREEZER_ERROR;
	char path[PATH_MAX];
	FILE *event;
	char state;
	int ret;

	/*
	 * cgroupv2 freezer uses cgroup.freeze to control the state. The file
	 * can return 0 or 1. 1 means the cgroup is frozen; 0 means it is not
	 * frozen. Writing 1 to an unfrozen cgroup can freeze it. Freezing can
	 * take some time and if the cgroup has finished freezing can be
	 * seen in cgroup.events: frozen 0|1.
	 */

	ret = lseek(fd, 0, SEEK_SET);
	if (ret < 0) {
		pr_perror("Unable to seek freezer FD");
		goto out;
	}
	ret = read(fd, &state, 1);
	if (ret <= 0) {
		pr_perror("Unable to read from freezer FD");
		goto out;
	}
	pr_debug("cgroup.freeze=%c\n", state);
	if (state == '0') {
		exit_code = THAWED;
		goto out;
	}

	snprintf(path, sizeof(path), "%s/cgroup.events", opts.freeze_cgroup);
	event = fopen(path, "r");
	if (event == NULL) {
		pr_perror("Unable to open %s", path);
		goto out;
	}
	while (fgets(path, sizeof(path), event)) {
		if (strncmp(path, "frozen", 6) != 0) {
			continue;
		} else if (strncmp(path, "frozen 0", 8) == 0) {
			exit_code = FREEZING;
			goto close;
		} else if (strncmp(path, "frozen 1", 8) == 0) {
			exit_code = FROZEN;
			goto close;
		}
	}

	pr_err("Unknown freezer state: %c\n", state);
close:
	fclose(event);
out:
	return exit_code;
}

static enum freezer_state get_freezer_state(int fd)
{
	if (cgroup_v2)
		return get_freezer_v2_state(fd);
	return get_freezer_v1_state(fd);
}

static enum freezer_state origin_freezer_state = FREEZER_ERROR;

const char *get_real_freezer_state(void)
{
	return origin_freezer_state == THAWED ? thawed : frozen;
}

static int freezer_write_state(int fd, enum freezer_state new_state)
{
	char state[32] = { 0 };
	int ret;

	if (new_state == THAWED) {
		if (cgroup_v2)
			state[0] = '0';
		else if (__strlcpy(state, thawed, sizeof(state)) >= sizeof(state))
			return -1;
	} else if (new_state == FROZEN) {
		if (cgroup_v2)
			state[0] = '1';
		else if (__strlcpy(state, frozen, sizeof(state)) >= sizeof(state))
			return -1;
	} else {
		return -1;
	}

	ret = lseek(fd, 0, SEEK_SET);
	if (ret < 0) {
		pr_perror("Unable to seek freezer FD");
		return -1;
	}
	if (write(fd, state, sizeof(state)) != sizeof(state)) {
		pr_perror("Unable to %s tasks", (new_state == THAWED) ? "thaw" : "freeze");
		return -1;
	}

	return 0;
}

static int freezer_open(void)
{
	const char freezer_v1[] = "freezer.state";
	const char freezer_v2[] = "cgroup.freeze";
	char path[PATH_MAX];
	int fd;

	snprintf(path, sizeof(path), "%s/%s", opts.freeze_cgroup, cgroup_v2 ? freezer_v2 : freezer_v1);
	fd = open(path, O_RDWR);
	if (fd < 0) {
		pr_perror("Unable to open %s", path);
		return -1;
	}

	return fd;
}

static int freezer_restore_state(void)
{
	int fd;
	int ret;

	if (!opts.freeze_cgroup || origin_freezer_state != FROZEN)
		return 0;

	fd = freezer_open();
	if (fd < 0)
		return -1;

	ret = freezer_write_state(fd, FROZEN);
	close(fd);
	return ret;
}

static FILE *freezer_open_thread_list(char *root_path)
{
	char path[PATH_MAX];
	FILE *f;

	snprintf(path, sizeof(path), "%s/%s", root_path, cgroup_v2 ? "cgroup.threads" : "tasks");
	f = fopen(path, "r");
	if (f == NULL) {
		pr_perror("Unable to open %s", path);
		return NULL;
	}

	return f;
}

/* A number of tasks in a freezer cgroup which are not going to be dumped */
static int processes_to_wait;
static pid_t *processes_to_wait_pids;

static int seize_cgroup_tree(char *root_path, enum freezer_state state)
{
	DIR *dir;
	struct dirent *de;
	char path[PATH_MAX];
	FILE *f;

	/*
	 * New tasks can appear while a freezer state isn't
	 * frozen, so we need to catch all new tasks.
	 */
	f = freezer_open_thread_list(root_path);
	if (f == NULL)
		return -1;

	while (fgets(path, sizeof(path), f)) {
		pid_t pid;
		int ret;

		pid = atoi(path);

		/* Here we are going to skip tasks which are already traced. */
		ret = ptrace(PTRACE_INTERRUPT, pid, NULL, NULL);
		if (ret == 0)
			continue;
		if (errno != ESRCH) {
			pr_perror("Unexpected error for pid %d (comm %s)", pid, __task_comm_info(pid));
			fclose(f);
			return -1;
		}

		if (!compel_interrupt_task(pid)) {
			pr_debug("SEIZE %d (comm %s): success\n", pid, __task_comm_info(pid));
			processes_to_wait++;
		} else if (state == FROZEN) {
			char buf[] = "/proc/XXXXXXXXXX/exe";
			struct stat st;

			/* skip kernel threads */
			snprintf(buf, sizeof(buf), "/proc/%d/exe", pid);
			if (stat(buf, &st) == -1 && errno == ENOENT)
				continue;
			/*
			 * fails when meets a zombie, or exiting process:
			 * there is a small race in a kernel -- the process
			 * may start exiting and we are trying to freeze it
			 * before it compete exit procedure. The caller simply
			 * should wait a bit and try freezing again.
			 */
			pr_err("zombie %d (comm %s) found while seizing\n", pid, __task_comm_info(pid));
			fclose(f);
			return -EAGAIN;
		}
	}
	fclose(f);

	dir = opendir(root_path);
	if (!dir) {
		pr_perror("Unable to open %s", root_path);
		return -1;
	}

	while ((de = readdir(dir))) {
		struct stat st;
		int ret;

		if (dir_dots(de))
			continue;

		sprintf(path, "%s/%s", root_path, de->d_name);

		if (fstatat(dirfd(dir), de->d_name, &st, 0) < 0) {
			pr_perror("stat of %s failed", path);
			closedir(dir);
			return -1;
		}

		if (!S_ISDIR(st.st_mode))
			continue;
		ret = seize_cgroup_tree(path, state);
		if (ret < 0) {
			closedir(dir);
			return ret;
		}
	}
	closedir(dir);

	return 0;
}

/*
 * A freezer cgroup can contain tasks which will not be dumped
 * and we need to wait them, because the are interrupted them by ptrace.
 */
static int freezer_wait_processes(void)
{
	int i;

	processes_to_wait_pids = xmalloc(sizeof(pid_t) * processes_to_wait);
	if (processes_to_wait_pids == NULL)
		return -1;

	for (i = 0; i < processes_to_wait; i++) {
		int status;
		pid_t pid;

		/*
		 * Here we are going to skip tasks which are already traced.
		 * Ptraced tasks looks like children for us, so if
		 * a task isn't ptraced yet, waitpid() will return a error.
		 */
		pid = waitpid(-1, &status, 0);
		if (pid < 0) {
			pr_perror("Unable to wait processes");
			xfree(processes_to_wait_pids);
			processes_to_wait_pids = NULL;
			return -1;
		}
		pr_warn("Unexpected process %d in the freezer cgroup (status 0x%x)\n", pid, status);

		processes_to_wait_pids[i] = pid;
	}

	return 0;
}

static int freezer_detach(void)
{
	int i;

	if (!opts.freeze_cgroup || compel_interrupt_only_mode)
		return 0;

	for (i = 0; i < processes_to_wait && processes_to_wait_pids; i++) {
		pid_t pid = processes_to_wait_pids[i];
		int status, save_errno;

		if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == 0)
			continue;

		save_errno = errno;

		/* A process may be killed by SIGKILL */
		if (wait4(pid, &status, __WALL, NULL) == pid) {
			pr_warn("The %d process returned 0x %x\n", pid, status);
			continue;
		}
		errno = save_errno;
		pr_perror("Unable to detach from %d", pid);
	}

	return 0;
}

static int log_unfrozen_stacks(char *root)
{
	DIR *dir;
	struct dirent *de;
	char path[PATH_MAX];
	FILE *f;

	f = freezer_open_thread_list(root);
	if (f == NULL)
		return -1;

	while (fgets(path, sizeof(path), f)) {
		pid_t pid;
		int ret, stack;
		char stackbuf[2048];

		pid = atoi(path);

		stack = open_proc(pid, "stack");
		if (stack < 0) {
			pr_err("`- couldn't log %d's stack\n", pid);
			fclose(f);
			return -1;
		}

		ret = read(stack, stackbuf, sizeof(stackbuf) - 1);
		close(stack);
		if (ret < 0) {
			pr_perror("couldn't read %d's stack", pid);
			fclose(f);
			return -1;
		}
		stackbuf[ret] = '\0';

		pr_debug("Task %d has stack:\n%s", pid, stackbuf);
	}
	fclose(f);

	dir = opendir(root);
	if (!dir) {
		pr_perror("Unable to open %s", root);
		return -1;
	}

	while ((de = readdir(dir))) {
		struct stat st;

		if (dir_dots(de))
			continue;

		sprintf(path, "%s/%s", root, de->d_name);

		if (fstatat(dirfd(dir), de->d_name, &st, 0) < 0) {
			pr_perror("stat of %s failed", path);
			closedir(dir);
			return -1;
		}

		if (!S_ISDIR(st.st_mode))
			continue;

		if (log_unfrozen_stacks(path) < 0) {
			closedir(dir);
			return -1;
		}
	}
	closedir(dir);

	return 0;
}

static int prepare_freezer_for_interrupt_only_mode(void)
{
	enum freezer_state state = THAWED;
	int fd;
	int exit_code = -1;

	BUG_ON(!compel_interrupt_only_mode);

	fd = freezer_open();
	if (fd < 0)
		return -1;

	state = get_freezer_state(fd);
	if (state == FREEZER_ERROR) {
		goto err;
	}

	origin_freezer_state = state == FREEZING ? FROZEN : state;

	if (state != THAWED) {
		pr_warn("unfreezing cgroup for plugin compatibility\n");
		if (freezer_write_state(fd, THAWED))
			goto err;
	}

	exit_code = 0;
err:
	close(fd);
	return exit_code;
}

static void cgroupv1_freezer_kludges(int fd, int iter, const struct timespec *req) {
	/* As per older kernel docs (freezer-subsystem.txt before
	 * the kernel commit ef9fe980c6fcc1821), if FREEZING is seen,
	 * userspace should either retry or thaw. While current
	 * kernel cgroup v1 docs no longer mention a need to retry,
	 * even recent kernels can't reliably freeze a cgroup v1.
	 *
	 * Let's keep asking the kernel to freeze from time to time.
	 * In addition, do occasional thaw/sleep/freeze.
	 *
	 * This is still a game of chances (the real fix belongs to the kernel)
	 * but these kludges might improve the probability of success.
	 *
	 * Cgroup v2 does not have this problem.
	 */
	switch (iter % 32) {
		case 9:
		case 20:
			freezer_write_state(fd, FROZEN);
			break;
		case 31:
			freezer_write_state(fd, THAWED);
			nanosleep(req, NULL);
			freezer_write_state(fd, FROZEN);
			break;
	}
}

static int freeze_processes(void)
{
	int fd, exit_code = -1;
	enum freezer_state state = THAWED;

	static const unsigned long step_ms = 100;
	/* Since opts.timeout is in seconds, multiply it by 1000 to convert to milliseconds. */
	unsigned long nr_attempts = (opts.timeout * 1000) / step_ms;
	unsigned long i = 0;

	const struct timespec req = {
		.tv_nsec = step_ms * 1000000,
		.tv_sec = 0,
	};

	if (unlikely(!nr_attempts)) {
		/* If the timeout is 0, wait for at least 10 seconds. */
		nr_attempts = (10 * 1000) / step_ms;
	}

	pr_debug("freezing cgroup %s: %lu x %lums attempts, timeout: %us\n",
		 opts.freeze_cgroup, nr_attempts, step_ms, opts.timeout);

	fd = freezer_open();
	if (fd < 0)
		return -1;

	state = get_freezer_state(fd);
	if (state == FREEZER_ERROR) {
		close(fd);
		return -1;
	}

	origin_freezer_state = state == FREEZING ? FROZEN : state;

	if (state == THAWED) {
		if (freezer_write_state(fd, FROZEN)) {
			close(fd);
			return -1;
		}

		/*
		 * Wait the freezer to complete before
		 * processing tasks. They might be exiting
		 * before freezing complete so we should
		 * not read @tasks pids while freezer in
		 * transition stage.
		 */
		while (1) {
			state = get_freezer_state(fd);
			if (state == FREEZER_ERROR) {
				close(fd);
				return -1;
			}

			if (state == FROZEN || i++ == nr_attempts || alarm_timeouted())
				break;

			if (!cgroup_v2)
				cgroupv1_freezer_kludges(fd, i, &req);

			nanosleep(&req, NULL);
		}

		if (state != FROZEN) {
			pr_err("Unable to freeze cgroup %s (%lu x %lums attempts, timeout: %us)\n",
			       opts.freeze_cgroup, i, step_ms, opts.timeout);
			if (!pr_quelled(LOG_DEBUG))
				log_unfrozen_stacks(opts.freeze_cgroup);
			goto err;
		}

		pr_debug("freezing processes: %lu attempts done\n", i);
	}

	/*
	 * Pay attention on @i variable -- it's continuation.
	 */
	for (; i <= nr_attempts; i++) {
		exit_code = seize_cgroup_tree(opts.freeze_cgroup, state);
		if (exit_code == -EAGAIN) {
			if (alarm_timeouted())
				goto err;
			nanosleep(&req, NULL);
		} else
			break;
	}

err:
	if (exit_code == 0 || origin_freezer_state == THAWED) {
		if (freezer_write_state(fd, THAWED))
			exit_code = -1;
	}

	if (close(fd)) {
		pr_perror("Unable to thaw tasks");
		return -1;
	}

	return exit_code;
}

static inline bool child_collected(struct pstree_item *i, pid_t pid)
{
	struct pstree_item *c;

	list_for_each_entry(c, &i->children, sibling)
		if (c->pid->real == pid)
			return true;

	return false;
}

static int collect_task(struct pstree_item *item);
static int collect_children(struct pstree_item *item)
{
	pid_t *ch;
	int ret, i, nr_children, nr_inprogress;

	ret = parse_children(item->pid->real, &ch, &nr_children);
	if (ret < 0)
		return ret;

	nr_inprogress = 0;
	for (i = 0; i < nr_children; i++) {
		struct pstree_item *c;
		struct proc_status_creds creds;
		pid_t pid = ch[i];

		/* Is it already frozen? */
		if (child_collected(item, pid))
			continue;

		nr_inprogress++;

		if (alarm_timeouted()) {
			ret = -1;
			goto free;
		}

		c = alloc_pstree_item();
		if (c == NULL) {
			ret = -1;
			goto free;
		}

		ret = run_plugins(PAUSE_DEVICES, pid);
		if (ret < 0 && ret != -ENOTSUP) {
			goto free;
		}

		if (!opts.freeze_cgroup || compel_interrupt_only_mode)
			/* fails when meets a zombie */
			__ignore_value(compel_interrupt_task(pid));

		ret = compel_wait_task(pid, item->pid->real, parse_pid_status, NULL, &creds.s, NULL);
		if (ret < 0) {
			/*
			 * Here is a race window between parse_children() and seize(),
			 * so the task could die for these time.
			 * Don't worry, will try again on the next attempt. The number
			 * of attempts is restricted, so it will exit if something
			 * really wrong.
			 */
			ret = 0;
			xfree(c);
			continue;
		}

		if (ret == TASK_ZOMBIE)
			ret = TASK_DEAD;
		else
			processes_to_wait--;

		if (ret == TASK_STOPPED)
			c->pid->stop_signo = compel_parse_stop_signo(pid);

		pr_info("Seized task %d, state %d\n", pid, ret);

		c->pid->real = pid;
		c->parent = item;
		c->pid->state = ret;
		list_add_tail(&c->sibling, &item->children);

		ret = seccomp_collect_entry(pid, creds.s.seccomp_mode);
		if (ret < 0)
			goto free;

		/* Here is a recursive call (Depth-first search) */
		ret = collect_task(c);
		if (ret < 0)
			goto free;
	}
free:
	xfree(ch);
	return ret < 0 ? ret : nr_inprogress;
}

static void unseize_task_and_threads(const struct pstree_item *item, int st)
{
	int i;

	if (item->pid->state == TASK_DEAD)
		return;

	/*
	 * The st is the state we want to switch tasks into,
	 * the item->state is the state task was in when we seized one.
	 */

	compel_resume_task_sig(item->pid->real, item->pid->state, st, item->pid->stop_signo);

	if (st == TASK_DEAD)
		return;

	for (i = 1; i < item->nr_threads; i++)
		if (ptrace(PTRACE_DETACH, item->threads[i].real, NULL, NULL))
			pr_perror("Unable to detach from %d", item->threads[i].real);
}

static void pstree_wait(struct pstree_item *root_item)
{
	struct pstree_item *item = root_item;
	int pid, status, i;

	for_each_pstree_item(item) {
		if (item->pid->state == TASK_DEAD)
			continue;

		for (i = 0; i < item->nr_threads; i++) {
			pid = wait4(-1, &status, __WALL, NULL);
			if (pid < 0) {
				pr_perror("wait4 failed");
				break;
			} else {
				if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL) {
					pr_err("Unexpected exit code %d of %d: %s\n", status, pid, strsignal(status));
					BUG();
				}
			}
		}
	}

	pid = wait4(-1, &status, __WALL, NULL);
	if (pid > 0) {
		pr_err("Unexpected child %d\n", pid);
		BUG();
	}
}

void pstree_switch_state(struct pstree_item *root_item, int st)
{
	struct pstree_item *item = root_item;

	if (!root_item)
		return;

	if (st != TASK_DEAD)
		freezer_restore_state();

	/*
	 * We need to detach from all processes before waiting the init
	 * process, because one of these processes may collect processes from a
	 * target pid namespace. The pid namespace is destroyed only when all
	 * processes have been killed and collected.
	 */
	freezer_detach();

	pr_info("Unfreezing tasks into %d\n", st);
	for_each_pstree_item(item)
		unseize_task_and_threads(item, st);

	if (st == TASK_DEAD)
		pstree_wait(root_item);
}

static pid_t item_ppid(const struct pstree_item *item)
{
	item = item->parent;
	return item ? item->pid->real : -1;
}

static inline bool thread_collected(struct pstree_item *i, pid_t tid)
{
	int t;

	if (i->pid->real == tid) /* thread leader is collected as task */
		return true;

	for (t = 0; t < i->nr_threads; t++)
		if (tid == i->threads[t].real)
			return true;

	return false;
}

static int collect_threads(struct pstree_item *item)
{
	struct seccomp_entry *task_seccomp_entry;
	struct pid *threads = NULL;
	struct pid *tmp = NULL;
	int nr_threads = 0, i = 0, ret, nr_inprogress, nr_stopped = 0;

	task_seccomp_entry = seccomp_find_entry(item->pid->real);
	if (!task_seccomp_entry)
		goto err;

	ret = parse_threads(item->pid->real, &threads, &nr_threads);
	if (ret < 0)
		goto err;

	if ((item->pid->state == TASK_DEAD) && (nr_threads > 1)) {
		pr_err("Zombies with threads are not supported\n");
		goto err;
	}

	/* The number of threads can't be less than already frozen */
	tmp = xrealloc(item->threads, nr_threads * sizeof(struct pid));
	if (tmp == NULL)
		goto err;

	item->threads = tmp;

	if (item->nr_threads == 0) {
		item->threads[0].real = item->pid->real;
		item->nr_threads = 1;
		item->threads[0].item = NULL;
	}

	nr_inprogress = 0;
	for (i = 0; i < nr_threads; i++) {
		pid_t pid = threads[i].real;
		struct proc_status_creds t_creds = {};

		if (thread_collected(item, pid))
			continue;

		nr_inprogress++;

		pr_info("\tSeizing %d's %d thread\n", item->pid->real, pid);

		if ((!opts.freeze_cgroup || compel_interrupt_only_mode) &&
		    compel_interrupt_task(pid))
			continue;

		ret = compel_wait_task(pid, item_ppid(item), parse_pid_status, NULL, &t_creds.s, NULL);
		if (ret < 0) {
			/*
			 * Here is a race window between parse_threads() and seize(),
			 * so the task could die for these time.
			 * Don't worry, will try again on the next attempt. The number
			 * of attempts is restricted, so it will exit if something
			 * really wrong.
			 */
			continue;
		}

		if (ret == TASK_ZOMBIE)
			ret = TASK_DEAD;
		else
			processes_to_wait--;

		BUG_ON(item->nr_threads + 1 > nr_threads);
		item->threads[item->nr_threads].real = pid;
		item->threads[item->nr_threads].ns[0].virt = t_creds.s.vpid;
		item->threads[item->nr_threads].item = NULL;
		item->nr_threads++;

		if (ret == TASK_DEAD) {
			pr_err("Zombie thread not supported\n");
			goto err;
		}

		if (seccomp_collect_entry(pid, t_creds.s.seccomp_mode))
			goto err;

		if (ret == TASK_STOPPED) {
			nr_stopped++;
		}
	}

	if (nr_stopped && nr_stopped != nr_inprogress) {
		pr_err("Individually stopped threads not supported\n");
		goto err;
	}

	xfree(threads);
	return nr_inprogress;

err:
	xfree(threads);
	return -1;
}

static int collect_loop(struct pstree_item *item, int (*collect)(struct pstree_item *))
{
	int attempts = NR_ATTEMPTS, nr_inprogress = 1;

	if (opts.freeze_cgroup && !compel_interrupt_only_mode)
		attempts = 1;

	/*
	 * While we scan the proc and seize the children/threads
	 * new ones can appear (with clone(CLONE_PARENT) or with
	 * pthread_create). Thus, after one go, we need to repeat
	 * the scan-and-freeze again collecting new arrivals. As
	 * new guys may appear again we do NR_ATTEMPTS passes and
	 * fail to seize the item if new tasks/threads still
	 * appear.
	 */

	while (nr_inprogress > 0 && attempts >= 0) {
		attempts--;
		nr_inprogress = collect(item);
	}

	pr_info("Collected (%d attempts, %d in_progress)\n", attempts, nr_inprogress);

	/*
	 * We may fail to collect items or run out of attempts.
	 * In the former case nr_inprogress will be negative, in
	 * the latter -- positive. Thus it's enough just to check
	 * for "no more new stuff" and say "we're OK" if so.
	 */

	return (nr_inprogress == 0) ? 0 : -1;
}

static int collect_task(struct pstree_item *item)
{
	int ret;

	ret = collect_loop(item, collect_threads);
	if (ret < 0)
		goto err_close;

	/* Depth-first search (DFS) is used for traversing a process tree. */
	ret = collect_loop(item, collect_children);
	if (ret < 0)
		goto err_close;

	if ((item->pid->state == TASK_DEAD) && has_children(item)) {
		pr_err("Zombie with children?! O_o Run, run, run!\n");
		goto err_close;
	}

	if (pstree_alloc_cores(item))
		goto err_close;

	pr_info("Collected %d in %d state\n", item->pid->real, item->pid->state);
	return 0;

err_close:
	close_pid_proc();
	return -1;
}

static int cgroup_version(void)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/freezer.state", opts.freeze_cgroup);
	if (access(path, F_OK) == 0) {
		cgroup_v2 = false;
		return 0;
	}

	snprintf(path, sizeof(path), "%s/cgroup.freeze", opts.freeze_cgroup);
	if (access(path, F_OK) == 0) {
		cgroup_v2 = true;
		return 0;
	}

	pr_err("Neither a cgroupv1 (freezer.state) or cgroupv2 (cgroup.freeze) control file found.\n");

	return -1;
}

int collect_pstree(void)
{
	pid_t pid = root_item->pid->real;
	int ret, exit_code = -1;
	struct proc_status_creds creds;

	timing_start(TIME_FREEZING);

	/*
	 * wait4() may hang for some reason. Enable timer and fire SIGALRM
	 * if timeout reached. SIGALRM handler will do  the necessary
	 * cleanups and terminate current process.
	 */
	alarm(opts.timeout);

	if (opts.freeze_cgroup && cgroup_version())
		goto err;

	pr_debug("Detected cgroup V%d freezer\n", cgroup_v2 ? 2 : 1);

	if (opts.freeze_cgroup && !compel_interrupt_only_mode) {
		ret = run_plugins(PAUSE_DEVICES, pid);
		if (ret < 0 && ret != -ENOTSUP) {
			goto err;
		}

		if (freeze_processes())
			goto err;
	} else {
		if (opts.freeze_cgroup && prepare_freezer_for_interrupt_only_mode())
			goto err;

		/*
		 * Call PAUSE_DEVICES after prepare_freezer_for_interrupt_only_mode()
		 * to be able to checkpoint containers in a frozen state.
		 */
		ret = run_plugins(PAUSE_DEVICES, pid);
		if (ret < 0 && ret != -ENOTSUP) {
			goto err;
		}

		if (compel_interrupt_task(pid)) {
			set_cr_errno(ESRCH);
			goto err;
		}
	}

	ret = compel_wait_task(pid, -1, parse_pid_status, NULL, &creds.s, NULL);
	if (ret < 0)
		goto err;

	if (ret == TASK_ZOMBIE)
		ret = TASK_DEAD;
	else
		processes_to_wait--;

	if (ret == TASK_STOPPED)
		root_item->pid->stop_signo = compel_parse_stop_signo(pid);

	pr_info("Seized task %d, state %d\n", pid, ret);
	root_item->pid->state = ret;

	ret = seccomp_collect_entry(pid, creds.s.seccomp_mode);
	if (ret < 0)
		goto err;

	ret = collect_task(root_item);
	if (ret < 0)
		goto err;

	if (opts.freeze_cgroup && !compel_interrupt_only_mode &&
	    freezer_wait_processes()) {
		goto err;
	}

	exit_code = 0;
	timing_stop(TIME_FREEZING);
	timing_start(TIME_FROZEN);

err:
	/* Freezing stage finished in time - disable timer. */
	alarm(0);
	return exit_code;
}

int checkpoint_devices(void)
{
	struct pstree_item *iter;
	int ret, exit_code = -1;

	for_each_pstree_item(iter) {
		if (!task_alive(iter))
			continue;
		ret = run_plugins(CHECKPOINT_DEVICES, iter->pid->real);
		if (ret < 0 && ret != -ENOTSUP)
			goto err;
	}

	exit_code = 0;
err:
	return exit_code;
}
