/* CPU-only integration tests for guarded CUDA backend calls.
 *
 * Run the production backend against libcuda.c and a real ptrace target. The
 * fake restore thread faults only after the checkpoint API starts waiting.
 */
/* The checks below run side effects inside assert(). */
#undef NDEBUG
#include <assert.h>
#include <dirent.h>
#include <pthread.h>
#include <errno.h>
#include <limits.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <compel/infect.h>
#include <compel/log.h>

#include "cr_options.h"
#include "cuda_device_map.h"
#include "cuda_plugin.h"
#include "pid.h"
#include "plugin.h"

struct cr_options opts;
unsigned int cuda_plugin_timeout;

static FILE *log_file;
static unsigned int interrupts;
static bool fault_before_interrupt;
static bool group_stop_before_interrupt;
static bool skip_interrupt;
static bool target_seccomp;
static unsigned int seccomp_thread_options;
static pid_t target_pid;
static pid_t other_child;
static volatile sig_atomic_t other_status = -1;
static int target_pipe[2];
static volatile sig_atomic_t criu_timed_out;

static void other_sigchld(int signal, siginfo_t *info, void *context)
{
	int saved_errno = errno, status;

	(void)signal;
	(void)info;
	(void)context;
	if (other_child && waitpid(other_child, &status, WNOHANG) == other_child)
		other_status = status;
	errno = saved_errno;
}

int log_get_fd(void)
{
	return fileno(log_file);
}

int close_fds(int minfd)
{
	DIR *directory = opendir("/proc/self/fd");
	struct dirent *entry;
	int ret = 0;

	if (!directory)
		return -1;
	while ((entry = readdir(directory))) {
		int fd = atoi(entry->d_name);

		if (fd >= minfd && fd != dirfd(directory) && close(fd))
			ret = -1;
	}
	closedir(directory);
	return ret;
}

void print_on_level(unsigned int loglevel, const char *format, ...)
{
	va_list args;

	(void)loglevel;
	va_start(args, format);
	vfprintf(log_file, format, args);
	va_end(args);
	fflush(log_file);
}

static void compel_test_log(unsigned int level, const char *format, va_list args)
{
	vfprintf(log_file, format, args);
}

int parse_pid_status(pid_t pid, struct seize_task_status *ss, void *data)
{
	char path[64], line[256];
	FILE *file;

	memset(ss, 0, sizeof(*ss));
	snprintf(path, sizeof(path), "/proc/%d/status", pid);
	file = fopen(path, "r");
	if (!file) {
		if (errno != ENOENT)
			return -1;
		ss->state = 'Z';
		return 0;
	}
	while (fgets(line, sizeof(line), file)) {
		sscanf(line, "State:\t%c", &ss->state);
		sscanf(line, "SigPnd:\t%llx", &ss->sigpnd);
		sscanf(line, "ShdPnd:\t%llx", &ss->shdpnd);
		sscanf(line, "SigBlk:\t%llx", &ss->sigblk);
		sscanf(line, "Seccomp:\t%d", &ss->seccomp_mode);
	}
	fclose(file);
	return 0;
}

int cuda_plugin_add_inventory(void)
{
	return 0;
}

bool alarm_timeouted(void)
{
	return criu_timed_out;
}

static void freezing_timeout(int signal)
{
	(void)signal;
	if (criu_timed_out)
		_exit(124);
	criu_timed_out = 1;
	alarm(5);
}

static int thread_seccomp_mode(pid_t tid)
{
	char path[64], line[256];
	int mode = -1;
	FILE *file;

	snprintf(path, sizeof(path), "/proc/%d/status", tid);
	file = fopen(path, "r");
	if (!file)
		return -1;
	while (fgets(line, sizeof(line), file)) {
		if (sscanf(line, "Seccomp:\t%d", &mode) == 1)
			break;
	}
	fclose(file);
	return mode;
}

/* SUSPEND_SECCOMP requires CAP_SYS_ADMIN in the initial user namespace, and
 * the backends leave it to CRIU, which suspends seccomp again after
 * CHECKPOINT_DEVICES. Fail every request like the kernel does for `criu
 * --unprivileged`, even when the test runs as root, and count the options
 * that the backends set on threads that use seccomp. Keep every other ptrace
 * operation real.
 *
 * The request type is deliberately a plain integer, not glibc's
 * "enum __ptrace_request": that enum is a glibc-specific typedef of the
 * ptrace() prototype and is not declared by musl libc (e.g. on Alpine),
 * where ptrace() takes a plain int instead.
 */
long __wrap_ptrace(int request, ...)
{
	va_list args;
	pid_t pid;
	void *addr;
	unsigned long data;

	va_start(args, request);
	pid = va_arg(args, pid_t);
	addr = va_arg(args, void *);
	data = va_arg(args, unsigned long);
	va_end(args);
	if (request == PTRACE_SETOPTIONS) {
		if (data & PTRACE_O_SUSPEND_SECCOMP) {
			errno = EPERM;
			return -1;
		}
		if (data && thread_seccomp_mode(pid) > SECCOMP_MODE_DISABLED)
			seccomp_thread_options++;
	}
	if (request == PTRACE_CONT)
		assert(!data); /* The backend must never forward a signal. */
	if (request == PTRACE_INTERRUPT) {
		interrupts++;
		if (skip_interrupt) {
			skip_interrupt = false;
			return 0;
		}
		if (fault_before_interrupt) {
			FILE *file = fopen(getenv("CRIU_CUDA_MOCK_FAULT_TRIGGER"), "w");
			siginfo_t info;

			fault_before_interrupt = false;
			assert(file && fclose(file) == 0);
			assert(waitid(P_PID, pid, &info, WSTOPPED | WNOWAIT | __WALL) == 0);
			assert(info.si_status == SIGSEGV);
		}
		if (group_stop_before_interrupt) {
			siginfo_t info;
			int status;

			group_stop_before_interrupt = false;
			assert(syscall(SYS_tgkill, target_pid, pid, SIGSTOP) == 0);
			assert(waitpid(pid, &status, __WALL) == pid);
			assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
			/* Deliver SIGSTOP only in the harness to create a group-stop. */
			assert(syscall(SYS_ptrace, PTRACE_CONT, pid, NULL, SIGSTOP) == 0);
			assert(waitid(P_PID, pid, &info, WSTOPPED | WNOWAIT | __WALL) == 0);
			assert(info.si_status == (SIGSTOP | (PTRACE_EVENT_STOP << 8)));
		}
	}
	return syscall(SYS_ptrace, request, pid, addr, data);
}

long __real_syscall(long number, ...);

/* Let a test make the worker's SIGSTOP notification fail. */
long __wrap_syscall(long number, ...)
{
	long args[6];
	va_list list;
	int i;

	va_start(list, number);
	for (i = 0; i < 6; i++)
		args[i] = va_arg(list, long);
	va_end(list);
	if (number == SYS_tgkill && args[2] == SIGSTOP && getenv("CRIU_CUDA_TEST_TGKILL_EPERM")) {
		errno = EPERM;
		return -1;
	}
	return __real_syscall(number, args[0], args[1], args[2], args[3], args[4], args[5]);
}

struct target_args {
	const char *trigger;
	int ready;
	bool exit_thread;
};

static void *target_thread(void *data)
{
	struct target_args *args = data;
	pid_t tid = syscall(SYS_gettid);
	volatile int *invalid = NULL;
	struct timespec delay = { .tv_nsec = 1000000 };

	assert(write(args->ready, &tid, sizeof(tid)) == sizeof(tid));
	close(args->ready);
	for (;;) {
		if (access(args->trigger, F_OK) == 0) {
			if (args->exit_thread)
				syscall(SYS_exit, 77);
			*invalid = 1;
		}
		nanosleep(&delay, NULL);
	}
	return NULL;
}

/* Give the target a seccomp filter that allows every system call. */
static void install_seccomp_filter(void)
{
	struct sock_filter filter[] = { BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW) };
	struct sock_fprog program = { .len = 1, .filter = filter };

	assert(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
	assert(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) == 0);
}

static pid_t start_target(const char *trigger, bool threaded, bool exit_thread, pid_t *tid)
{
	int ready[2];
	pid_t pid;

	assert(pipe(ready) == 0);
	pid = fork();
	assert(pid >= 0);
	if (!pid) {
		const struct rlimit no_core = { 0, 0 };
		struct target_args args = { .trigger = trigger, .ready = ready[1], .exit_thread = exit_thread };
		pthread_t thread;

		close(ready[0]);
		close(target_pipe[0]);
		assert(setrlimit(RLIMIT_CORE, &no_core) == 0);
		if (target_seccomp)
			install_seccomp_filter();
		if (!threaded)
			target_thread(&args);
		assert(pthread_create(&thread, NULL, target_thread, &args) == 0);
		for (;;)
			pause();
	}
	close(ready[1]);
	close(target_pipe[1]);
	assert(read(ready[0], tid, sizeof(*tid)) == sizeof(*tid));
	close(ready[0]);
	return pid;
}

static void stop_target(pid_t pid)
{
	int status;

	assert(ptrace(PTRACE_SEIZE, pid, NULL, 0UL) == 0);
	assert(ptrace(PTRACE_INTERRUPT, pid, NULL, 0UL) == 0);
	assert(waitpid(pid, &status, __WALL) == pid);
	assert(WIFSTOPPED(status));
}

static off_t file_size(const char *path)
{
	struct stat status;

	assert(stat(path, &status) == 0);
	return status.st_size;
}

static pid_t check_api_calls(const char *path, bool completed, bool driver, bool restore_fault, bool helper_error)
{
	FILE *file = fopen(path, "r");
	char operation[32];
	pid_t api_caller = -1;
	int target_pid, caller, checkpoints = 0, restores = 0, unlocks = 0;

	assert(file);
	while (fscanf(file, "%31s %d %d", operation, &target_pid, &caller) == 3) {
		int status;

		if (api_caller < 0)
			api_caller = caller;
		if (driver) {
			if (!strcmp(operation, "checkpoint") || !strcmp(operation, "restore") ||
			    !strcmp(operation, "unlock") || !strcmp(operation, "init"))
				assert(caller != getpid());
			if (caller != getpid())
				assert(syscall(SYS_tgkill, getpid(), caller, 0) == -1 && errno == ESRCH);
		} else {
			assert(waitpid(caller, &status, __WALL | WNOHANG) == -1 && errno == ECHILD);
			assert(kill(caller, 0) == -1 && errno == ESRCH);
		}
		checkpoints += !strcmp(operation, "checkpoint");
		restores += !strcmp(operation, "restore");
		unlocks += !strcmp(operation, "unlock");
	}
	assert(feof(file));
	fclose(file);
	assert(checkpoints == 1);
	assert(restores == (((completed && !helper_error) || restore_fault) ? 1 : 0));
	assert(unlocks == (completed ? 1 : 0));
	assert(api_caller > 0);
	return api_caller;
}

static void check_log(const char *expected)
{
	char *text;
	long size;

	assert(fseek(log_file, 0, SEEK_END) == 0);
	size = ftell(log_file);
	assert(size >= 0);
	text = malloc(size + 1);
	assert(text);
	rewind(log_file);
	assert(fread(text, 1, size, log_file) == (size_t)size);
	text[size] = '\0';
	if (!strstr(text, expected)) {
		fprintf(stderr, "Expected log to contain '%s':\n%s", expected, text);
		abort();
	}
	free(text);
}

static void run_case(const char *directory, const char *behavior,
		     const struct cuda_plugin_backend *backend)
{
	char marker[512], trigger[512], mapping[512], log_path[512], state_path[512];
	bool success = !strcmp(behavior, "success") || !strcmp(behavior, "unrelated") ||
		       !strcmp(behavior, "notify-eperm") || !strcmp(behavior, "seccomp") ||
		       !strncmp(behavior, "delayed-success", strlen("delayed-success"));
	bool helper_error = !strcmp(behavior, "exit");
	bool completed = success || !strcmp(behavior, "api-error") || helper_error;
	bool delayed = !strncmp(behavior, "delayed-", strlen("delayed-"));
	bool stop_timeout = !strncmp(behavior, "stop-timeout", strlen("stop-timeout"));
	bool freezing = !strncmp(behavior, "criu-timeout", strlen("criu-timeout"));
	bool driver = backend == &cuda_driver_backend;
	bool restore_fault = !strcmp(behavior, "restore-fault");
	bool init_fault = !strcmp(behavior, "init-fault");
	bool unrelated = !strcmp(behavior, "unrelated");
	bool target_dead = !strcmp(behavior, "target-exit") || !strcmp(behavior, "target-kill");
	CUcheckpointGpuPair pair = { .oldUuid = { 1 }, .newUuid = { 2 } };
	struct cuda_device_map map = {
		.pairs = &pair,
		.count = 1,
		.cli_value = "GPU-01000000-0000-0000-0000-000000000000="
			     "GPU-02000000-0000-0000-0000-000000000000",
	};
	k_rtsigset_t original_mask, restored_mask;
	sigset_t original_tracer_mask, tracer_mask;
	struct sigaction original_action, action;
	struct timespec start, end;
	pid_t pid, tid, api_caller;
	int other_pipe[2] = { -1, -1 };
	char value[32];
	off_t before_cleanup;
	int status, ret;
	double elapsed;

	assert(snprintf(marker, sizeof(marker), "%s/%s.calls", directory, behavior) > 0);
	assert(snprintf(trigger, sizeof(trigger), "%s/%s.fault", directory, behavior) > 0);
	assert(snprintf(mapping, sizeof(mapping), "%s/%s.map", directory, behavior) > 0);
	assert(snprintf(log_path, sizeof(log_path), "%s/%s.log", directory, behavior) > 0);
	assert(snprintf(state_path, sizeof(state_path), "%s/%s.state", directory, behavior) > 0);
	assert(setenv("CRIU_CUDA_MOCK_API_MARKER", marker, 1) == 0);
	assert(setenv("CRIU_CUDA_MOCK_FAULT_TRIGGER", trigger, 1) == 0);
	assert(setenv("CRIU_CUDA_MOCK_CHECKPOINT_BEHAVIOR", behavior, 1) == 0);
	assert(setenv("CRIU_CUDA_MOCK_STATE_FILE", state_path, 1) == 0);
	assert(unsetenv("CRIU_CUDA_MOCK_CHECKPOINT_ERROR_AFTER_TRANSITION") == 0);
	assert(unsetenv("CRIU_CUDA_MOCK_INIT_HANG") == 0);
	assert(unsetenv("CRIU_CUDA_MOCK_RESTORE_BEHAVIOR") == 0);
	assert(unsetenv("CRIU_CUDA_MOCK_INIT_FAULT") == 0);
	assert(unsetenv("CRIU_CUDA_MOCK_RESTORE_TID") == 0);
	assert(unsetenv("CRIU_CUDA_TEST_TGKILL_EPERM") == 0);
	if (!strcmp(behavior, "notify-eperm"))
		assert(setenv("CRIU_CUDA_TEST_TGKILL_EPERM", "1", 1) == 0);
	if (restore_fault || init_fault)
		assert(setenv("CRIU_CUDA_MOCK_CHECKPOINT_BEHAVIOR", "success", 1) == 0);
	if (restore_fault)
		assert(setenv("CRIU_CUDA_MOCK_RESTORE_BEHAVIOR", "fault", 1) == 0);
	if (init_fault)
		assert(setenv("CRIU_CUDA_MOCK_INIT_FAULT", "1", 1) == 0);
	if (!strcmp(behavior, "blocked-fault"))
		assert(setenv("CRIU_CUDA_MOCK_CHECKPOINT_BEHAVIOR", "fault", 1) == 0);
	assert(unsetenv("CRIU_CUDA_MOCK_DEVICE_MAP_MARKER") == 0);
	if (!strcmp(behavior, "api-error"))
		assert(setenv("CRIU_CUDA_MOCK_CHECKPOINT_ERROR_AFTER_TRANSITION", "1", 1) == 0);
	if (!strcmp(behavior, "init-hang"))
		assert(setenv("CRIU_CUDA_MOCK_INIT_HANG", "1", 1) == 0);
	if (delayed)
		assert(setenv("CRIU_CUDA_MOCK_CHECKPOINT_BEHAVIOR",
			      strstr(behavior, "closed-output") ? "delay-closed-output" : "delay", 1) == 0);
	if (!strcmp(behavior, "hang") || !strcmp(behavior, "init-hang") || (delayed && !success))
		cuda_plugin_timeout = 1;
	if (stop_timeout)
		assert(setenv("CRIU_CUDA_MOCK_CHECKPOINT_BEHAVIOR", "success", 1) == 0);
	if (success)
		assert(setenv("CRIU_CUDA_MOCK_DEVICE_MAP_MARKER", mapping, 1) == 0);
	if (freezing)
		assert(setenv("CRIU_CUDA_MOCK_CHECKPOINT_BEHAVIOR", "hang", 1) == 0);
	if (!strcmp(behavior, "criu-timeout-finite") || !strcmp(behavior, "stop-timeout-finite"))
		cuda_plugin_timeout = 30;
	log_file = fopen(log_path, "w+");
	assert(log_file);
	assert(pipe(target_pipe) == 0);
	snprintf(value, sizeof(value), "%d", target_pipe[0]);
	assert(setenv("CRIU_CUDA_MOCK_TARGET_PIPE", value, 1) == 0);
	target_seccomp = !strcmp(behavior, "seccomp");
	pid = start_target(trigger, driver, !strcmp(behavior, "target-exit"), &tid);
	target_pid = pid;
	if (driver) {
		assert(pid != tid);
		snprintf(value, sizeof(value), "%d", tid);
		assert(setenv("CRIU_CUDA_MOCK_RESTORE_TID", value, 1) == 0);
	}
	snprintf(value, sizeof(value), "%d", pid);
	assert(setenv("CRIU_CUDA_MOCK_TARGET_PID", value, 1) == 0);
	assert(backend->init(CR_PLUGIN_STAGE__DUMP) == 0);
	assert(backend->probe(false) == 0);
	assert(backend->pause_devices(pid) == 0);
	stop_target(pid);
	if (tid != pid)
		stop_target(tid);
	interrupts = 0;
	seccomp_thread_options = 0;
	fault_before_interrupt = !strcmp(behavior, "late-fault");
	group_stop_before_interrupt = !strcmp(behavior, "late-group-stop");
	skip_interrupt = stop_timeout;
	assert(ptrace(PTRACE_GETSIGMASK, tid, sizeof(original_mask), &original_mask) == 0);
	if (driver && (!strcmp(behavior, "api-error") || !strcmp(behavior, "blocked-fault"))) {
		sigemptyset(&tracer_mask);
		sigaddset(&tracer_mask, SIGCHLD);
		assert(sigprocmask(SIG_BLOCK, &tracer_mask, NULL) == 0);
	}
	if (unrelated) {
		assert(pipe(other_pipe) == 0);
		other_child = fork();
		assert(other_child >= 0);
		if (!other_child) {
			char byte;

			close(other_pipe[1]);
			assert(read(other_pipe[0], &byte, 1) == 1);
			_exit(23);
		}
		close(other_pipe[0]);

		snprintf(value, sizeof(value), "%d", other_pipe[1]);
		assert(setenv("CRIU_CUDA_MOCK_OTHER_FD", value, 1) == 0);
	}
	if (driver) {
		struct sigaction action = { .sa_sigaction = other_sigchld,
					    .sa_flags = SA_SIGINFO | SA_NOCLDSTOP | SA_RESTART };

		sigemptyset(&action.sa_mask);
		sigaddset(&action.sa_mask, SIGUSR1);
		assert(sigaction(SIGCHLD, &action, NULL) == 0);
	}
	assert(sigprocmask(SIG_SETMASK, NULL, &original_tracer_mask) == 0);
	assert(sigaction(SIGCHLD, NULL, &original_action) == 0);
	assert(clock_gettime(CLOCK_MONOTONIC, &start) == 0);
	if (freezing) {
		struct sigaction action = { .sa_handler = freezing_timeout };

		assert(sigaction(SIGALRM, &action, NULL) == 0);
		alarm(1);
	}
	ret = backend->checkpoint_devices(pid);
	if (restore_fault || init_fault || !strcmp(behavior, "init-hang")) {
		assert(ret == 0);
		ret = backend->resume_devices_late(pid, NULL);
	}
	assert(clock_gettime(CLOCK_MONOTONIC, &end) == 0);
	elapsed = end.tv_sec - start.tv_sec + (end.tv_nsec - start.tv_nsec) / 1e9;
	if (driver) {
		int signal;

		assert(sigprocmask(SIG_SETMASK, NULL, &tracer_mask) == 0);
		assert(sigaction(SIGCHLD, NULL, &action) == 0);
		assert(action.sa_sigaction == original_action.sa_sigaction);
		assert(action.sa_flags == original_action.sa_flags);
		for (signal = 1; signal < NSIG; signal++) {
			assert(sigismember(&tracer_mask, signal) == sigismember(&original_tracer_mask, signal));
			assert(sigismember(&action.sa_mask, signal) == sigismember(&original_action.sa_mask, signal));
		}
		if (unrelated) {
			int retries;

			for (retries = 0; other_status == -1 && retries < 1000; retries++)
				usleep(1000);
			assert(other_status != -1 && WIFEXITED(other_status) && WEXITSTATUS(other_status) == 23);
			assert(waitpid(other_child, &status, WNOHANG) == -1 && errno == ECHILD);
			close(other_pipe[1]);
		}
	}

	assert(elapsed < (stop_timeout ? 13 : 5));
	assert((ret == 0) == success);
	if (delayed && success)
		assert(elapsed >= 1.2);
	if (stop_timeout) {
		assert(interrupts == 1);
		assert(elapsed >= 10);
		/* The backend cannot restore ptrace settings without a stop. Finish
		 * the deliberately suppressed interrupt only for harness cleanup.
		 */
		assert(syscall(SYS_ptrace, PTRACE_INTERRUPT, tid, NULL, 0) == 0);
		assert(waitpid(tid, &status, __WALL) == tid);
		assert(WIFSTOPPED(status));
	} else if (!target_dead && (!driver || completed)) {
		assert(ptrace(PTRACE_GETSIGMASK, tid, sizeof(restored_mask), &restored_mask) == 0);
		assert(!memcmp(&original_mask, &restored_mask, sizeof(original_mask)));
	}
	if (success) {
		FILE *file;
		char line[256];

		assert(backend->resume_devices_late(pid, &map) == 0);
		file = fopen(mapping, "r");
		assert(file);
		assert(fgets(line, sizeof(line), file));
		assert(!strcmp(line, "GPU-01000000-0000-0000-0000-000000000000="
				     "GPU-02000000-0000-0000-0000-000000000000\n"));
		assert(fgetc(file) == EOF);
		fclose(file);
		if (!strcmp(behavior, "notify-eperm"))
			check_log("Unable to stop CUDA restore tid");
		/* The options of the seccomp thread were set again after
		 * checkpoint and after restore, without SUSPEND_SECCOMP.
		 */
		if (target_seccomp)
			assert(seccomp_thread_options >= 2);
	} else if (!completed) {
		if (stop_timeout) {
			check_log("stop CUDA restore thread");
			check_log("timed out");
		} else if (driver) {
			check_log("failed during Driver API operation");
		} else if (!strcmp(behavior, "fault") || !strcmp(behavior, "late-fault")) {
			/* The in-call fault was already consumed by the CLI monitor. */
			assert(interrupts == (unsigned int)!strcmp(behavior, "late-fault"));
			if (!strcmp(behavior, "fault")) {
				check_log("stopped by signal 11");
				check_log("fault: code 1, address 0");
			} else {
				check_log("stopped unexpectedly with signal 11");
			}
		} else if (!strcmp(behavior, "hang") || !strcmp(behavior, "init-hang") || delayed) {
			check_log("timed out");
		} else if (freezing) {
			assert(criu_timed_out);
			check_log("interrupted by CRIU's freezing timeout");
		} else if (!strcmp(behavior, "late-group-stop")) {
			assert(interrupts == 1);
			check_log("stopped unexpectedly with signal 19");
		} else {
			check_log("unexpectedly signaled with 9");
		}
	}
	before_cleanup = file_size(marker);
	ret = backend->dump_finish(success ? 0 : -1);
	assert((ret == 0) == completed);
	if (!completed)
		assert(file_size(marker) == before_cleanup); /* No API reentry during rollback. */
	api_caller = check_api_calls(marker, completed, driver, restore_fault, helper_error);
	backend->fini(CR_PLUGIN_STAGE__DUMP, ret);
	assert(waitpid(api_caller, &status, __WALL | WNOHANG) == -1 && errno == ECHILD);
	if (!driver)
		assert(kill(api_caller, 0) == -1 && errno == ESRCH);
	/* The Driver API backend kills failed targets; reap their exit events. */
	if (strcmp(behavior, "target-kill") && (!driver || completed))
		assert(kill(pid, SIGKILL) == 0);
	if (driver && !target_dead) {
		assert(waitpid(tid, &status, __WALL) == tid);
		assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
	}
	assert(waitpid(pid, &status, __WALL) == pid);
	assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);

	close(target_pipe[0]);
	fclose(log_file);
	unlink(marker);
	unlink(trigger);
	unlink(mapping);
	unlink(log_path);
	unlink(state_path);
}

static int count_api_calls(const char *path, const char *operation, pid_t pid)
{
	FILE *file = fopen(path, "r");
	char name[32];
	int target, caller, count = 0;

	assert(file);
	while (fscanf(file, "%31s %d %d", name, &target, &caller) == 3)
		count += !strcmp(name, operation) && target == pid;
	assert(feof(file));
	fclose(file);
	return count;
}

static void reset_mock_environment(const char *directory, const char *name, char *marker, size_t size)
{
	char path[512];

	assert(snprintf(marker, size, "%s/%s.calls", directory, name) < (int)size);
	assert(snprintf(path, sizeof(path), "%s/%s.state", directory, name) < (int)sizeof(path));
	assert(setenv("CRIU_CUDA_MOCK_API_MARKER", marker, 1) == 0);
	assert(setenv("CRIU_CUDA_MOCK_STATE_FILE", path, 1) == 0);
	assert(setenv("CRIU_CUDA_MOCK_STATE_PER_PID", "1", 1) == 0);
	assert(unsetenv("CRIU_CUDA_MOCK_CHECKPOINT_BEHAVIOR") == 0);
	assert(unsetenv("CRIU_CUDA_MOCK_CHECKPOINT_ERROR_AFTER_TRANSITION") == 0);
	assert(unsetenv("CRIU_CUDA_MOCK_RESTORE_BEHAVIOR") == 0);
	assert(unsetenv("CRIU_CUDA_MOCK_RESTORE_TID") == 0);
	assert(unsetenv("CRIU_CUDA_MOCK_DEVICE_MAP_MARKER") == 0);
	assert(snprintf(path, sizeof(path), "%s/%s.log", directory, name) < (int)sizeof(path));
	log_file = fopen(path, "w+");
	assert(log_file);
	cuda_plugin_timeout = 0;
}

static void reap_killed(pid_t pid)
{
	int status;

	kill(pid, SIGKILL);
	assert(waitpid(pid, &status, __WALL) == pid);
	assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
}

/* PAUSE_DEVICES locked a task, but CRIU failed to seize it. Rollback must
 * unlock it without ptrace because its restore thread is still running.
 */
static void run_unseized_rollback(const char *directory, const struct cuda_plugin_backend *backend)
{
	char marker[512], trigger[512];
	pid_t pid, tid;

	reset_mock_environment(directory, "unseized", marker, sizeof(marker));
	assert(snprintf(trigger, sizeof(trigger), "%s/unseized.fault", directory) < (int)sizeof(trigger));
	assert(pipe(target_pipe) == 0);
	pid = start_target(trigger, false, false, &tid);
	close(target_pipe[0]);

	assert(backend->init(CR_PLUGIN_STAGE__DUMP) == 0);
	assert(backend->probe(false) == 0);
	assert(backend->pause_devices(pid) == 0);
	assert(backend->dump_finish(-1) == 0);
	assert(count_api_calls(marker, "lock", pid) == 1);
	assert(count_api_calls(marker, "unlock", pid) == 1);
	check_log("was not seized");
	backend->fini(CR_PLUGIN_STAGE__DUMP, -1);

	reap_killed(pid);
	fclose(log_file);
}

/* A fault on one task must not prevent rollback of the other tasks. */
static void run_sibling_rollback(const char *directory, const struct cuda_plugin_backend *backend)
{
	char marker[512], trigger_a[512], trigger_b[512], value[32];
	pid_t pid_a, pid_b, tid;
	int ret;

	reset_mock_environment(directory, "sibling", marker, sizeof(marker));
	assert(snprintf(trigger_a, sizeof(trigger_a), "%s/sibling-a.fault", directory) <
	       (int)sizeof(trigger_a));
	assert(snprintf(trigger_b, sizeof(trigger_b), "%s/sibling-b.fault", directory) <
	       (int)sizeof(trigger_b));
	assert(pipe(target_pipe) == 0);
	pid_b = start_target(trigger_b, false, false, &tid);
	close(target_pipe[0]);
	assert(pipe(target_pipe) == 0);
	pid_a = start_target(trigger_a, false, false, &tid);
	snprintf(value, sizeof(value), "%d", target_pipe[0]);
	assert(setenv("CRIU_CUDA_MOCK_TARGET_PIPE", value, 1) == 0);
	snprintf(value, sizeof(value), "%d", pid_a);
	assert(setenv("CRIU_CUDA_MOCK_TARGET_PID", value, 1) == 0);

	assert(backend->init(CR_PLUGIN_STAGE__DUMP) == 0);
	assert(backend->probe(false) == 0);
	assert(backend->pause_devices(pid_b) == 0);
	assert(backend->pause_devices(pid_a) == 0);
	stop_target(pid_b);
	stop_target(pid_a);
	assert(backend->checkpoint_devices(pid_b) == 0);

	assert(setenv("CRIU_CUDA_MOCK_FAULT_TRIGGER", trigger_a, 1) == 0);
	assert(setenv("CRIU_CUDA_MOCK_CHECKPOINT_BEHAVIOR", "fault", 1) == 0);
	assert(backend->checkpoint_devices(pid_a) != 0);
	assert(unsetenv("CRIU_CUDA_MOCK_CHECKPOINT_BEHAVIOR") == 0);
	/* No new operation starts after the fault. */
	assert(backend->pause_devices(getpid()) != 0);

	ret = backend->dump_finish(-1);
	assert(ret != 0);
	assert(count_api_calls(marker, "restore", pid_b) == 1);
	assert(count_api_calls(marker, "unlock", pid_b) == 1);
	assert(count_api_calls(marker, "restore", pid_a) == 0);
	assert(count_api_calls(marker, "unlock", pid_a) == 0);
	backend->fini(CR_PLUGIN_STAGE__DUMP, ret);

	close(target_pipe[0]);
	reap_killed(pid_b);
	reap_killed(pid_a);
	fclose(log_file);
}

/* The multi-task cases leave per-task mock state files behind. */
static void remove_files(const char *path)
{
	DIR *directory = opendir(path);
	struct dirent *entry;

	assert(directory);
	while ((entry = readdir(directory))) {
		if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, ".."))
			assert(unlinkat(dirfd(directory), entry->d_name, 0) == 0);
	}
	closedir(directory);
}

static int run_isolated(const char *directory, const char *name, const struct cuda_plugin_backend *backend,
			void (*test)(const char *directory, const struct cuda_plugin_backend *backend))
{
	pid_t child;
	int status;

	/* Start without a fault trigger or call log from the other backend. */
	remove_files(directory);
	child = fork();
	assert(child >= 0);
	if (!child) {
		assert(setpgid(0, 0) == 0);
		alarm(8);
		test(directory, backend);
		_exit(0);
	}
	assert(waitpid(child, &status, 0) == child);
	kill(-child, SIGKILL);
	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		fprintf(stderr, "%s guard case %s failed (status %#x), artifacts: %s\n",
			backend->name, name, status, directory);
		return 1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	const char *tmpdir = getenv("TMPDIR") ?: "/tmp";
	char directory[PATH_MAX];
	const char *driver_cases[] = { "success", "api-error", "fault", "trap", "blocked-fault",
				       "target-exit", "target-kill", "restore-fault", "init-fault",
				       "unrelated", "notify-eperm", "seccomp", NULL };
	const char *cli_cases[] = { "success", "api-error", "fault", "late-fault", "late-group-stop",
				    "hang", "criu-timeout", "criu-timeout-finite", "signal", "exit",
				    "delayed-success", "delayed-timeout", "delayed-success-closed-output",
				    "delayed-timeout-closed-output", "stop-timeout", "stop-timeout-finite", "seccomp",
				    NULL };
	const struct cuda_plugin_backend *backends[] = { &cuda_driver_backend, &cuda_cli_backend };
	unsigned int i, j;

	assert(snprintf(directory, sizeof(directory), "%s/criu-cuda-backend-guard-XXXXXX", tmpdir) <
	       (int)sizeof(directory));
	assert(mkdtemp(directory));
	compel_log_init(compel_test_log, 4);
	opts.final_state = TASK_DEAD;
	opts.timeout = 1;
	for (j = 0; j < sizeof(backends) / sizeof(backends[0]); j++) {
		const char **cases = j ? cli_cases : driver_cases;

		for (i = 0; cases[i]; i++) {
			pid_t child;
			int status;

			if (argc > 1 && strcmp(argv[1], cases[i]))
				continue;
			child = fork();
			assert(child >= 0);
			if (!child) {
				assert(setpgid(0, 0) == 0);
				/* Bound regressions that leave an API call or waitpid blocked. */
				alarm(!strncmp(cases[i], "stop-timeout", strlen("stop-timeout")) ? 15 : 8);
				run_case(directory, cases[i], backends[j]);
				_exit(0);
			}
			assert(waitpid(child, &status, 0) == child);
			kill(-child, SIGKILL);
			if (!WIFEXITED(status) || WEXITSTATUS(status)) {
				fprintf(stderr, "%s guard case %s failed (status %#x), artifacts: %s\n",
					backends[j]->name, cases[i], status, directory);
				return 1;
			}
		}
	}
	for (j = 0; j < sizeof(backends) / sizeof(backends[0]); j++) {
		if ((argc <= 1 || !strcmp(argv[1], "unseized")) &&
		    run_isolated(directory, "unseized", backends[j], run_unseized_rollback))
			return 1;
		if ((argc <= 1 || !strcmp(argv[1], "sibling")) &&
		    run_isolated(directory, "sibling", backends[j], run_sibling_rollback))
			return 1;
	}
	remove_files(directory);
	assert(rmdir(directory) == 0);
	puts("CUDA backend guard regression tests PASS");
	return 0;
}
