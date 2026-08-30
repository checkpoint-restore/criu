/* CPU-only integration tests for guarded CUDA backend calls.
 *
 * Run the production backend against libcuda.c and a real ptrace target. The
 * fake restore thread faults only after the checkpoint API starts waiting.
 */
#include <assert.h>
#include <dirent.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
static pid_t target_pid;
static pid_t other_child;
static volatile sig_atomic_t other_status = -1;
static int signal_tid;
static int signal_thread_done;

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

static void *signal_thread(void *arg)
{
	sigset_t mask;

	(void)arg;
	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);
	assert(pthread_sigmask(SIG_UNBLOCK, &mask, NULL) == 0);
	__atomic_store_n(&signal_tid, syscall(SYS_gettid), __ATOMIC_RELEASE);
	while (!__atomic_load_n(&signal_thread_done, __ATOMIC_ACQUIRE))
		usleep(1000);
	return NULL;
}
static volatile sig_atomic_t criu_timed_out;

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

/* SUSPEND_SECCOMP requires CAP_SYS_ADMIN. Keep every other ptrace operation
 * real, but omit this unrelated option so the test can run as an ordinary user.
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
	if (request == PTRACE_SETOPTIONS)
		data &= ~PTRACE_O_SUSPEND_SECCOMP;
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
		assert(setrlimit(RLIMIT_CORE, &no_core) == 0);
		if (!threaded)
			target_thread(&args);
		assert(pthread_create(&thread, NULL, target_thread, &args) == 0);
		for (;;)
			pause();
	}
	close(ready[1]);
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
		if (driver)
			assert(caller == api_caller);
		else {
			assert(waitpid(caller, &status, __WALL | WNOHANG) == -1 && errno == ECHILD);
			assert(kill(caller, 0) == -1 && errno == ESRCH);
		}
		assert((caller == getpid()) == driver);
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
	char text[16384];
	size_t size;

	rewind(log_file);
	size = fread(text, 1, sizeof(text) - 1, log_file);
	text[size] = '\0';
	if (!strstr(text, expected)) {
		fprintf(stderr, "Expected log to contain '%s':\n%s", expected, text);
		abort();
	}
}

static void run_case(const char *directory, const char *behavior,
		     const struct cuda_plugin_backend *backend)
{
	char marker[512], trigger[512], log_path[512], state_path[512];
	bool success = !strcmp(behavior, "success") || !strcmp(behavior, "unrelated") ||
		       !strncmp(behavior, "delayed-success", strlen("delayed-success"));
	bool helper_error = !strcmp(behavior, "exit");
	bool completed = success || !strcmp(behavior, "api-error") || helper_error;
	bool delayed = !strncmp(behavior, "delayed-", strlen("delayed-"));
	bool stop_timeout = !strncmp(behavior, "stop-timeout", strlen("stop-timeout"));
	bool freezing = !strncmp(behavior, "criu-timeout", strlen("criu-timeout"));
	bool driver = backend == &cuda_driver_backend;
	bool restore_fault = !strcmp(behavior, "restore-fault");
	bool init_fault = !strcmp(behavior, "init-fault");
	bool foreign = !strcmp(behavior, "foreign-sigchld");
	bool unrelated = !strcmp(behavior, "unrelated") || !strcmp(behavior, "coalesced");
	bool target_dead = !strcmp(behavior, "target-exit") || !strcmp(behavior, "target-kill");
	k_rtsigset_t original_mask, restored_mask;
	sigset_t original_tracer_mask, tracer_mask;
	struct sigaction original_action, action;
	struct timespec start, end;
	pid_t pid, tid, api_caller;
	pthread_t notifier;
	int other_pipe[2] = { -1, -1 };
	char value[32];
	off_t before_cleanup;
	int status, ret;
	double elapsed;

	assert(snprintf(marker, sizeof(marker), "%s/%s.calls", directory, behavior) > 0);
	assert(snprintf(trigger, sizeof(trigger), "%s/%s.fault", directory, behavior) > 0);
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
	if (restore_fault || init_fault)
		assert(setenv("CRIU_CUDA_MOCK_CHECKPOINT_BEHAVIOR", "success", 1) == 0);
	if (restore_fault)
		assert(setenv("CRIU_CUDA_MOCK_RESTORE_BEHAVIOR", "fault", 1) == 0);
	if (init_fault)
		assert(setenv("CRIU_CUDA_MOCK_INIT_FAULT", "1", 1) == 0);
	if (!strcmp(behavior, "blocked-fault"))
		assert(setenv("CRIU_CUDA_MOCK_CHECKPOINT_BEHAVIOR", "fault", 1) == 0);
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
	if (freezing)
		assert(setenv("CRIU_CUDA_MOCK_CHECKPOINT_BEHAVIOR", "hang", 1) == 0);
	if (!strcmp(behavior, "criu-timeout-finite") || !strcmp(behavior, "stop-timeout-finite"))
		cuda_plugin_timeout = 30;
	log_file = fopen(log_path, "w+");
	assert(log_file);
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
		snprintf(value, sizeof(value), "%d", other_child);
		assert(setenv("CRIU_CUDA_MOCK_OTHER_PID", value, 1) == 0);
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
	if (foreign) {
		assert(pthread_create(&notifier, NULL, signal_thread, NULL) == 0);
		while (!__atomic_load_n(&signal_tid, __ATOMIC_ACQUIRE))
			usleep(1000);
		snprintf(value, sizeof(value), "%d", signal_tid);
		assert(setenv("CRIU_CUDA_MOCK_SIGNAL_TID", value, 1) == 0);
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

		if (foreign) {
			__atomic_store_n(&signal_thread_done, 1, __ATOMIC_RELEASE);
			assert(pthread_join(notifier, NULL) == 0);
		}
		assert(sigprocmask(SIG_SETMASK, NULL, &tracer_mask) == 0);
		assert(sigaction(SIGCHLD, NULL, &action) == 0);
		assert(action.sa_sigaction == original_action.sa_sigaction);
		assert(action.sa_flags == original_action.sa_flags);
		for (signal = 1; signal < NSIG; signal++) {
			assert(sigismember(&tracer_mask, signal) == sigismember(&original_tracer_mask, signal));
			assert(sigismember(&action.sa_mask, signal) == sigismember(&original_action.sa_mask, signal));
		}
		if (unrelated) {
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
	} else if (!target_dead) {
		assert(ptrace(PTRACE_GETSIGMASK, tid, sizeof(restored_mask), &restored_mask) == 0);
		assert(!memcmp(&original_mask, &restored_mask, sizeof(original_mask)));
	}
	if (success) {
		assert(backend->resume_devices_late(pid, NULL) == 0);
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
	if (driver && !completed && !stop_timeout && strcmp(behavior, "late-fault") && strcmp(behavior, "late-group-stop")) {
		assert(backend->init(CR_PLUGIN_STAGE__DUMP) == -1);
		assert(backend->probe(false) == -1);
		assert(file_size(marker) == before_cleanup);
	}
	assert(waitpid(api_caller, &status, __WALL | WNOHANG) == -1 && errno == ECHILD);
	if (!driver)
		assert(kill(api_caller, 0) == -1 && errno == ESRCH);
	/* Faults stay stopped. Only the harness kills the target for cleanup. */
	if (strcmp(behavior, "target-kill"))
		assert(kill(pid, SIGKILL) == 0);
	if (driver && !target_dead) {
		assert(waitpid(tid, &status, __WALL) == tid);
		assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
	}
	assert(waitpid(pid, &status, __WALL) == pid);
	assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);

	fclose(log_file);
	unlink(marker);
	unlink(trigger);
	unlink(log_path);
	unlink(state_path);
}

int main(int argc, char **argv)
{
	char directory[] = "/tmp/criu-cuda-backend-guard-XXXXXX";
	const char *driver_cases[] = { "success", "api-error", "fault", "trap", "late-fault", "late-group-stop",
				       "blocked-fault", "target-exit", "target-kill", "restore-fault", "init-fault", "unrelated",
				       "coalesced", "foreign-sigchld", "stop-timeout", "stop-timeout-finite", NULL };
	const char *cli_cases[] = { "success", "api-error", "fault", "late-fault", "late-group-stop",
				    "hang", "criu-timeout", "criu-timeout-finite", "signal", "exit",
				    "delayed-success", "delayed-timeout", "delayed-success-closed-output",
				    "delayed-timeout-closed-output", "stop-timeout", "stop-timeout-finite", NULL };
	const struct cuda_plugin_backend *backends[] = { &cuda_driver_backend, &cuda_cli_backend };
	unsigned int i, j;

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
	assert(rmdir(directory) == 0);
	puts("CUDA backend guard regression tests PASS");
	return 0;
}
