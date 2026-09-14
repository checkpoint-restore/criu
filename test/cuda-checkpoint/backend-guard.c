/* CPU-only integration tests for guarded CUDA backend calls.
 *
 * Run the production backend against libcuda.c and a real ptrace target. The
 * fake restore thread faults only after the checkpoint API starts waiting.
 */
#include <assert.h>
#include <dirent.h>
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

#include "cr_options.h"
#include "cuda_plugin.h"
#include "pid.h"
#include "plugin.h"

struct cr_options opts;
unsigned int cuda_plugin_timeout = 1;

static FILE *log_file;
static unsigned int interrupts;
static bool fault_before_interrupt;
static bool group_stop_before_interrupt;
static volatile sig_atomic_t criu_timed_out;

int log_get_fd(void)
{
	return fileno(log_file);
}

void log_fini(void)
{
	/* The worker duplicated its inherited log to stderr before closing fds. */
	log_file = stderr;
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
	if (request == PTRACE_INTERRUPT) {
		interrupts++;
		if (fault_before_interrupt) {
			FILE *file = fopen(getenv("CRIU_CUDA_MOCK_FAULT_TRIGGER"), "w");
			siginfo_t info;

			fault_before_interrupt = false;
			assert(file && fclose(file) == 0);
			/* Inject a stop after the API reply, before the final interrupt.
			 * Observe it without consuming the event needed by the backend.
			 */
			assert(waitid(P_PID, pid, &info, WSTOPPED | WNOWAIT) == 0);
			assert(info.si_status == SIGSEGV);
		}
		if (group_stop_before_interrupt) {
			siginfo_t info;
			int status;

			group_stop_before_interrupt = false;
			assert(kill(pid, SIGSTOP) == 0);
			assert(waitpid(pid, &status, __WALL) == pid);
			assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
			/* Deliver SIGSTOP to enter a real group-stop, whose event is
			 * PTRACE_EVENT_STOP but whose signal is not SIGTRAP.
			 */
			assert(syscall(SYS_ptrace, PTRACE_CONT, pid, NULL, SIGSTOP) == 0);
			assert(waitid(P_PID, pid, &info, WSTOPPED | WNOWAIT) == 0);
			assert(info.si_status == (SIGSTOP | (PTRACE_EVENT_STOP << 8)));
		}
	}
	return syscall(SYS_ptrace, request, pid, addr, data);
}

static pid_t start_target(const char *trigger)
{
	int ready[2];
	char byte;
	pid_t pid;

	assert(pipe(ready) == 0);
	pid = fork();
	assert(pid >= 0);
	if (!pid) {
		const struct rlimit no_core = { 0, 0 };
		volatile int *invalid = NULL;
		struct timespec delay = { .tv_nsec = 1000000 };

		close(ready[0]);
		assert(setrlimit(RLIMIT_CORE, &no_core) == 0);
		assert(write(ready[1], "x", 1) == 1);
		close(ready[1]);
		for (;;) {
			if (access(trigger, F_OK) == 0)
				*invalid = 1;
			nanosleep(&delay, NULL);
		}
	}
	close(ready[1]);
	assert(read(ready[0], &byte, 1) == 1);
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

static pid_t check_api_calls(const char *path, bool completed, bool driver)
{
	FILE *file = fopen(path, "r");
	char operation[32];
	pid_t worker = -1;
	int target_pid, caller, checkpoints = 0, restores = 0, unlocks = 0;

	assert(file);
	while (fscanf(file, "%31s %d %d", operation, &target_pid, &caller) == 3) {
		int status;

		if (worker < 0)
			worker = caller;
		if (driver)
			assert(caller == worker);
		else {
			assert(waitpid(caller, &status, __WALL | WNOHANG) == -1 && errno == ECHILD);
			assert(kill(caller, 0) == -1 && errno == ESRCH);
		}
		assert(caller != getpid());
		checkpoints += !strcmp(operation, "checkpoint");
		restores += !strcmp(operation, "restore");
		unlocks += !strcmp(operation, "unlock");
	}
	assert(feof(file));
	fclose(file);
	assert(checkpoints == 1);
	assert(restores == (completed ? 1 : 0));
	assert(unlocks == (completed ? 1 : 0));
	assert(worker > 0);
	return worker;
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
	bool completed = !strcmp(behavior, "success") || !strcmp(behavior, "api-error");
	bool driver = backend == &cuda_driver_backend;
	k_rtsigset_t original_mask, restored_mask;
	struct timespec start, end;
	pid_t pid, worker;
	off_t before_cleanup;
	int status, ret;

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
	if (!strcmp(behavior, "api-error"))
		assert(setenv("CRIU_CUDA_MOCK_CHECKPOINT_ERROR_AFTER_TRANSITION", "1", 1) == 0);
	if (!strcmp(behavior, "init-hang"))
		assert(setenv("CRIU_CUDA_MOCK_INIT_HANG", "1", 1) == 0);
	if (!strcmp(behavior, "criu-timeout")) {
		assert(setenv("CRIU_CUDA_MOCK_CHECKPOINT_BEHAVIOR", "hang", 1) == 0);
		cuda_plugin_timeout = 30;
	}
	log_file = fopen(log_path, "w+");
	assert(log_file);
	pid = start_target(trigger);
	assert(backend->init(CR_PLUGIN_STAGE__DUMP) == 0);
	assert(backend->probe() == 0);
	assert(backend->pause_devices(pid) == 0);
	stop_target(pid);
	interrupts = 0;
	fault_before_interrupt = !strcmp(behavior, "late-fault");
	group_stop_before_interrupt = !strcmp(behavior, "late-group-stop");
	assert(ptrace(PTRACE_GETSIGMASK, pid, sizeof(original_mask), &original_mask) == 0);
	assert(clock_gettime(CLOCK_MONOTONIC, &start) == 0);
	if (!strcmp(behavior, "criu-timeout")) {
		struct sigaction action = { .sa_handler = freezing_timeout };

		assert(sigaction(SIGALRM, &action, NULL) == 0);
		alarm(1);
	}
	ret = backend->checkpoint_devices(pid);
	if (!strcmp(behavior, "init-hang")) {
		assert(ret == 0);
		ret = backend->resume_devices_late(pid);
	}
	assert(clock_gettime(CLOCK_MONOTONIC, &end) == 0);
	assert(end.tv_sec - start.tv_sec < 5);
	assert((ret == 0) == !strcmp(behavior, "success"));
	assert(ptrace(PTRACE_GETSIGMASK, pid, sizeof(restored_mask), &restored_mask) == 0);
	assert(!memcmp(&original_mask, &restored_mask, sizeof(original_mask)));
	if (!strcmp(behavior, "success")) {
		assert(backend->resume_devices_late(pid) == 0);
	} else if (!completed) {
		if (!strcmp(behavior, "fault") || !strcmp(behavior, "late-fault")) {
			/* The in-call fault was already consumed by the worker monitor. */
			assert(interrupts == (unsigned int)!strcmp(behavior, "late-fault"));
			if (!strcmp(behavior, "fault")) {
				check_log("stopped by signal 11");
				check_log("fault: code 1, address 0");
			} else {
				check_log("stopped unexpectedly with signal 11");
			}
		} else if (!strcmp(behavior, "hang") || !strcmp(behavior, "init-hang")) {
			check_log("timed out");
		} else if (!strcmp(behavior, "criu-timeout")) {
			assert(criu_timed_out);
			check_log("interrupted by CRIU's freezing timeout");
		} else if (!strcmp(behavior, "late-group-stop")) {
			assert(interrupts == 1);
			check_log("stopped unexpectedly with signal 19");
		} else if (!strcmp(behavior, "exit")) {
			check_log("exited with status 77");
		} else {
			check_log("unexpectedly signaled with 9");
		}
	}
	before_cleanup = file_size(marker);
	ret = backend->dump_finish(!strcmp(behavior, "success") ? 0 : -1);
	assert((ret == 0) == completed);
	if (!completed)
		assert(file_size(marker) == before_cleanup); /* No API reentry during rollback. */
	worker = check_api_calls(marker, completed, driver);
	backend->fini(CR_PLUGIN_STAGE__DUMP, ret);
	assert(waitpid(worker, &status, __WALL | WNOHANG) == -1 && errno == ECHILD);
	assert(kill(worker, 0) == -1 && errno == ESRCH);
	assert(kill(pid, SIGKILL) == 0);
	assert(waitpid(pid, &status, __WALL) == pid);
	assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
	fclose(log_file);
	unlink(marker);
	unlink(trigger);
	unlink(log_path);
	unlink(state_path);
}

int main(void)
{
	char directory[] = "/tmp/criu-cuda-backend-guard-XXXXXX";
	const char *cases[] = { "success", "api-error", "fault", "late-fault", "late-group-stop",
				"hang", "criu-timeout", "exit", "init-hang" };
	const struct cuda_plugin_backend *backends[] = { &cuda_driver_backend, &cuda_cli_backend };
	unsigned int i, j;

	assert(mkdtemp(directory));
	opts.final_state = TASK_DEAD;
	opts.timeout = 1;
	for (j = 0; j < sizeof(backends) / sizeof(backends[0]); j++) {
		for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
			pid_t child;
			int status;
			const char *behavior = !j || strcmp(cases[i], "exit") ? cases[i] : "signal";

			if (j && !strcmp(behavior, "init-hang"))
				continue; /* cuInit runs only in the Driver API worker. */
			child = fork();
			assert(child >= 0);
			if (!child) {
				assert(setpgid(0, 0) == 0);
				/* Bound regressions that leave an API call or waitpid blocked. */
				alarm(8);
				run_case(directory, behavior, backends[j]);
				_exit(0);
			}
			assert(waitpid(child, &status, 0) == child);
			/* Kill any target or worker leaked by an assertion or alarm. */
			kill(-child, SIGKILL);
			if (!WIFEXITED(status) || WEXITSTATUS(status)) {
				fprintf(stderr, "%s guard case %s failed (status %#x), artifacts: %s\n",
					backends[j]->name, behavior, status, directory);
				return 1;
			}
		}
	}
	assert(rmdir(directory) == 0);
	puts("CUDA backend guard regression tests PASS");
	return 0;
}
