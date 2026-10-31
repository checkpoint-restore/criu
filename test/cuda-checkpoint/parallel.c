/* CPU-only tests: production batch + production per-TID core primitive,
 * actual Linux ptrace tracees, and an in-process thread-safe fake Driver API.
 * Reuse the existing serial harness's logging/link stubs and ptrace wrapper.
 */
#define main serial_guard_main
#include "backend-guard.c"
#undef main
#include "../../plugins/cuda/cuda_plugin_driver.c"
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/prctl.h>

enum injected_fault { NONE, API_ERROR, SEGV, BUS, EXIT, EARLY_STOP, FORK, CLONE, CREATE_FAIL, RESUME_FAIL, TIMEOUT };
struct fake_target {
	pid_t pid;
	atomic_int command;
	atomic_int observed_ppid;
	CUprocessState state;
	unsigned int delay_ms;
	int mask_signal;
	bool filter;
};
static struct fake_target *fake;
static unsigned int fake_count;
static enum injected_fault inject;
static atomic_int api_active, api_peak, api_finished;
static int init_count, create_calls;
static bool inject_eintr;
static pid_t master_tid;

int __real_pthread_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*fn)(void *), void *arg)
{
	create_calls++;
	if (inject == CREATE_FAIL && create_calls == 3) /* serial first + A started, B fails */
		return EAGAIN;
	return __real_pthread_create(thread, attr, fn, arg);
}

pid_t __real_waitpid(pid_t, int *, int);
pid_t __wrap_waitpid(pid_t pid, int *status, int options)
{
	assert(syscall(SYS_gettid) == master_tid);
	assert(pid > 0); /* catches accidental waitpid(-1), including error drain */
	if (inject_eintr) {
		inject_eintr = false;
		errno = EINTR;
		return -1;
	}
	return __real_waitpid(pid, status, options);
}

static struct fake_target *find_fake(int pid)
{
	unsigned int i;

	for (i = 0; i < fake_count; i++)
		if (fake[i].pid == pid)
			return &fake[i];
	return NULL;
}

static CUresult fake_init(unsigned int flags)
{
	assert(syscall(SYS_gettid) == master_tid);
	init_count++;
	return CUDA_SUCCESS;
}

static CUresult fake_tid(int pid, int *tid)
{
	assert(syscall(SYS_gettid) == master_tid);
	if (!find_fake(pid))
		return CUDA_ERROR_INVALID_VALUE;
	*tid = pid;
	return CUDA_SUCCESS;
}

static CUresult fake_state(int pid, CUprocessState *state)
{
	*state = find_fake(pid)->state;
	return CUDA_SUCCESS;
}

static CUresult fake_unlock(int pid, CUcheckpointUnlockArgs *args)
{
	find_fake(pid)->state = CU_PROCESS_STATE_RUNNING;
	return CUDA_SUCCESS;
}

static CUresult fake_restore(int pid, CUcheckpointRestoreArgs *args)
{
	struct fake_target *target = find_fake(pid);
	int active = atomic_fetch_add(&api_active, 1) + 1, peak = atomic_load(&api_peak);
	unsigned int elapsed;

	assert(syscall(SYS_gettid) != master_tid);
	while (active > peak && !atomic_compare_exchange_weak(&api_peak, &peak, active))
		;
	if (target == &fake[2]) {
		if (inject == EARLY_STOP)
			assert(kill(pid, SIGSTOP) == 0);
		if (inject == SEGV || inject == BUS || inject == EXIT || inject == FORK || inject == CLONE)
			atomic_store(&target->command, inject);
	}
	/* Return promptly on target death, modelling the driver error-drain
	 * contract. An uninterruptible real driver is an external timeout case.
	 */
	for (elapsed = 0; elapsed < target->delay_ms; elapsed++) {
		if (kill(pid, 0) < 0 && errno == ESRCH)
			break;
		usleep(1000);
	}
	target->state = CU_PROCESS_STATE_LOCKED;
	atomic_fetch_sub(&api_active, 1);
	atomic_fetch_add(&api_finished, 1);
	return inject == API_ERROR && target == &fake[2] ? CUDA_ERROR_INVALID_VALUE : CUDA_SUCCESS;
}

static void install_filter(void)
{
	struct sock_filter instructions[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getppid, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog program = { .len = sizeof(instructions) / sizeof(instructions[0]), .filter = instructions };

	assert(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
	assert(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) == 0);
}

static int clone_target(void *arg)
{
	for (;;)
		pause();
	return 0;
}

static void spawn_fake(unsigned int i, bool filter)
{
	int ready[2], status;
	char byte;
	pid_t pid;

	assert(pipe(ready) == 0);
	fake[i].mask_signal = i % 2 ? SIGUSR1 : SIGUSR2;
	fake[i].filter = filter;
	pid = fork();
	assert(pid >= 0);
	if (!pid) {
		sigset_t mask;

		close(ready[0]);
		sigemptyset(&mask);
		sigaddset(&mask, fake[i].mask_signal);
		assert(sigprocmask(SIG_SETMASK, &mask, NULL) == 0);
		if (filter)
			install_filter();
		assert(write(ready[1], "x", 1) == 1);
		close(ready[1]);
		for (;;) {
			int command = atomic_exchange(&fake[i].command, NONE);

			atomic_store(&fake[i].observed_ppid, syscall(SYS_getppid));
			if (command == SEGV)
				*(volatile int *)0 = 1;
			if (command == BUS) {
				int fd = memfd_create("cuda-test-bus", 0);
				volatile char *mapping;

				assert(fd >= 0);
				mapping = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
				assert(mapping != MAP_FAILED);
				*mapping = 1;
			}
			if (command == EXIT)
				_exit(7);
			if (command == FORK) {
				pid_t child = fork();

				assert(child >= 0);
				if (!child)
					for (;;)
						pause();
			}
			if (command == CLONE) {
				char *stack = malloc(65536);

				assert(stack && clone(clone_target, stack + 65536, SIGUSR1, NULL) >= 0);
			}
			usleep(1000);
		}
	}
	close(ready[1]);
	assert(read(ready[0], &byte, 1) == 1);
	close(ready[0]);
	fake[i].pid = pid;
	fake[i].state = CU_PROCESS_STATE_CHECKPOINTED;
	assert(ptrace(PTRACE_SEIZE, pid, NULL, 0) == 0);
	assert(ptrace(PTRACE_INTERRUPT, pid, NULL, 0) == 0);
	assert(waitpid(pid, &status, __WALL) == pid && WIFSTOPPED(status));
}

static void interrupt_fake(pid_t tid)
{
	int status;

	assert(ptrace(PTRACE_INTERRUPT, tid, NULL, 0) == 0);
	assert(waitpid(tid, &status, __WALL) == tid && WIFSTOPPED(status));
}

static void assert_mask(unsigned int i)
{
	k_rtsigset_t actual, expected;

	ksigemptyset(&expected);
	ksigaddset(&expected, fake[i].mask_signal);
	assert(ptrace(PTRACE_GETSIGMASK, fake[i].pid, sizeof(actual), &actual) == 0);
	assert(!memcmp(&actual, &expected, sizeof(actual)));
}

static void reap_fake(unsigned int i)
{
	int status;
	pid_t w;

	assert(kill(fake[i].pid, SIGKILL) == 0 || errno == ESRCH);
	while ((w = waitpid(fake[i].pid, &status, __WALL)) > 0) {
		if (WIFEXITED(status) || WIFSIGNALED(status))
			break;
		ptrace(PTRACE_CONT, fake[i].pid, NULL, 0);
	}
	assert(w == fake[i].pid || (w < 0 && errno == ECHILD));
}

static void core_context_test(bool seccomp)
{
	struct criu_thread_context a = { 0 }, b = { 0 }, missing = { 0 };

	test_context_suspend_seccomp = seccomp;
	spawn_fake(0, seccomp);
	spawn_fake(1, false);
	fail_context_cont = fake[0].pid;
	assert(criu_resume_thread_context(fake[0].pid, &a) != 0);
	assert(!a.active);
	assert_mask(0); /* CONT failure unwinds the real mask/ptrace options */
	assert(criu_resume_thread_context(fake[0].pid, &a) == 0);
	test_context_suspend_seccomp = false;
	assert(criu_resume_thread_context(fake[1].pid, &b) == 0);
	assert(criu_resume_thread_context(fake[0].pid, &a) != 0);
	assert(criu_resume_thread_context(2147483647, &missing) == -ESRCH);
	usleep(20000);
	if (seccomp)
		assert(atomic_load(&fake[0].observed_ppid) == -1);
	/* Reverse completion with distinct masks catches a shared saved-mask slot. */
	interrupt_fake(fake[1].pid);
	assert(criu_restore_thread_context(&b) == 0);
	assert_mask(1);
	interrupt_fake(fake[0].pid);
	assert(criu_restore_thread_context(&a) == 0);
	assert_mask(0);
	assert(criu_restore_thread_context(&a) != 0);
	if (seccomp) {
		assert(ptrace(PTRACE_CONT, fake[0].pid, NULL, 0) == 0);
		usleep(20000);
		assert(atomic_load(&fake[0].observed_ppid) > 0); /* filter suspended again */
		interrupt_fake(fake[0].pid);
	}
	reap_fake(0);
	reap_fake(1);
	printf("PASS core contexts: reverse completion, masks, active/ESRCH guard, seccomp=%d\n", seccomp);
}

static void parallel_case(enum injected_fault fault, unsigned int limit)
{
	unsigned int i;
	int ret = 0, status;
	pid_t unrelated;

	memset(fake, 0, 4 * sizeof(*fake));
	fake_count = 4;
	inject = fault;
	create_calls = init_count = 0;
	atomic_store(&api_active, 0);
	atomic_store(&api_peak, 0);
	atomic_store(&api_finished, 0);
	for (i = 0; i < fake_count; i++) {
		spawn_fake(i, false);
		fake[i].delay_ms = i == 0 ? 1 : i == 1 ? 300 : 60;
	}
	if (fault == TIMEOUT)
		fake[1].delay_ms = 5000;
	unrelated = fork();
	assert(unrelated >= 0);
	if (!unrelated)
		_exit(23);
	cuda_api.init = fake_init;
	cuda_api.get_restore_tid = fake_tid;
	cuda_api.get_state = fake_state;
	cuda_api.restore = fake_restore;
	cuda_api.unlock = fake_unlock;
	cuda_driver_initialized = false;
	cuda_plugin_parallel = limit;
	cuda_plugin_timeout = fault == TIMEOUT ? 1 : 0;
	assert(cuda_driver_backend_init(CR_PLUGIN_STAGE__RESTORE) == 0);
	assert(cuda_driver_resume_devices_begin() == 0);
	assert(init_count == 1);
	for (i = 0; i < fake_count; i++) {
		if (fault == RESUME_FAIL && i == 2)
			reap_fake(i); /* exact TID is now ESRCH; A is already running */
		if ((fault == FORK || fault == CLONE) && i == 2)
			test_context_options = PTRACE_O_TRACEFORK | PTRACE_O_TRACECLONE;
		ret = cuda_driver_resume_devices_late(fake[i].pid, NULL);
		test_context_options = 0;
		if (ret)
			break;
	}
	inject_eintr = true;
	if (!ret)
		ret = cuda_driver_resume_devices_finish();
	if (fault == NONE) {
		assert(ret == 0);
		assert(atomic_load(&api_peak) >= 2);
		for (i = 0; i < fake_count; i++) {
			assert(fake[i].state == CU_PROCESS_STATE_RUNNING);
			assert_mask(i); /* GETSIGMASK also proves each tracee is stopped */
		}
	} else {
		assert(ret != 0);
		assert(cuda_driver_resume_devices_abort() == 0);
	}
	assert(cuda_driver_resume_devices_abort() == -ENOTSUP); /* idempotent */
	assert(!cuda_batch.ops && cuda_batch.count == 0);
	assert(atomic_load(&api_active) == 0);
	assert(init_count == 1);
	for (i = 0; i < fake_count; i++)
		reap_fake(i);
	assert(waitpid(unrelated, &status, 0) == unrelated);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == 23);
	printf("PASS parallel fault=%d peak=%d: joined, targets stopped/dead, unrelated child preserved\n",
	       fault, atomic_load(&api_peak));
}

int main(void)
{
	struct rlimit no_core = { 0, 0 };
	int fault;

	assert(setrlimit(RLIMIT_CORE, &no_core) == 0);
	alarm(60); /* CPU test supervisor kills this isolated pod on any timeout. */
	master_tid = syscall(SYS_gettid);
	test_ptrace_owner = master_tid;
	log_file = stderr;
	compel_log_init(compel_test_log, 4);
	fake = mmap(NULL, 4 * sizeof(*fake), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	assert(fake != MAP_FAILED);
	core_context_test(false);
	if (getenv("CRIU_TEST_REAL_SECCOMP")) {
		test_real_seccomp = true;
		core_context_test(true); /* requires CAP_SYS_ADMIN and unconfined tracer */
		test_real_seccomp = false;
	} else {
		puts("SKIP real SUSPEND_SECCOMP (set CRIU_TEST_REAL_SECCOMP=1 in privileged CPU pod)");
	}
	parallel_case(NONE, 2); /* bounded two-wave completion */
	for (fault = NONE; fault <= TIMEOUT; fault++)
		parallel_case(fault, 3);
	cuda_plugin_parallel = 1;
	assert(cuda_driver_resume_devices_begin() == -ENOTSUP);
	assert(!cuda_batch.ops);
	puts("PASS CUDA parallel suite (no GPU, dump, restore, or firewall operations)");
	return 0;
}
