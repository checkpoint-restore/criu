#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/syscall.h>

#include <compel/log.h>
#include <compel/infect.h>

/*
 * The victim's lowest executable VMA is a shared read-only mapping. compel
 * must start its remote syscalls from a private executable area instead:
 * the syscall instruction cannot be poked into a shared read-only mapping.
 */

static void print_vmsg(unsigned int lvl, const char *fmt, va_list parms)
{
	printf("\tLC%u: ", lvl);
	vprintf(fmt, parms);
}

static int remote_getpid(int pid)
{
	struct parasite_ctl *ctl;
	long ret = -1000;
	int state;

	compel_log_init(print_vmsg, COMPEL_LOG_DEBUG);

	state = compel_stop_task(pid);
	if (state < 0) {
		fprintf(stderr, "Can't stop task\n");
		return -1;
	}

	ctl = compel_prepare(pid, false);
	if (!ctl) {
		fprintf(stderr, "Can't prepare for infection\n");
		return -1;
	}

	if (compel_syscall(ctl, __NR_getpid, &ret, 0, 0, 0, 0, 0, 0) < 0) {
		fprintf(stderr, "Can't run a remote getpid()\n");
		return -1;
	}
	printf("Remote getpid returned %ld\n", ret);

	if (compel_cure(ctl)) {
		fprintf(stderr, "Can't cure victim\n");
		return -1;
	}
	if (compel_resume_task(pid, state, state)) {
		fprintf(stderr, "Can't unseize task\n");
		return -1;
	}

	return ret == pid ? 0 : -1;
}

int main(int argc, char **argv)
{
	int p_in[2], p_out[2], pid, ready, i = 0;

	if (pipe(p_in) || pipe(p_out)) {
		perror("Can't make pipe");
		return 1;
	}

	pid = vfork();
	if (pid == 0) {
		close(p_in[1]);
		dup2(p_in[0], 0);
		close(p_in[0]);
		close(p_out[0]);
		dup2(p_out[1], 1);
		close(p_out[1]);
		execl("./victim", "victim", NULL);
		exit(1);
	}

	close(p_in[0]);
	close(p_out[1]);

	if (read(p_out[0], &ready, sizeof(ready)) != sizeof(ready)) {
		fprintf(stderr, "Victim did not start\n");
		return 1;
	}
	if (!ready) {
		printf("SKIP: no room for a shared executable mapping below the victim's code\n");
		close(p_in[1]);
		waitpid(pid, NULL, 0);
		return 0;
	}

	if (remote_getpid(pid)) {
		printf("FAIL\n");
		return 1;
	}

	/* The victim still works after the infection. */
	if (write(p_in[1], &i, sizeof(i)) != sizeof(i) || read(p_out[0], &i, sizeof(i)) != sizeof(i) || i != pid) {
		printf("FAIL: victim does not answer after curing\n");
		return 1;
	}

	close(p_in[1]);
	waitpid(pid, NULL, 0);
	printf("PASS\n");
	return 0;
}
