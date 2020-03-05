#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/syscall.h>

static void print_vmsg(unsigned int lvl, const char *fmt, va_list parms)
{
	printf("\tLC%u: ", lvl);
	vprintf(fmt, parms);
}

static int do_rsetsid(int pid)
{
#define err_and_ret(msg) do { fprintf(stderr, msg); return -1; } while (0)

	int state;
	long ret;
	struct parasite_ctl *ctl;

	compel_log_init(print_vmsg, COMPEL_LOG_DEBUG);

	printf("Stopping task\n");
	state = compel_stop_task(pid);
	if (state < 0)
		err_and_ret("Can't stop task");

	printf("Preparing parasite ctl\n");
	ctl = compel_prepare(pid);
	if (!ctl)
		err_and_ret("Can't prepare for infection");

	ret = -1000;
	if (compel_syscall(ctl, __NR_getpid, &ret, 0, 0, 0, 0, 0, 0) < 0)
		err_and_ret("Can't run rgetpid");

	printf("Remote getpid returned %ld\n", ret);
	if (ret != pid)
		err_and_ret("Pid mismatch!");

	ret = -1000;
	if (compel_syscall(ctl, __NR_setsid, &ret, 0, 0, 0, 0, 0, 0) < 0)
		err_and_ret("Can't run rsetsid");
	printf("Remote setsid returned %ld\n", ret);

	/*
	 * Done. Cure and resume the task.
	 */
	printf("Curing\n");
	if (compel_cure(ctl))
		err_and_ret("Can't cure victim");

	if (compel_resume_task(pid, state, state))
		err_and_ret("Can't unseize task");

	printf("Done\n");
	return 0;
}

static inline int chk(int fd, int val)
{
	int v = 0;

	read(fd, &v, sizeof(v));
	printf("%d, want %d\n", v, val);
	return v == val;
}

int main(int argc, char **argv)
{
	int p_in[2], p_out[2], p_err[2], pid, i, pass = 1, sid;

	/*
	 * Prepare IO-s and fork the victim binary
	 */
	if (pipe(p_in) || pipe(p_out) || pipe(p_err)) {
		perror("Can't make pipe");
		return -1;
	}

	pid = vfork();
	if (pid == 0) {
		close(p_in[1]);  dup2(p_in[0], 0);  close(p_in[0]);
		close(p_out[0]); dup2(p_out[1], 1); close(p_out[1]);
		close(p_err[0]); dup2(p_err[1], 2); close(p_err[1]);
		execl("./victim", "victim", NULL);
		exit(1);
	}

	close(p_in[0]); close(p_out[1]); close(p_err[1]);
	sid = getsid(0);

	/*
	 * Kick the victim once
	 */
	i = 0;
	write(p_in[1], &i, sizeof(i));

	printf("Checking the victim session to be %d\n", sid);
	pass = chk(p_out[0], sid);
	if (!pass)
		return 1;

	/*
	 * Now do the infection with parasite.c
	 */

	printf("Setsid() the victim\n");
	if (do_rsetsid(pid))
		return 1;

	/*
	 * Kick the victim again so it tells new session
	 */
	write(p_in[1], &i, sizeof(i));

	/*
	 * Stop the victim and check the intrusion went well
	 */
	printf("Closing victim stdin\n");
	close(p_in[1]);
	printf("Waiting for victim to die\n");
	wait(NULL);

	printf("Checking the new session to be %d\n", pid);
	pass = chk(p_out[0], pid);

	if (pass)
		printf("All OK\n");
	else
		printf("Something went WRONG\n");

	return 0;
}
