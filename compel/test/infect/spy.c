#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>

#include <compel/compel.h>
#include "parasite.h"

#define PARASITE_CMD_INC	PARASITE_USER_CMDS
#define PARASITE_CMD_DEC	PARASITE_USER_CMDS + 1

static void print_vmsg(unsigned int lvl, const char *fmt, va_list parms)
{
	printf("\tLC%u: ", lvl);
	vprintf(fmt, parms);
}

static int do_infection(int pid)
{
#define err_and_ret(msg) do { fprintf(stderr, msg); return -1; } while (0)

	int state;
	struct parasite_ctl *ctl;
	struct infect_ctx *ictx;
	int *arg;

	compel_log_init(print_vmsg, COMPEL_LOG_DEBUG);

	printf("Stopping task\n");
	state = compel_stop_task(pid);
	if (state < 0)
		err_and_ret("Can't stop task");

	printf("Preparing parasite ctl\n");
	ctl = compel_prepare(pid);
	if (!ctl)
		err_and_ret("Can't prepare for infection");

	printf("Configuring contexts\n");

	/*
	 * First -- the infection context. Most of the stuff
	 * is already filled by compel_prepare(), just set the
	 * log descriptor for parasite side, library cannot
	 * live w/o it.
	 */
	ictx = compel_infect_ctx(ctl);
	ictx->log_fd = STDERR_FILENO;

	parasite_setup_c_header(ctl);

	printf("Infecting\n");
	if (compel_infect(ctl, 1, sizeof(int)))
		err_and_ret("Can't infect victim");

	/*
	 * Now get the area with arguments and run two
	 * commands one by one.
	 */
	arg = compel_parasite_args(ctl, int);

	printf("Running cmd 1\n");
	*arg = 137;
	if (compel_rpc_call_sync(PARASITE_CMD_INC, ctl))
		err_and_ret("Can't run parasite command 1");

	printf("Running cmd 2\n");
	*arg = 404;
	if (compel_rpc_call_sync(PARASITE_CMD_DEC, ctl))
		err_and_ret("Can't run parasite command 2");

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
	int p_in[2], p_out[2], p_err[2], pid, i, pass = 1;

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

	/*
	 * Tell the little guy some numbers
	 */
	i = 1;  write(p_in[1], &i, sizeof(i));
	i = 42; write(p_in[1], &i, sizeof(i));

	printf("Checking the victim alive\n");
	pass = chk(p_out[0], 1);
	pass = chk(p_out[0], 42);
	if (!pass)
		return 1;

	/*
	 * Now do the infection with parasite.c
	 */

	printf("Infecting the victim\n");
	if (do_infection(pid))
		return 1;

	/*
	 * Tell the victim some more stuff to check it's alive
	 */
	i = 1234; write(p_in[1], &i, sizeof(i));
	i = 4096; write(p_in[1], &i, sizeof(i));

	/*
	 * Stop the victim and check the infection went well
	 */
	printf("Closing victim stdin\n");
	close(p_in[1]);
	printf("Waiting for victim to die\n");
	wait(NULL);

	printf("Checking the result\n");

	/* These two came from parasite */
	pass = chk(p_out[0], 138);
	pass = chk(p_out[0], 403);

	/* These two came from post-infect */
	pass = chk(p_out[0], 1234);
	pass = chk(p_out[0], 4096);

	if (pass)
		printf("All OK\n");
	else
		printf("Something went WRONG\n");

	return 0;
}
