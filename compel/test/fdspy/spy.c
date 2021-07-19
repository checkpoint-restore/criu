#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>

#include <compel/log.h>
#include <compel/infect-rpc.h>
#include <compel/infect-util.h>

#include "parasite.h"

#define PARASITE_CMD_GETFD PARASITE_USER_CMDS

static void print_vmsg(unsigned int lvl, const char *fmt, va_list parms)
{
	printf("\tLC%u: ", lvl);
	vprintf(fmt, parms);
}

static int do_infection(int pid, int *stolen_fd)
{
#define err_and_ret(msg)              \
	do {                          \
		fprintf(stderr, msg); \
		return -1;            \
	} while (0)

	int state;
	struct parasite_ctl *ctl;
	struct infect_ctx *ictx;

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

	printf("Stealing fd\n");
	if (compel_rpc_call(PARASITE_CMD_GETFD, ctl))
		err_and_ret("Can't run cmd");

	if (compel_util_recv_fd(ctl, stolen_fd))
		err_and_ret("Can't recv fd");

	if (compel_rpc_sync(PARASITE_CMD_GETFD, ctl))
		err_and_ret("Con't finalize cmd");

	printf("Stole %d fd\n", *stolen_fd);

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

static int check_pipe_ends(int wfd, int rfd)
{
	struct stat r, w;
	char aux[4] = "0000";

	printf("Check pipe ends are at hands\n");
	if (fstat(wfd, &w) < 0) {
		perror("Can't stat wfd");
		return 0;
	}

	if (fstat(rfd, &r) < 0) {
		perror("Can't stat rfd");
		return 0;
	}

	if (w.st_dev != r.st_dev || w.st_ino != r.st_ino) {
		perror("Pipe's not the same");
		return 0;
	}

	printf("Check pipe ends are connected\n");
	if (write(wfd, "1", 2) != 2) {
		fprintf(stderr, "write to pipe failed\n");
		return -1;
	}
	if (read(rfd, aux, sizeof(aux)) != sizeof(aux)) {
		fprintf(stderr, "read from pipe failed\n");
		return -1;
	}
	if (aux[0] != '1' || aux[1] != '\0') {
		fprintf(stderr, "Pipe connectivity lost\n");
		return 0;
	}

	return 1;
}

int main(int argc, char **argv)
{
	int p_in[2], p_out[2], p_err[2], pid, pass = 1, stolen_fd = -1;

	/*
	 * Prepare IO-s and fork the victim binary
	 */
	if (pipe(p_in) || pipe(p_out) || pipe(p_err)) {
		perror("Can't make pipe");
		return -1;
	}

	printf("Run the victim\n");
	pid = vfork();
	if (pid == 0) {
		close(p_in[1]);
		dup2(p_in[0], 0);
		close(p_in[0]);
		close(p_out[0]);
		dup2(p_out[1], 1);
		close(p_out[1]);
		close(p_err[0]);
		dup2(p_err[1], 2);
		close(p_err[1]);
		execl("./victim", "victim", NULL);
		exit(1);
	}

	close(p_in[0]);
	close(p_out[1]);
	close(p_err[1]);

	/*
	 * Now do the infection with parasite.c
	 */

	printf("Infecting the victim\n");
	if (do_infection(pid, &stolen_fd))
		return 1;

	/*
	 * Stop the victim and check the infection went well
	 */
	printf("Closing victim stdin\n");
	close(p_in[1]);
	printf("Waiting for victim to die\n");
	wait(NULL);

	printf("Checking the result\n");
	/*
	 * Stolen fd is the stderr of the task
	 * Check these are the ends of the same pipe
	 * and message passing works OK
	 */

	pass = check_pipe_ends(stolen_fd, p_err[0]);

	if (pass)
		printf("All OK\n");
	else
		printf("Something went WRONG\n");

	return 0;
}
