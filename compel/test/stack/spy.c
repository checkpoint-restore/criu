#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/mman.h>

#include <common/page.h>

#include <compel/log.h>
#include <compel/infect-rpc.h>
#include <errno.h>

#include "parasite.h"

#define PARASITE_CMD_INC PARASITE_USER_CMDS
#define PARASITE_CMD_DEC PARASITE_USER_CMDS + 1

#define err_and_ret(msg)              \
	do {                          \
		fprintf(stderr, msg); \
		return -1;            \
	} while (0)

void *saved_data = NULL;

#define SAVED_DATA_MAX page_size()

void cleanup_saved_data(void)
{
	free(saved_data);
}

static void print_vmsg(unsigned int lvl, const char *fmt, va_list parms)
{
	printf("\tLC%u: ", lvl);
	vprintf(fmt, parms);
}

static void *get_parasite_rstack_start(struct parasite_ctl *ctl)
{
	void *rstack, *r_thread_stack, *rstack_start;

	compel_get_stack(ctl, &rstack, &r_thread_stack);

	rstack_start = rstack;
	if (r_thread_stack != NULL && r_thread_stack < rstack_start)
		rstack_start = r_thread_stack;

	return rstack_start;
}

static int page_writable(struct parasite_ctl *ctl, int pid, void *page)
{
	FILE *maps;
	size_t maps_line_len = 0;
	char *maps_line = NULL;
	char victim_maps_path[6 + 11 + 5 + 1];
	int written;
	int ret = 0;

	if (((uintptr_t)page & (page_size() - 1)) != 0) {
		fprintf(stderr, "Page address not aligned\n");
		ret = -1;
		goto done;
	}

	written = snprintf(victim_maps_path, sizeof(victim_maps_path), "/proc/%d/maps", pid);
	if (written < 0 || written >= sizeof(victim_maps_path)) {
		fprintf(stderr, "Failed to create path string to victim's /proc/%d/maps file\n", pid);
		ret = -1;
		goto done;
	}

	maps = fopen(victim_maps_path, "r");
	if (maps == NULL) {
		perror("Can't open victim's /proc/$pid/maps");
		ret = -1;
		goto done;
	}

	while (getline(&maps_line, &maps_line_len, maps) != -1) {
		unsigned long vmstart, vmend;
		char r, w;

		if (sscanf(maps_line, "%lx-%lx %c%c", &vmstart, &vmend, &r, &w) < 4) {
			fprintf(stderr, "Can't parse victim's /proc/%d/maps; line: %s\n", pid, maps_line);
			ret = -1;
			goto free_linebuf;
		}

		if (page >= (void *)vmstart && page < (void *)vmend) {
			if (w == 'w') {
				if (r != 'r') {
					fprintf(stderr, "Expecting writable memory to also be readable");
					ret = -1;
					goto free_linebuf;
				}
				ret = 1;
			}
			break;
		}
	}

	if (errno) {
		perror("Can't read victim's /proc/$pid/maps");
		ret = -1;
	}

free_linebuf:
	free(maps_line);
	fclose(maps);
done:
	return ret;
}

static void *read_proc_mem(int pid, void *offset, size_t len)
{
	char victim_mem_path[6 + 11 + 4 + 1];
	int written;
	int fd;
	void *data;
	ssize_t mem_read;

	written = snprintf(victim_mem_path, sizeof(victim_mem_path), "/proc/%d/mem", pid);
	if (written < 0 || written >= sizeof(victim_mem_path)) {
		fprintf(stderr, "Failed to create path string to victim's /proc/%d/mem file\n", pid);
		return NULL;
	}

	fd = open(victim_mem_path, O_RDONLY);
	if (fd < 0) {
		perror("Failed to open victim's /proc/$pid/mem file");
		return NULL;
	}

	data = malloc(len);
	if (data == NULL) {
		perror("Can't allocate memory to read victim's /proc/$pid/mem file");
		return NULL;
	}

	mem_read = pread(fd, data, len, (off_t)offset);
	if (mem_read == -1) {
		perror("Failed to read victim's /proc/$pid/mem file");
		goto freebuf;
	}

	return data;

freebuf:
	free(data);
	return NULL;
}

static int save_data_near_stack(struct parasite_ctl *ctl, int pid, void *stack, void **saved_data,
				size_t *saved_data_size)
{
	size_t page_mask = page_size() - 1;
	size_t saved_size = 0;
	size_t stack_size_last_page = (uintptr_t)stack & page_mask;
	void *next_page = stack;

	if (stack_size_last_page != 0) {
		size_t empty_space_last_page = page_size() - stack_size_last_page;
		saved_size = min(empty_space_last_page, (size_t)SAVED_DATA_MAX);
		next_page += page_size() - stack_size_last_page;
	}

	while (saved_size < SAVED_DATA_MAX && next_page != NULL) {
		switch (page_writable(ctl, pid, next_page)) {
		case 1:
			saved_size = min((size_t)(saved_size + page_size()), (size_t)SAVED_DATA_MAX);
			next_page += page_size();
			break;
		case 0:
			next_page = NULL;
			break;
		default:
			return -1;
		}
	}

	if (saved_size > 0) {
		void *sd;

		sd = read_proc_mem(pid, stack, saved_size);
		if (sd == NULL)
			return -1;

		*saved_data = sd;
	} else {
		*saved_data = NULL;
	}

	*saved_data_size = saved_size;

	return 0;
}

static int check_saved_data(struct parasite_ctl *ctl, int pid, void *stack, void *saved_data, size_t saved_data_size)
{
	if (saved_data != NULL) {
		void *current_data;

		current_data = read_proc_mem(pid, stack, saved_data_size);
		if (current_data == NULL)
			return -1;

		if (memcmp(saved_data, current_data, saved_data_size) != 0)
			return 1;
	}

	return 0;
}

static int do_infection(int pid)
{
	int state;
	struct parasite_ctl *ctl;
	struct infect_ctx *ictx;
	int *arg;
	void *stack;
	size_t saved_data_size;
	int saved_data_check;

	compel_log_init(print_vmsg, COMPEL_LOG_DEBUG);

	printf("Stopping task\n");
	state = compel_stop_task(pid);
	if (state < 0)
		err_and_ret("Can't stop task\n");

	printf("Preparing parasite ctl\n");
	ctl = compel_prepare(pid);
	if (!ctl)
		err_and_ret("Can't prepare for infection\n");

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
	if (compel_infect_no_daemon(ctl, 1, sizeof(int)))
		err_and_ret("Can't infect victim\n");

	if (atexit(cleanup_saved_data))
		err_and_ret("Can't register cleanup function with atexit\n");

	stack = get_parasite_rstack_start(ctl);
	if (save_data_near_stack(ctl, pid, stack, &saved_data, &saved_data_size))
		err_and_ret("Can't save data above stack\n");

	if (compel_start_daemon(ctl))
		err_and_ret("Can't start daemon in victim\n");

	/*
	 * Now get the area with arguments and run two
	 * commands one by one.
	 */
	arg = compel_parasite_args(ctl, int);

	printf("Running cmd 1\n");
	*arg = 137;
	if (compel_rpc_call_sync(PARASITE_CMD_INC, ctl))
		err_and_ret("Can't run parasite command 1\n");

	printf("Running cmd 2\n");
	*arg = 404;
	if (compel_rpc_call_sync(PARASITE_CMD_DEC, ctl))
		err_and_ret("Can't run parasite command 2\n");

	saved_data_check = check_saved_data(ctl, pid, stack, saved_data, saved_data_size);
	if (saved_data_check == -1)
		err_and_ret("Could not check saved data\n");
	if (saved_data_check != 0)
		err_and_ret("Saved data unexpectedly modified\n");

	/*
	 * Done. Cure and resume the task.
	 */
	printf("Curing\n");
	if (compel_cure(ctl))
		err_and_ret("Can't cure victim\n");

	if (compel_resume_task(pid, state, state))
		err_and_ret("Can't unseize task\n");

	printf("Done\n");

	return 0;
}

static inline int chk(int fd, int val)
{
	int v = 0;

	if (read(fd, &v, sizeof(v)) != sizeof(v))
		return 1;

	printf("%d, want %d\n", v, val);
	return v != val;
}

int main(int argc, char **argv)
{
	int p_in[2], p_out[2], p_err[2], pid, i, err = 0;

	/*
	 * Prepare IO-s and fork the victim binary
	 */
	if (pipe(p_in) || pipe(p_out) || pipe(p_err)) {
		perror("Can't make pipe");
		return -1;
	}

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
	 * Tell the little guy some numbers
	 */
	i = 1;
	if (write(p_in[1], &i, sizeof(i)) != sizeof(i))
		return 1;
	i = 42;
	if (write(p_in[1], &i, sizeof(i)) != sizeof(i))
		return 1;

	printf("Checking the victim alive\n");
	err = chk(p_out[0], 1);
	if (err)
		return 1;
	err = chk(p_out[0], 42);
	if (err)
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
	i = 1234;
	if (write(p_in[1], &i, sizeof(i)) != sizeof(i))
		return 1;
	i = 4096;
	if (write(p_in[1], &i, sizeof(i)) != sizeof(i))
		return 1;

	/*
	 * Stop the victim and check the infection went well
	 */
	printf("Closing victim stdin\n");
	close(p_in[1]);
	printf("Waiting for victim to die\n");
	wait(NULL);

	printf("Checking the result\n");

	/* These two came from parasite */
	err = chk(p_out[0], 138);
	err |= chk(p_out[0], 403);

	/* These two came from post-infect */
	err |= chk(p_out[0], 1234);
	err |= chk(p_out[0], 4096);

	if (!err)
		printf("All OK\n");
	else
		printf("Something went WRONG\n");

	return 0;
}
