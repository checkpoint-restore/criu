#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include "crtools.h"
#include "ptrace.h"
#include "parasite-syscall.h"
#include "vma.h"
#include "log.h"

struct syscall_exec_desc {
	char *name;
	unsigned nr;
};

static struct syscall_exec_desc sc_exec_table[] = {
#define SYSCALL(__name, __nr) { .name = #__name, .nr = __nr, },
#include "sys-exec-tbl.c"
#undef SYSCALL
	{ }, /* terminator */
};

static struct syscall_exec_desc *find_syscall(char *name)
{
	int i;

	for (i = 0; sc_exec_table[i].name != NULL; i++)
		if (!strcmp(sc_exec_table[i].name, name))
			return &sc_exec_table[i];

	return NULL;
}

#define MAX_ARGS	6

static int execute_syscall(struct parasite_ctl *ctl,
		struct syscall_exec_desc *scd, char **opt)
{
	int i, err;
	unsigned long args[MAX_ARGS] = {}, ret, r_mem_size = 0;
	unsigned int ret_args[MAX_ARGS] = {};
	void *r_mem = NULL;

	for (i = 0; i < MAX_ARGS; i++) {
		if (opt[i] == NULL)
			break;

		/*
		 * &foo -- argument string "foo"
		 * @<size> -- ret-arg of size <size>
		 */

		if ((opt[i][0] == '&') || (opt[i][0] == '@')) {
			int len;

			if (!r_mem) {
				err = parasite_map_exchange(ctl, PAGE_SIZE);
				if (err)
					return err;

				r_mem_size = PAGE_SIZE;
				r_mem = ctl->local_map;
			}

			if (opt[i][0] == '&') {
				len = strlen(opt[i]);
				if (r_mem_size < len) {
					pr_err("Arg size overflow\n");
					return -1;
				}

				memcpy(r_mem, opt[i] + 1, len);
			} else {
				len = strtol(opt[i] + 1, NULL, 0);
				if (!len || (r_mem_size < len)) {
					pr_err("Bad argument size %d\n", len);
					return -1;
				}

				ret_args[i] = len;
			}

			args[i] = (unsigned long)ctl->remote_map + (r_mem - ctl->local_map);
			pr_info("Pushing %c mem arg [%s]\n", opt[i][0], (char *)r_mem);
			r_mem_size -= len;
			r_mem += len;
		} else
			args[i] = strtol(opt[i], NULL, 0);
	}

	pr_info("Calling %d with %lu %lu %lu %lu %lu %lu\n", scd->nr,
			args[0], args[1], args[2], args[3], args[4], args[5]);

	err = syscall_seized(ctl, scd->nr, &ret,
			args[0], args[1], args[2], args[3], args[4], args[5]);
	if (err)
		return err;

	pr_msg("Syscall returned %lx(%d)\n", ret, (int)ret);
	for (i = 0; i < MAX_ARGS; i++) {
		unsigned long addr;

		if (!ret_args[i])
			continue;

		pr_msg("Argument %d returns:\n", i);
		addr = (unsigned long)ctl->local_map + (args[i] - (unsigned long)ctl->remote_map);
		print_data(0, (unsigned char *)addr, ret_args[i]);
	}

	return 0;
}

int cr_exec(int pid, char **opt)
{
	char *sys_name = opt[0];
	struct syscall_exec_desc *si;
	struct parasite_ctl *ctl;
	struct vm_area_list vmas;
	int ret = -1, prev_state;
	struct proc_status_creds *creds;

	if (!sys_name) {
		pr_err("Syscall name required\n");
		goto out;
	}

	si = find_syscall(sys_name);
	if (!si) {
		pr_err("Unknown syscall [%s]\n", sys_name);
		goto out;
	}

	if (seize_catch_task(pid))
		goto out;

	prev_state = ret = seize_wait_task(pid, -1, &creds);
	if (ret < 0) {
		pr_err("Can't seize task %d\n", pid);
		goto out;
	}

	/*
	 * We don't seize a task's threads here, and there is no reason to
	 * compare threads' creds in this use case anyway, so let's just free
	 * the creds.
	 */
	free(creds);

	ret = collect_mappings(pid, &vmas);
	if (ret) {
		pr_err("Can't collect vmas for %d\n", pid);
		goto out_unseize;
	}

	ctl = parasite_prep_ctl(pid, &vmas);
	if (!ctl) {
		pr_err("Can't prep ctl %d\n", pid);
		goto out_unseize;
	}

	ret = execute_syscall(ctl, si, opt + 1);
	if (ret < 0)
		pr_err("Can't execute syscall remotely\n");

	parasite_cure_seized(ctl);
out_unseize:
	unseize_task(pid, prev_state, prev_state);
out:
	return ret;
}
