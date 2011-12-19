#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <limits.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include "compiler.h"
#include "types.h"
#include "util.h"
#include "ptrace.h"

int unseize_task(pid_t pid)
{
	return ptrace(PTRACE_DETACH, pid, NULL, NULL);
}

/*
 * This routine seizes task putting it into a special
 * state where we can manipulate the task via ptrace
 * inteface, and finally we can detach ptrace out of
 * of it so the task would not know if it was saddled
 * up with someone else.
 */
int seize_task(pid_t pid)
{
	siginfo_t si;
	int status;
	int ret = 0;

	jerr_rc(ptrace(PTRACE_SEIZE, pid, NULL,
		       (void *)(unsigned long)PTRACE_SEIZE_DEVEL), ret, err);
	jerr_rc(ptrace(PTRACE_INTERRUPT, pid, NULL, NULL), ret, err);

	ret = -10;
	if (wait4(pid, &status, __WALL, NULL) != pid)
		goto err;

	ret = -20;
	if (!WIFSTOPPED(status))
		goto err;

	jerr_rc(ptrace(PTRACE_GETSIGINFO, pid, NULL, &si), ret, err_cont);

	ret = -30;
	if ((si.si_code >> 8) != PTRACE_EVENT_STOP)
		goto err_cont;

	jerr_rc(ptrace(PTRACE_SETOPTIONS, pid, NULL,
		       (void *)(unsigned long)PTRACE_O_TRACEEXIT), ret, err_cont);

err:
	return ret;

err_cont:
	continue_task(pid);
	goto err;
}

int ptrace_show_area_r(pid_t pid, void *addr, long bytes)
{
	unsigned long w, i;
	if (bytes & (sizeof(long) - 1))
		return -1;
	for (w = 0; w < bytes / sizeof(long); w++) {
		unsigned long *a = addr;
		unsigned long v;
		v = ptrace(PTRACE_PEEKDATA, pid, a + w, NULL);
		if (v == -1U && errno)
			goto err;
		else {
			unsigned char *c = (unsigned char *)&v;
			for (i = sizeof(v)/sizeof(*c); i > 0; i--)
				printk("%02x ", c[i - 1]);
			printk("  ");
		}
	}
	printk("\n");
	return 0;
err:
	return -2;
}

int ptrace_show_area(pid_t pid, void *addr, long bytes)
{
	unsigned long w, i;
	if (bytes & (sizeof(long) - 1))
		return -1;
	printk("%016lx: ", (unsigned long)addr);
	for (w = 0; w < bytes / sizeof(long); w++) {
		unsigned long *a = addr;
		unsigned long v;
		v = ptrace(PTRACE_PEEKDATA, pid, a + w, NULL);
		if (v == -1U && errno)
			goto err;
		else {
			unsigned char *c = (unsigned char *)&v;
			for (i = 0; i < sizeof(v)/sizeof(*c); i++)
				printk("%02x ", c[i]);
			printk("  ");
		}
	}
	printk("\n");
	return 0;
err:
	return -2;
}

int ptrace_peek_area(pid_t pid, void *dst, void *addr, long bytes)
{
	unsigned long w;
	if (bytes & (sizeof(long) - 1))
		return -1;
	for (w = 0; w < bytes / sizeof(long); w++) {
		unsigned long *d = dst, *a = addr;
		d[w] = ptrace(PTRACE_PEEKDATA, pid, a + w, NULL);
		if (d[w] == -1U && errno)
			goto err;
	}
	return 0;
err:
	return -2;
}

int ptrace_poke_area(pid_t pid, void *src, void *addr, long bytes)
{
	unsigned long w;
	if (bytes & (sizeof(long) - 1))
		return -1;
	for (w = 0; w < bytes / sizeof(long); w++) {
		unsigned long *s = src, *a = addr;
		if (ptrace(PTRACE_POKEDATA, pid, a + w, s[w]))
			goto err;
	}
	return 0;
err:
	return -2;
}

