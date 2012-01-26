#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include "util.h"
#include "crtools.h"
#include "syscall.h"

static int switch_ns(int pid, int type, char *ns)
{
	char buf[32];
	int nsfd, ret;

	snprintf(buf, sizeof(buf), "/proc/%d/ns/%s", pid, ns);
	nsfd = open(buf, O_RDONLY);
	if (nsfd < 0) {
		pr_perror("Can't open ipcns file\n");
		goto out;
	}

	ret = setns(nsfd, type);
	if (ret < 0)
		pr_perror("Can't setns %d/%s\n", pid, ns);

	close(nsfd);
out:
	return ret;
}

static int do_dump_namespaces(int ns_pid)
{
	return 0;
}

int dump_namespaces(int ns_pid)
{
	int pid, ret, status;

	/*
	 * The setns syscall is cool, we can switch to the other
	 * namespace and then return back to our initial one, but
	 * for me it's much easier just to fork another task and
	 * let it do the job, all the more so it can be done in
	 * parallel with task dumping routine.
	 *
	 * However, the question how to dump sockets from the target
	 * net namesapce with this is still open
	 */

	pr_info("Dumping %d's namespaces\n", ns_pid);

	pid = fork();
	if (pid < 0) {
		pr_perror("Can't fork ns dumper\n");
		return -1;
	}

	if (pid == 0) {
		ret = do_dump_namespaces(ns_pid);
		exit(ret);
	}

	ret = waitpid(pid, &status, 0);
	if (ret != pid) {
		pr_perror("Can't wait ns dumper\n");
		return -1;
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		pr_err("Namespaces dumping finished with error %d\n", status);
		return -1;
	}

	pr_info("Namespaces dump complete\n");
	return 0;
}

int prepare_namespace(int pid, unsigned long clone_flags)
{
	int ret = 0;

	pr_info("Restoring namespaces %d flags %lx\n",
			pid, clone_flags);

	return ret;
}

int try_show_namespaces(int ns_pid)
{
	return 0;
}
