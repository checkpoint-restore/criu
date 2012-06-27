#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <stdlib.h>
#include "util.h"
#include "syscall.h"
#include "uts_ns.h"
#include "ipc_ns.h"
#include "mount.h"
#include "namespaces.h"

int switch_ns(int pid, int type, char *ns)
{
	char buf[32];
	int nsfd;
	int ret = -1;

	snprintf(buf, sizeof(buf), "/proc/%d/ns/%s", pid, ns);
	nsfd = open(buf, O_RDONLY);
	if (nsfd < 0) {
		pr_perror("Can't open ipcns file");
		goto out;
	}

	ret = setns(nsfd, type);
	if (ret < 0)
		pr_perror("Can't setns %d/%s", pid, ns);

	close(nsfd);
out:
	return ret;
}

static int do_dump_namespaces(struct pid *ns_pid, unsigned int ns_flags)
{
	struct cr_fdset *fdset;
	int ret = 0;

	fdset = cr_ns_fdset_open(ns_pid->virt, O_DUMP);
	if (fdset == NULL)
		return -1;

	if (ns_flags & CLONE_NEWUTS) {
		pr_info("Dump UTS namespace\n");
		ret = dump_uts_ns(ns_pid->real, fdset);
		if (ret < 0)
			goto err;
	}
	if (ns_flags & CLONE_NEWIPC) {
		pr_info("Dump IPC namespace\n");
		ret = dump_ipc_ns(ns_pid->real, fdset);
		if (ret < 0)
			goto err;
	}
	if (ns_flags & CLONE_NEWNS) {
		pr_info("Dump MNT namespace (mountpoints)\n");
		ret = dump_mnt_ns(ns_pid->real, fdset);
		if (ret < 0)
			goto err;
	}
err:
	close_cr_fdset(&fdset);
	return ret;

}

int dump_namespaces(struct pid *ns_pid, unsigned int ns_flags)
{
	int pid, status;
	int ret = 0;

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

	pr_info("Dumping %d(%d)'s namespaces\n", ns_pid->virt, ns_pid->real);

	if ((opts.namespaces_flags & CLONE_NEWPID) && ns_pid->virt != 1) {
		pr_err("Can't dump a pid namespace without the process init\n");
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		pr_perror("Can't fork ns dumper");
		return -1;
	}

	if (pid == 0) {
		ret = do_dump_namespaces(ns_pid, ns_flags);
		exit(ret);
	}

	ret = waitpid(pid, &status, 0);
	if (ret != pid) {
		pr_perror("Can't wait ns dumper");
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

	pr_info("Restoring namespaces %d flags 0x%lx\n",
			pid, clone_flags);

	if (clone_flags & CLONE_NEWUTS)
		ret = prepare_utsns(pid);
	if (clone_flags & CLONE_NEWIPC)
		ret = prepare_ipc_ns(pid);
	if (clone_flags & CLONE_NEWNS)
		ret = prepare_mnt_ns(pid);

	return ret;
}

int try_show_namespaces(int ns_pid, struct cr_options *o)
{
	struct cr_fdset *fdset;
	int i;

	fdset = cr_ns_fdset_open(ns_pid, O_SHOW);
	if (!fdset)
		return -1;

	for (i = _CR_FD_NS_FROM + 1; i < _CR_FD_NS_TO; i++) {
		int fd;

		if (!fdset_template[i].show)
			continue;

		fd = fdset_fd(fdset, i);
		if (fd == -1)
			continue;

		fdset_template[i].show(fdset_fd(fdset, i), o);
	}

	close_cr_fdset(&fdset);
	return 0;
}
