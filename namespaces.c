#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/utsname.h>
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

static int dump_uts_string(int fd, char *str)
{
	int ret;
	u32 len;

	len = strlen(str);
	ret = write_img(fd, &len);
	if (ret == 0)
		ret = write_img_buf(fd, str, len);

	return ret;
}

static int dump_uts_ns(int ns_pid, struct cr_fdset *fdset)
{
	int fd, ret;
	struct utsname ubuf;

	ret = switch_ns(ns_pid, CLONE_NEWUTS, "uts");
	if (ret < 0)
		return ret;

	ret = uname(&ubuf);
	if (ret < 0) {
		pr_perror("Error calling uname\n");
		return ret;
	}

	fd = fdset->fds[CR_FD_UTSNS];

	ret = dump_uts_string(fd, ubuf.nodename);
	if (!ret)
		ret = dump_uts_string(fd, ubuf.domainname);

	return ret;
}

static int do_dump_namespaces(int ns_pid)
{
	struct cr_fdset *fdset;
	int ret;

	fdset = cr_fdset_open(ns_pid, CR_FD_DESC_NS, NULL);
	if (fdset == NULL)
		return -1;

	ret = dump_uts_ns(ns_pid, fdset);

	close_cr_fdset(&fdset);
	return ret;

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

static int prepare_uts_str(int fd, char *n)
{
	int ret;
	u32 len;
	char str[65], path[128];

	ret = read_img(fd, &len);
	if (ret > 0) {
		if (len >= 65) {
			pr_err("Corrupted %s\n", n);
			return -1;
		}

		ret = read_img_buf(fd, str, len);
		if (ret < 0)
			return -1;

		str[len] = '\0';

		snprintf(path, sizeof(path),
				"/proc/sys/kernel/%s", n);
		fd = open(path, O_WRONLY);
		if (fd < 0) {
			pr_perror("Can't open %s\n", path);
			return -1;
		}

		pr_info("Restoging %s to [%s]\n", n, str);

		ret = write(fd, str, len);
		close(fd);
		if (ret != len) {
			pr_perror("Can't write %s to %s\n",
					str, path);
			return -1;
		}

		ret = 0;
	}

	return ret;
}

static int prepare_utsns(int pid)
{
	int fd, ret;
	u32 len;
	char str[65];

	fd = open_image_ro(CR_FD_UTSNS, pid);
	if (fd < 0)
		return -1;

	ret = prepare_uts_str(fd, "hostname");
	if (!ret)
		ret = prepare_uts_str(fd, "domainname");

	close(fd);
	return ret;
}

int prepare_namespace(int pid, unsigned long clone_flags)
{
	int ret = 0;

	pr_info("Restoring namespaces %d flags %lx\n",
			pid, clone_flags);

	if (clone_flags & CLONE_NEWUTS)
		ret = prepare_utsns(pid);

	return ret;
}

static void show_uts_string(int fd, char *n)
{
	int ret;
	u32 len;
	char str[65];

	ret = read_img(fd, &len);
	if (ret > 0) {
		if (len >= 65) {
			pr_err("Corrupted hostname\n");
			return;
		}

		ret = read_img_buf(fd, str, len);
		if (ret < 0)
			return;

		str[len] = '\0';
		pr_info("%s: [%s]\n", n, str);
	}
}

void show_utsns(int fd)
{
	pr_img_head(CR_FD_UTSNS);
	show_uts_string(fd, "hostname");
	show_uts_string(fd, "domainname");
	pr_img_tail(CR_FD_UTSNS);
}

int try_show_namespaces(int ns_pid)
{
	struct cr_fdset *fdset;

	fdset = prep_cr_fdset_for_restore(ns_pid, CR_FD_DESC_NS);
	if (!fdset)
		return -1;

	show_utsns(fdset->fds[CR_FD_UTSNS]);

	close_cr_fdset(&fdset);
	return 0;
}
