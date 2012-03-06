#include <unistd.h>
#include <fcntl.h>
#include <sys/utsname.h>

#include "util.h"
#include "crtools.h"
#include "syscall.h"
#include "namespaces.h"
#include "sysctl.h"

static int dump_uts_string(int fd, const char *str)
{
	int ret;
	u32 len;

	len = strlen(str);
	ret = write_img(fd, &len);
	if (!ret)
		ret = write_img_buf(fd, str, len);

	return ret;
}

int dump_uts_ns(int ns_pid, struct cr_fdset *fdset)
{
	int fd, ret;
	struct utsname ubuf;

	ret = switch_ns(ns_pid, CLONE_NEWUTS, "uts");
	if (ret < 0)
		return ret;

	ret = uname(&ubuf);
	if (ret < 0) {
		pr_perror("Error calling uname");
		return ret;
	}

	fd = fdset->fds[CR_FD_UTSNS];

	ret = dump_uts_string(fd, ubuf.nodename);
	if (!ret)
		ret = dump_uts_string(fd, ubuf.domainname);

	return ret;
}

static int read_uts_str(int fd, char *n, int size)
{
	int ret;
	u32 len;

	ret = read_img(fd, &len);
	if (ret < 0)
		return -1;

	if (len >= size) {
		pr_err("Corrupted %s\n", n);
		return -1;
	}

	ret = read_img_buf(fd, n, len);
	if (ret < 0)
		return -1;

	n[len] = '\0';
	return 0;
}

int prepare_utsns(int pid)
{
	int fd, ret;
	u32 len;
	char hostname[65];
	char domainname[65];

	struct sysctl_req req[] = {
		{ "kernel/hostname",	hostname,	CTL_STR(sizeof(hostname)) },
		{ "kernel/domainname",	domainname,	CTL_STR(sizeof(hostname)) },
		{ },
	};

	fd = open_image_ro(CR_FD_UTSNS, pid);
	if (fd < 0)
		return -1;

	ret = read_uts_str(fd, hostname, sizeof(hostname));
	if (ret < 0)
		goto out;

	ret = read_uts_str(fd, domainname, sizeof(domainname));
	if (ret < 0)
		goto out;

	ret = sysctl_op(req, CTL_WRITE);
out:
	close(fd);
	return ret;
}

static void show_uts_string(int fd, char *n)
{
	int ret;
	u32 len;
	char str[65];

	ret = read_img_eof(fd, &len);
	if (ret > 0) {
		if (len >= sizeof(str)) {
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
