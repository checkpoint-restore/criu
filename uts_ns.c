#include <unistd.h>
#include <fcntl.h>
#include <sys/utsname.h>
#include <string.h>

#include "util.h"
#include "crtools.h"
#include "syscall.h"
#include "namespaces.h"
#include "sysctl.h"
#include "uts_ns.h"

#include "protobuf.h"
#include "protobuf/utsns.pb-c.h"

int dump_uts_ns(int ns_pid, struct cr_fdset *fdset)
{
	int ret;
	struct utsname ubuf;
	UtsnsEntry ue = UTSNS_ENTRY__INIT;

	ret = switch_ns(ns_pid, &uts_ns_desc, NULL);
	if (ret < 0)
		return ret;

	ret = uname(&ubuf);
	if (ret < 0) {
		pr_perror("Error calling uname");
		return ret;
	}

	ue.nodename = ubuf.nodename;
	ue.domainname = ubuf.domainname;

	return pb_write_one(fdset_fd(fdset, CR_FD_UTSNS), &ue, PB_UTSNS);
}

int prepare_utsns(int pid)
{
	int fd, ret;
	UtsnsEntry *ue;
	struct sysctl_req req[3] = {
		{ "kernel/hostname" },
		{ "kernel/domainname" },
		{ },
	};

	fd = open_image(CR_FD_UTSNS, O_RSTR, pid);
	if (fd < 0)
		return -1;

	ret = pb_read_one(fd, &ue, PB_UTSNS);
	if (ret < 0)
		goto out;

	req[0].arg = ue->nodename;
	req[0].type = CTL_STR(strlen(ue->nodename));
	req[1].arg = ue->domainname;
	req[1].type = CTL_STR(strlen(ue->domainname));

	ret = sysctl_op(req, CTL_WRITE);
	utsns_entry__free_unpacked(ue, NULL);
out:
	close(fd);
	return ret;
}

void show_utsns(int fd)
{
	pb_show_vertical(fd, PB_UTSNS);
}

struct ns_desc uts_ns_desc = NS_DESC_ENTRY(CLONE_NEWUTS, "uts");
