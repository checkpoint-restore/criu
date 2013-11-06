#include <unistd.h>
#include <fcntl.h>
#include <sys/utsname.h>
#include <string.h>

#include "util.h"
#include "syscall.h"
#include "namespaces.h"
#include "sysctl.h"
#include "uts_ns.h"

#include "protobuf.h"
#include "protobuf/utsns.pb-c.h"

int dump_uts_ns(int ns_pid, int ns_id)
{
	int ret, img_fd;
	struct utsname ubuf;
	UtsnsEntry ue = UTSNS_ENTRY__INIT;

	img_fd = open_image(CR_FD_UTSNS, O_DUMP, ns_id);
	if (img_fd < 0)
		return -1;

	ret = switch_ns(ns_pid, &uts_ns_desc, NULL);
	if (ret < 0)
		goto err;

	ret = uname(&ubuf);
	if (ret < 0) {
		pr_perror("Error calling uname");
		goto err;
	}

	ue.nodename = ubuf.nodename;
	ue.domainname = ubuf.domainname;

	ret = pb_write_one(img_fd, &ue, PB_UTSNS);
err:
	close(img_fd);
	return ret < 0 ? -1 : 0;
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

struct ns_desc uts_ns_desc = NS_DESC_ENTRY(CLONE_NEWUTS, "uts");
