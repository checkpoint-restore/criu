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

int dump_uts_ns(int ns_id)
{
	int ret;
	struct cr_img *img;
	struct utsname ubuf;
	UtsnsEntry ue = UTSNS_ENTRY__INIT;

	img = open_image(CR_FD_UTSNS, O_DUMP, ns_id);
	if (!img)
		return -1;

	ret = uname(&ubuf);
	if (ret < 0) {
		pr_perror("Error calling uname");
		goto err;
	}

	ue.nodename = ubuf.nodename;
	ue.domainname = ubuf.domainname;

	ret = pb_write_one(img, &ue, PB_UTSNS);
err:
	close_image(img);
	return ret < 0 ? -1 : 0;
}

int prepare_utsns(int pid)
{
	int ret;
	struct cr_img *img;
	UtsnsEntry *ue;
	struct sysctl_req req[] = {
		{ "kernel/hostname" },
		{ "kernel/domainname" },
	};

	img = open_image(CR_FD_UTSNS, O_RSTR, pid);
	if (!img)
		return -1;

	ret = pb_read_one(img, &ue, PB_UTSNS);
	if (ret < 0)
		goto out;

	req[0].arg = ue->nodename;
	req[0].type = CTL_STR(strlen(ue->nodename));
	req[1].arg = ue->domainname;
	req[1].type = CTL_STR(strlen(ue->domainname));

	ret = sysctl_op(req, ARRAY_SIZE(req), CTL_WRITE);
	utsns_entry__free_unpacked(ue, NULL);
out:
	close_image(img);
	return ret;
}

struct ns_desc uts_ns_desc = NS_DESC_ENTRY(CLONE_NEWUTS, "uts");
