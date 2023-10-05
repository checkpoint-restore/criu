#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sched.h>

// MAO required on Centos 6 (linux-3.18.1 kernel)
#include <linux/filter.h>

#include "cr_options.h"
#include "imgset.h"
#include "protobuf.h"
#include "string.h"
#include "files.h"
#include "files-reg.h"
#include "tun.h"
#include "net.h"
#include "namespaces.h"
#include "xmalloc.h"
#include "kerndat.h"
#include "sockets.h"

#include "images/tun.pb-c.h"

#undef LOG_PREFIX
#define LOG_PREFIX "tun: "

#ifndef IFF_PERSIST
#define IFF_PERSIST 0x0800
#endif

#ifndef IFF_NOFILTER
#define IFF_NOFILTER 0x1000
#endif

#ifndef TUNSETQUEUE
#define TUNSETQUEUE	 _IOW('T', 217, int)
#define IFF_ATTACH_QUEUE 0x0200
#define IFF_DETACH_QUEUE 0x0400
#endif

/*
 * Absence of the 1st ioctl means we cannot restore tun link. But
 * since the 2nd one appeared at the same time, we'll "check" this
 * by trying to dump filter and abort dump if it's not there.
 */

#ifndef TUNSETIFINDEX
#define TUNSETIFINDEX _IOW('T', 218, unsigned int)
#endif

#ifndef TUNGETFILTER
#define TUNGETFILTER _IOR('T', 219, struct sock_fprog)
#endif

#define TUN_DEV_GEN_PATH "/dev/net/tun"

int check_tun_cr(int no_tun_err)
{
	int fd, idx = 13, ret;

	fd = open(TUN_DEV_GEN_PATH, O_RDWR);
	if (fd < 0) {
		pr_perror("Can't check tun support");
		return no_tun_err;
	}

	ret = ioctl(fd, TUNSETIFINDEX, &idx);
	if (ret < 0)
		pr_perror("No proper support for tun dump/restore");

	close(fd);
	return ret;
}

int check_tun_netns_cr(bool *result)
{
	bool val = false;
	int tun;

	tun = open(TUN_DEV_GEN_PATH, O_RDONLY);
	if (tun < 0) {
		pr_perror("Unable to create tun");
		goto out;
	}
	check_has_netns_ioc(tun, &val, "tun");
	close(tun);

out:
	if (result)
		*result = val;

	return 0;
}

static LIST_HEAD(tun_links);

struct tun_link {
	char name[IFNAMSIZ];
	struct list_head l;
	unsigned ns_id;
	union {
		struct {
			unsigned flags;
		} rst;

		struct {
			unsigned sndbuf;
			unsigned vnethdr;
		} dmp;
	};
};

static int list_tun_link(NetDeviceEntry *nde, unsigned ns_id)
{
	struct tun_link *tl;

	tl = xmalloc(sizeof(*tl));
	if (!tl)
		return -1;

	__strlcpy(tl->name, nde->name, sizeof(tl->name));
	/*
	 * Keep tun-flags not only for persistency fixup (see
	 * comment below), but also for TUNSETIFF -- we must
	 * open the device with the same flags it should live
	 * with (i.e. -- with which it was created.
	 */
	tl->rst.flags = nde->tun->flags;
	tl->ns_id = ns_id;
	list_add_tail(&tl->l, &tun_links);
	return 0;
}

static struct tun_link *find_tun_link(char *name, unsigned int ns_id)
{
	struct tun_link *tl;

	list_for_each_entry(tl, &tun_links, l) {
		if (!strcmp(tl->name, name) && tl->ns_id == ns_id)
			return tl;
	}
	return NULL;
}

static struct tun_link *__dump_tun_link_fd(int fd, char *name, unsigned ns_id, unsigned flags)
{
	struct tun_link *tl;
	struct sock_fprog flt;

	tl = xmalloc(sizeof(*tl));
	if (!tl)
		goto err;
	__strlcpy(tl->name, name, sizeof(tl->name));
	tl->ns_id = ns_id;
	INIT_LIST_HEAD(&tl->l);

	if (ioctl(fd, TUNGETVNETHDRSZ, &tl->dmp.vnethdr) < 0) {
		pr_perror("Can't dump vnethdr size for %s", name);
		goto err;
	}

	if (ioctl(fd, TUNGETSNDBUF, &tl->dmp.sndbuf) < 0) {
		pr_perror("Can't dump sndbuf for %s", name);
		goto err;
	}

	if (flags & IFF_TAP) {
		pr_debug("Checking filter for tap %s\n", name);
		if (ioctl(fd, TUNGETFILTER, &flt) < 0) {
			pr_perror("Can't get tun filter for %s", name);
			goto err;
		}

		/*
		 * TUN filters are tricky -- the program itself is 'somewhere'
		 * in the task's memory, so we can't get one for unattached
		 * persistent device. The only way for doing it is opening the
		 * device with IFF_NOFILTER and attaching some fake one :(
		 */

		if (flt.len != 0) {
			pr_err("Can't dump %s with filter on-board\n", name);
			goto err;
		}
	} else if (!(flags & IFF_NOFILTER)) {
		pr_err("No info about %s filter, kernel is too old\n", name);
		goto err;
	}

	return tl;

err:
	xfree(tl);
	return NULL;
}

static struct tun_link *dump_tun_link_fd(int fd, char *name, unsigned ns_id, unsigned flags)
{
	struct tun_link *tl;

	tl = find_tun_link(name, ns_id);
	if (tl)
		return tl;

	tl = __dump_tun_link_fd(fd, name, ns_id, flags);
	if (tl) {
		/*
		 * Keep this in list till links dumping code starts.
		 * We can't let it dump all this stuff itself, since
		 * multiple attaches to one tun device is limited and
		 * we may not be able to it that late.
		 *
		 * For persistent detached devices the get_tun_link_fd
		 * will attach to the device and get the needed stuff.
		 */
		list_add(&tl->l, &tun_links);
	}
	return tl;
}

static int open_tun_dev(char *name, unsigned int idx, unsigned flags)
{
	int fd;
	struct ifreq ifr;

	fd = open(TUN_DEV_GEN_PATH, O_RDWR);
	if (fd < 0) {
		pr_perror("Can't open tun device");
		return -1;
	}

	if (idx) {
		pr_debug("  restoring %u for %s tun\n", idx, name);
		if (ioctl(fd, TUNSETIFINDEX, &idx) < 0) {
			pr_perror("Can't restore tun's index");
			goto err;
		}
	}

	memset(&ifr, 0, sizeof(ifr));
	__strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
	ifr.ifr_flags = flags;

	if (ioctl(fd, TUNSETIFF, &ifr)) {
		pr_perror("Can't create tun device");
		goto err;
	}

	return fd;

err:
	close(fd);
	return -1;
}

static struct tun_link *get_tun_link_fd(char *name, unsigned ns_id, unsigned flags)
{
	struct tun_link *tl;
	int fd;

	tl = find_tun_link(name, ns_id);
	if (tl)
		return tl;

	/*
	 * If we haven't found this thing, then the
	 * device we see via netlink exists w/o any fds
	 * attached, i.e. -- it's persistent
	 */

	if (!(flags & IFF_PERSIST)) {
		pr_err("No fd info for non persistent tun device %s\n", name);
		return NULL;
	}

	/*
	 * Kernel will try to attach filter (if it exists) to our memory,
	 * avoid this.
	 */

	flags |= IFF_NOFILTER;

	fd = open_tun_dev(name, 0, flags);
	if (fd < 0)
		return NULL;

	tl = __dump_tun_link_fd(fd, name, ns_id, flags);
	close(fd);

	return tl;
}

static int dump_tunfile(int lfd, u32 id, const struct fd_parms *p)
{
	int ret;
	struct cr_img *img;
	FileEntry fe = FILE_ENTRY__INIT;
	TunfileEntry tfe = TUNFILE_ENTRY__INIT;
	struct ns_id *ns;
	struct ifreq ifr;

	if (!(root_ns_mask & CLONE_NEWNET)) {
		pr_err("Net namespace is required to dump tun link\n");
		return -1;
	}

	if (kdat.tun_ns) {
		ns = get_socket_ns(lfd);
		if (!ns) {
			pr_err("No net_ns for tun device\n");
			return -1;
		}
		tfe.has_ns_id = true;
		tfe.ns_id = ns->id;
	}

	if (dump_one_reg_file(lfd, id, p))
		return -1;

	pr_info("Dumping tun-file %d with id %#x\n", lfd, id);

	tfe.id = id;
	ret = ioctl(lfd, TUNGETIFF, &ifr);
	if (ret < 0) {
		if (errno != EBADFD) {
			pr_perror("Can't dump tun-file device");
			return -1;
		}

		/*
		 * Otherwise this is just opened file with not yet attached
		 * tun device. Go ahead an write the respective entry.
		 */
	} else {
		tfe.netdev = ifr.ifr_name;
		pr_info("`- attached to device %s (flags %x)\n", tfe.netdev, ifr.ifr_flags);

		if (ifr.ifr_flags & IFF_DETACH_QUEUE) {
			tfe.has_detached = true;
			tfe.detached = true;
		}

		if (dump_tun_link_fd(lfd, tfe.netdev, tfe.ns_id, ifr.ifr_flags) == NULL)
			return -1;
	}

	fe.type = FD_TYPES__TUNF;
	fe.id = tfe.id;
	fe.tunf = &tfe;

	img = img_from_set(glob_imgset, CR_FD_FILES);
	return pb_write_one(img, &fe, PB_FILE);
}

const struct fdtype_ops tunfile_dump_ops = {
	.type = FD_TYPES__TUNF,
	.dump = dump_tunfile,
};

struct tunfile_info {
	struct file_desc d;
	TunfileEntry *tfe;
};

static int tunfile_open(struct file_desc *d, int *new_fd)
{
	int fd, ns_id;
	struct tunfile_info *ti;
	struct ifreq ifr;
	struct tun_link *tl;

	ti = container_of(d, struct tunfile_info, d);

	ns_id = ti->tfe->ns_id;
	if (set_netns(ns_id))
		return -1;

	fd = open_reg_by_id(ti->tfe->id);
	if (fd < 0)
		return -1;

	if (!ti->tfe->netdev)
		/* just-opened tun file */
		goto ok;

	tl = find_tun_link(ti->tfe->netdev, ns_id);
	if (!tl) {
		pr_err("No tun device for file %s\n", ti->tfe->netdev);
		goto err;
	}

	memset(&ifr, 0, sizeof(ifr));
	__strlcpy(ifr.ifr_name, tl->name, sizeof(ifr.ifr_name));
	ifr.ifr_flags = tl->rst.flags;

	if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
		pr_perror("Can't attach tunfile to device");
		goto err;
	}

	if (ti->tfe->has_detached && ti->tfe->detached) {
		pr_info("Detaching from %s queue\n", ti->tfe->netdev);
		ifr.ifr_flags = IFF_DETACH_QUEUE;
		if (ioctl(fd, TUNSETQUEUE, &ifr) < 0) {
			pr_perror("Can't detach queue");
			goto err;
		}
	}

	if (!(tl->rst.flags & IFF_PERSIST)) {
		pr_info("Dropping persistency for %s\n", tl->name);
		if (ioctl(fd, TUNSETPERSIST, 0) < 0) {
			pr_perror("Error dropping persistency");
			goto err;
		}
	}
ok:
	*new_fd = fd;
	return 0;

err:
	close(fd);
	return -1;
}

static struct file_desc_ops tunfile_desc_ops = {
	.type = FD_TYPES__TUNF,
	.open = tunfile_open,
};

static int collect_one_tunfile(void *o, ProtobufCMessage *base, struct cr_img *i)
{
	struct tunfile_info *ti = o;

	ti->tfe = pb_msg(base, TunfileEntry);
	file_desc_add(&ti->d, ti->tfe->id, &tunfile_desc_ops);

	pr_info("Collected %s tunfile\n", ti->tfe->netdev);

	return 0;
}

struct collect_image_info tunfile_cinfo = {
	.fd_type = CR_FD_TUNFILE,
	.pb_type = PB_TUNFILE,
	.priv_size = sizeof(struct tunfile_info),
	.collect = collect_one_tunfile,
};

int dump_tun_link(NetDeviceEntry *nde, struct cr_imgset *fds, struct nlattr **info)
{
	TunLinkEntry tle = TUN_LINK_ENTRY__INIT;
	char spath[64];
	char buf[64];
	struct tun_link *tl;

	sprintf(spath, "class/net/%s/tun_flags", nde->name);
	if (read_ns_sys_file(spath, buf, sizeof(buf)) < 0)
		return -1;
	tle.flags = strtol(buf, NULL, 0);

	sprintf(spath, "class/net/%s/owner", nde->name);
	if (read_ns_sys_file(spath, buf, sizeof(buf)) < 0)
		return -1;
	tle.owner = strtol(buf, NULL, 10);

	sprintf(spath, "class/net/%s/group", nde->name);
	if (read_ns_sys_file(spath, buf, sizeof(buf)) < 0)
		return -1;
	tle.group = strtol(buf, NULL, 10);

	tl = get_tun_link_fd(nde->name, nde->peer_nsid, tle.flags);
	if (!tl)
		return -1;

	tle.vnethdr = tl->dmp.vnethdr;
	tle.sndbuf = tl->dmp.sndbuf;

	/*
	 * Function get_tun_link_fd() can return either entry
	 * from tun_links list or a newly allocated one, need to
	 * free it only if not in list.
	 */
	if (list_empty(&tl->l))
		xfree(tl);

	nde->tun = &tle;
	return write_netdev_img(nde, fds, info);
}

int restore_one_tun(struct ns_id *ns, struct net_link *link, int nlsk)
{
	NetDeviceEntry *nde = link->nde;
	int fd, ret = -1, aux;

	if (!nde->tun) {
		pr_err("Corrupted TUN link entry %x\n", nde->ifindex);
		return -1;
	}

	pr_info("Restoring tun device %s\n", nde->name);

	fd = open_tun_dev(nde->name, nde->ifindex, nde->tun->flags);
	if (fd < 0)
		return -1;

	aux = nde->tun->owner;
	if ((aux != -1) && ioctl(fd, TUNSETOWNER, aux) < 0) {
		pr_perror("Can't set owner");
		goto out;
	}

	aux = nde->tun->group;
	if ((aux != -1) && ioctl(fd, TUNSETGROUP, aux) < 0) {
		pr_perror("Can't set group");
		goto out;
	}

	aux = nde->tun->sndbuf;
	if (ioctl(fd, TUNSETSNDBUF, &aux) < 0) {
		pr_perror("Can't set sndbuf");
		goto out;
	}

	aux = nde->tun->vnethdr;
	if (ioctl(fd, TUNSETVNETHDRSZ, &aux) < 0) {
		pr_perror("Can't set vnethdr");
		goto out;
	}

	/*
	 * Set this device persistent anyway and schedule
	 * the persistence drop if it should not be such.
	 * The first _real_ opener will do it.
	 */

	if (ioctl(fd, TUNSETPERSIST, 1)) {
		pr_perror("Can't make tun device persistent");
		goto out;
	}

	if (restore_link_parms(link, nlsk)) {
		pr_err("Error restoring %s link params\n", nde->name);
		goto out;
	}

	ret = list_tun_link(nde, ns->id);
out:
	close(fd);
	return ret;
}
