#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include "zdtmtst.h"

const char *test_doc	= "Test TUN/TAP devices\n";
const char *test_author	= "Pavel Emelianov <xemul@parallels.com>";

#define TUN_DEVICE	"/dev/net/tun"
#ifndef IFF_MULTI_QUEUE
#define IFF_MULTI_QUEUE  0x0100
#define IFF_ATTACH_QUEUE 0x0200
#define IFF_DETACH_QUEUE 0x0400
#define IFF_PERSIST      0x0800
#endif

#ifndef TUNSETQUEUE
#define TUNSETQUEUE  _IOW('T', 217, int)
#endif

static int any_fail = 0;

static int __open_tun(void)
{
	int fd;

	fd = open(TUN_DEVICE, O_RDWR);
	if (fd < 0)
		pr_perror("Can't open tun file");

	return fd;
}

static int set_tun_queue(int fd, unsigned flags)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = flags;

	if (ioctl(fd, TUNSETQUEUE, &ifr) < 0) {
		pr_perror("Can't set queue");
		return -1;
	}

	return 0;
}

static int __attach_tun(int fd, char *name, unsigned flags)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, name);
	ifr.ifr_flags = flags;

	if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
		if (!(flags & IFF_TUN_EXCL))
			pr_perror("Can't attach iff %s", name);
		return -1;
	}

	return fd;
}

static int open_tun(char *name, unsigned flags)
{
	int fd;

	fd = __open_tun();
	if (fd < 0)
		return -1;

	return __attach_tun(fd, name, flags);
}

static void check_tun(int fd, char *name, unsigned flags)
{
	struct ifreq ifr;

	if (ioctl(fd, TUNGETIFF, &ifr) > 0) {
		any_fail = 1;
		fail("Attached tun %s file lost device", name);
	}

	if (strcmp(ifr.ifr_name, name)) {
		any_fail = 1;
		fail("Attached tun %s wrong device", name);
	}

	if ((ifr.ifr_flags & flags) != flags) {
		any_fail = 1;
		fail("Attached tun %s wrong device type", name);
	}
}

static int dev_get_hwaddr(int fd, char *a)
{
	struct ifreq ifr;

	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		pr_perror("Can't get hwaddr");
		return -1;
	}

	memcpy(a, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	return 0;
}

int main(int argc, char **argv)
{
	int fds[5], ret;
	char addr[ETH_ALEN], a2[ETH_ALEN];

	test_init(argc, argv);

	/* fd[0] -- opened file */
	fds[0] = __open_tun();
	if (fds[0] < 0) {
		pr_perror("No file 0");
		return -1;
	}

	/* fd[1] -- opened file with tun device */
	fds[1] = open_tun("tunx0", IFF_TUN);
	if (fds[1] < 0) {
		pr_perror("No file 1");
		return -1;
	}

	/* fd[2] and [3] -- two-queued device, with 3 detached */
	fds[2] = open_tun("tunx1", IFF_TUN | IFF_MULTI_QUEUE);
	if (fds[2] < 0) {
		pr_perror("No file 2");
		return -1;
	}

	fds[3] = open_tun("tunx1", IFF_TUN | IFF_MULTI_QUEUE);
	if (fds[3] < 0) {
		pr_perror("No file 3");
		return -1;
	}

	ret = set_tun_queue(fds[3], IFF_DETACH_QUEUE);
	if (ret < 0)
		return -1;

	/* special case -- persistent device */
	ret = open_tun("tunx2", IFF_TUN);
	if (ret < 0) {
		pr_perror("No persistent device");
		return -1;
	}

	if (ioctl(ret, TUNSETPERSIST, 1) < 0) {
		pr_perror("Can't make persistent");
		return -1;
	}

	/* and one tap in fd[4] */
	fds[4] = open_tun("tapx0", IFF_TAP);
	if (fds[4] < 0) {
		pr_perror("No tap");
		return -1;
	}

	if (dev_get_hwaddr(fds[4], addr) < 0) {
		pr_perror("No hwaddr for tap?");
		return -1;
	}

	close(ret);

	test_daemon();
	test_waitsig();

	/* check fds[0] is not attached to device */
	ret = __attach_tun(fds[0], "tunx3", IFF_TUN);
	if (ret < 0) {
		any_fail = 1;
		fail("Opened tun file broken");
	}

	/* check that fds[1] has device */
	check_tun(fds[1], "tunx0", IFF_TUN);

	/* check that fds[2] and [3] are at MQ device with */
	check_tun(fds[2], "tunx1", IFF_TUN | IFF_MULTI_QUEUE);
	check_tun(fds[3], "tunx1", IFF_TUN | IFF_MULTI_QUEUE);

	ret = set_tun_queue(fds[2], IFF_DETACH_QUEUE);
	if (ret < 0) {
		any_fail = 1;
		fail("Queue not attached");
	}

	ret = set_tun_queue(fds[3], IFF_ATTACH_QUEUE);
	if (ret < 0) {
		any_fail = 1;
		fail("Queue not detached");
	}

	/* check persistent device */
	ret = open_tun("tunx2", IFF_TUN | IFF_TUN_EXCL);
	if (ret >= 0) {
		any_fail = 1;
		fail("Persistent device lost");
	} else {
		ret = open_tun("tunx2", IFF_TUN);
		if (ret < 0)
			pr_perror("Can't attach tun2");
		else
			ioctl(ret, TUNSETPERSIST, 0);
	}

	check_tun(fds[4], "tapx0", IFF_TAP);
	if (dev_get_hwaddr(fds[4], a2) < 0) {
		pr_perror("No hwaddr for tap? (2)");
		any_fail = 1;
	} else if (memcmp(addr, a2, sizeof(addr))) {
		fail("Address mismatch on tap %x:%x -> %x:%x",
				(int)addr[0], (int)addr[1],
				(int)a2[0], (int)a2[1]);
		any_fail = 1;
	}

	if (!any_fail)
		pass();

	return 0;
}
