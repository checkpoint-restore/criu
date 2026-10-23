#define _XOPEN_SOURCE 500
#define _DEFAULT_SOURCE

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <poll.h>
#include <errno.h>
#include <termios.h>
#include <sys/ioctl.h>

#include "zdtmtst.h"

const char *test_doc = "Check C/R of a pty master switched to packet mode (TIOCPKT)";
const char *test_author = "Rocker Zhang <zhang.rocker.liyuan@gmail.com>";

/* TIOCGPKT appeared in 4.13; define it for older userspace headers. */
#ifndef TIOCGPKT
#define TIOCGPKT _IOR('T', 0x38, int)
#endif

#ifndef TIOCPKT_DATA
#define TIOCPKT_DATA 0
#endif

/*
 * Deliberately newline-free: the slave's default termios (OPOST/ONLCR)
 * would otherwise be free to rewrite the bytes on the way to the master.
 */
static const char teststr[] = "ping";

int main(int argc, char *argv[])
{
	int master, slave, pkt;
	char *slavename;
	char acc[16];
	int acc_len = 0;

	test_init(argc, argv);

	master = open("/dev/ptmx", O_RDWR);
	if (master == -1) {
		pr_perror("open(/dev/ptmx) failed");
		return 1;
	}

	if (grantpt(master)) {
		pr_perror("grantpt failed");
		return 1;
	}
	if (unlockpt(master)) {
		pr_perror("unlockpt failed");
		return 1;
	}

	slavename = ptsname(master);
	if (!slavename) {
		pr_perror("ptsname failed");
		return 1;
	}
	slave = open(slavename, O_RDWR);
	if (slave == -1) {
		pr_perror("open(%s) failed", slavename);
		return 1;
	}

	/*
	 * Put the master into packet mode.  CRIU reads this state with
	 * TIOCGPKT on dump and replays it with TIOCPKT on restore, so the
	 * flag has to come back set on the restored master.
	 */
	pkt = 1;
	if (ioctl(master, TIOCPKT, &pkt)) {
		pr_perror("Can't enable packet mode");
		return 1;
	}

	/*
	 * TIOCGPKT (used below to confirm the flag survived C/R) only appeared
	 * in 4.13.  On an older runtime kernel TIOCPKT still works but TIOCGPKT
	 * fails with ENOTTY, so probe it up front and skip rather than report a
	 * spurious failure for a feature the kernel doesn't have.
	 */
	if (ioctl(master, TIOCGPKT, &pkt) && errno == ENOTTY) {
		test_daemon();
		test_waitsig();
		skip("TIOCGPKT not supported by the kernel");
		pass();
		return 0;
	}

	test_daemon();
	test_waitsig();

	signal(SIGHUP, SIG_IGN);

	/* The packet-mode flag itself must survive C/R. */
	pkt = 0;
	if (ioctl(master, TIOCGPKT, &pkt)) {
		pr_perror("Can't query packet mode");
		return 1;
	}
	if (pkt != 1) {
		fail("packet mode not restored (TIOCGPKT=%d)", pkt);
		return 1;
	}

	/*
	 * It must also still be functionally active: in packet mode every
	 * read() from the master starts with a control status byte
	 * (TIOCPKT_DATA == 0 for ordinary data), so what the slave writes
	 * comes back as [status][payload].  Poll with a timeout instead of a
	 * blocking read so a regressed pty can't hang the whole run, and
	 * accumulate across reads in case the payload arrives split up.
	 */
	if (write(slave, teststr, sizeof(teststr) - 1) != sizeof(teststr) - 1) {
		pr_perror("write(slave) failed");
		return 1;
	}

	while (acc_len < (int)(sizeof(teststr) - 1)) {
		struct pollfd pfd = { .fd = master, .events = POLLIN };
		char buf[64];
		int n, take;

		if (poll(&pfd, 1, 5000) <= 0) {
			fail("timed out reading master in packet mode (%d/%d payload bytes)", acc_len,
			     (int)(sizeof(teststr) - 1));
			return 1;
		}

		n = read(master, buf, sizeof(buf));
		if (n < 0) {
			pr_perror("read(master) failed");
			return 1;
		}
		if (n == 0) {
			fail("unexpected EOF on master");
			return 1;
		}

		/*
		 * A control/state packet carries no payload; skip it.  If packet
		 * mode had been lost the first byte would be payload instead, no
		 * TIOCPKT_DATA packet would ever arrive, and the poll above would
		 * time out -- so this still fails a regression, it just doesn't
		 * hang on one.
		 */
		if (buf[0] != TIOCPKT_DATA)
			continue;

		take = n - 1;
		if (take > (int)sizeof(acc) - acc_len)
			take = (int)sizeof(acc) - acc_len;
		memcpy(acc + acc_len, buf + 1, take);
		acc_len += take;
	}

	if (acc_len != (int)(sizeof(teststr) - 1) || memcmp(acc, teststr, sizeof(teststr) - 1)) {
		fail("payload mismatch after restore (%d bytes)", acc_len);
		return 1;
	}

	close(slave);
	close(master);

	pass();
	return 0;
}
