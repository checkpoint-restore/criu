#include <unistd.h>
#include <sys/socket.h>
#include "sockets.h"
#include "crtools.h"
#include "log.h"
#include "util-net.h"

static int check_map_files(void)
{
	int ret;

	ret = access("/proc/self/map_files", R_OK);
	if (!ret)
		return 0;

	pr_msg("/proc/<pid>/map_files directory is missing.\n");
	return -1;
}

static int check_sock_diag(void)
{
	int ret;

	ret = collect_sockets();
	if (!ret)
		return 0;

	pr_msg("sock diag infrastructure is incomplete.\n");
	return -1;
}

static int check_ns_last_pid(void)
{
	int ret;

	ret = access(LAST_PID_PATH, W_OK);
	if (!ret)
		return 0;

	pr_msg("%s sysctl is missing.\n", LAST_PID_PATH);
	return -1;
}

static int check_sock_peek_off(void)
{
	int sk;
	int ret, off, sz;

	sk = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (sk < 0) {
		pr_perror("Can't create unix socket for check");
		return -1;
	}

	sz = sizeof(off);
	ret = getsockopt(sk, SOL_SOCKET, SO_PEEK_OFF, &off, (socklen_t *)&sz);
	close(sk);

	if ((ret == 0) && (off == -1) && (sz == sizeof(int)))
		return 0;

	pr_msg("SO_PEEK_OFF sockoption doesn't work.\n");
	return -1;
}

int cr_check(void)
{
	int ret = 0;

	ret |= check_map_files();
	ret |= check_sock_diag();
	ret |= check_ns_last_pid();
	ret |= check_sock_peek_off();

	if (!ret)
		pr_msg("Looks good.\n");

	return ret;
}
