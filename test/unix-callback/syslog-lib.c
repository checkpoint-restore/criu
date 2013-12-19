#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/un.h>

#include "criu-plugin.h"
#include "criu-log.h"

extern cr_plugin_dump_unix_sk_t cr_plugin_dump_unix_sk;
extern cr_plugin_restore_unix_sk_t cr_plugin_restore_unix_sk;

int cr_plugin_dump_unix_sk(int sk, int id)
{
	struct sockaddr_un addr;
	socklen_t addr_len = sizeof(addr);
	char buf[4096];
	int fd;

	if (getsockname(sk, (struct sockaddr *) &addr, &addr_len) < 0)
		return -1;

	if (strncmp(addr.sun_path, "/dev/log", addr_len - sizeof(addr.sun_family)))
		return -ENOTSUP;

	snprintf(buf, sizeof(buf), "syslog-%x.img", id);
	fd = open(buf, O_WRONLY | O_CREAT);
	if (fd < 0)
		return -1;
	close(fd);

	return 0;
}

int cr_plugin_restore_unix_sk(int id)
{
	struct sockaddr_un addr;
	socklen_t addr_len;
	char buf[4096];
	int sk, fd;

	snprintf(buf, sizeof(buf), "syslog-%x.img", id);
	fd = open(buf, O_RDONLY);
	if (fd < 0)
		return -ENOTSUP;
	close(fd);

	sk = socket(AF_FILE, SOCK_DGRAM|SOCK_CLOEXEC, 0);
	if (sk == -1)
		return sk;

	addr.sun_family = AF_FILE;
	addr_len = strlen("/dev/log");
	strncpy(addr.sun_path, "/dev/log", addr_len);
	addr_len += sizeof(addr.sun_family);
	if (connect(sk, (struct sockaddr *) &addr, addr_len) == -1) {
		close(sk);
		return -1;
	}

	return sk;
}
