#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libgen.h>
#include <errno.h>

#include <sys/socket.h>
#include <linux/un.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "criu-plugin.h"
#include "criu-log.h"

#include "unix.pb-c.h"

extern cr_plugin_init_t cr_plugin_init;
extern cr_plugin_dump_unix_sk_t cr_plugin_dump_unix_sk;
extern cr_plugin_restore_unix_sk_t cr_plugin_restore_unix_sk;

#define SK_NAME "/tmp/criu.unix.callback.test"
static int get_srv_socket(void)
{
	struct sockaddr_un addr;
	socklen_t addr_len;
	int skd;

	skd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (skd < 0) {
		pr_perror("socket");
		return -1;
	}

	addr.sun_family = AF_UNIX;
	addr_len = snprintf(addr.sun_path, UNIX_PATH_MAX, "%s.dump.%d", SK_NAME, getpid());
	addr_len += sizeof(addr.sun_family);

	unlink(addr.sun_path);
	if (bind(skd, (struct sockaddr *) &addr, addr_len) < 0) {
		pr_perror("bind");
		return 1;
	}

	addr.sun_family = AF_UNIX;
	addr_len = snprintf(addr.sun_path, UNIX_PATH_MAX, SK_NAME);
	addr_len += sizeof(addr.sun_family);

	if (connect(skd, (struct sockaddr *) &addr, addr_len) < 0) {
		pr_perror("connect");
		return -1;
	}

	return skd;
}

int cr_plugin_init(void)
{
	return 0;
}

int cr_plugin_dump_unix_sk(int sk, int sk_id)
{
	struct sockaddr_un addr;
	socklen_t addr_len = sizeof(addr);
	char buf[4096];
	int skd, id, ret, fd, len;
	UnixTest e = UNIX_TEST__INIT;

	if (getpeername(sk, (struct sockaddr *) &addr, &addr_len)) {
		pr_perror("getpeername");
		return -1;
	}

	len = addr_len - sizeof(addr.sun_family);
	if (addr.sun_path[len - 1] == 0)
		len--;

	if (len != strlen(SK_NAME) ||
	    strncmp(addr.sun_path, SK_NAME, strlen(SK_NAME)))
		return -ENOTSUP;

	pr_info("Dump the socket %x\n", sk_id);
	skd = get_srv_socket();
	if (skd < 0)
		return -1;

	addr_len = sizeof(struct sockaddr_un);

	if (getsockname(sk, (struct sockaddr *) &addr, &addr_len) < 0)
		return -1;

	id = atoi(addr.sun_path + strlen(SK_NAME));

	ret = sprintf(buf, "d%d", id) + 1;
	if (send(skd, buf, ret, 0) < 0) {
		pr_perror("send");
		return -1;
	}

	if (recv(skd, buf, sizeof(buf), 0) <= 0)
		return -1;

	close(skd);

	e.val = atoi(buf);
	pr_err("%x: val %d\n", sk_id, e.val);
	e.name.data = (void *)addr.sun_path;
	e.name.len = addr_len - sizeof(addr.sun_family);

	snprintf(buf, sizeof(buf), "unix-test-%x.img", sk_id);
	fd = openat(criu_get_image_dir(), buf, O_WRONLY | O_CREAT, 0600);
	if (fd < 0)
		return -1;

	if (unix_test__get_packed_size(&e) > sizeof(buf)) {
		pr_err("%ld\n", unix_test__get_packed_size(&e));
		return -1;
	}

	ret = unix_test__pack(&e, (uint8_t *) buf);
	if (write(fd, buf, ret) != ret)
		return -1;
	close(fd);

	return 0;
}

int cr_plugin_restore_unix_sk(int sk_id)
{
	struct sockaddr_un addr;
	socklen_t addr_len;
	int fd, sk, ret;
	char buf[4096];
	UnixTest *e;

	snprintf(buf, sizeof(buf), "unix-test-%x.img", sk_id);
	fd = openat(criu_get_image_dir(), buf, O_RDONLY, 0600);
	if (fd < 0)
		return -ENOTSUP;

	ret = read(fd, buf, sizeof(buf));
	if (ret < 0) {
		pr_perror("read");
		return -1;
	}
	close(fd);

	e = unix_test__unpack(NULL, ret, (uint8_t *) buf);
	if (e == NULL)
		return -1;

	sk = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sk < 0) {
		pr_perror("socket");
		return -1;
	}

	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, e->name.data, e->name.len);
	addr_len = sizeof(addr.sun_family) + e->name.len;

	if (bind(sk, (struct sockaddr *) &addr, addr_len) < 0) {
		pr_perror("bind");
		return -1;
	}

	addr.sun_family = AF_UNIX;
	addr_len = snprintf(addr.sun_path, UNIX_PATH_MAX, SK_NAME);
	addr_len += sizeof(addr.sun_family);

	if (connect(sk, (struct sockaddr *) &addr, addr_len) < 0) {
		pr_perror("connect");
		return -1;
	}

	pr_err("id %d val %d\n", sk_id, e->val);
	ret = sprintf(buf, "t%d", e->val);
	if (send(sk, buf, ret, 0) < 0) {
		pr_perror("send");
		return -1;
	}

	return sk;
}
