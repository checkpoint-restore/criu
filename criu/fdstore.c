#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>

#include "common/scm.h"
#include "common/lock.h"
#include "servicefd.h"
#include "fdstore.h"
#include "xmalloc.h"
#include "rst-malloc.h"
#include "log.h"
#include "util.h"
#include "cr_options.h"
#include "util-caps.h"
#include "sockets.h"

/* clang-format off */
static struct fdstore_desc {
	int next_id;
	mutex_t lock; /* to protect a peek offset */
} *desc;
/* clang-format on */

int fdstore_init(void)
{
	/* In kernel a bufsize has type int and a value is doubled. */
	uint32_t buf[2] = { INT_MAX / 2, INT_MAX / 2 };
	struct sockaddr_un addr;
	unsigned int addrlen;
	struct stat st;
	int sk, ret;

	desc = shmalloc(sizeof(*desc));
	if (!desc)
		return -1;

	desc->next_id = 0;
	mutex_init(&desc->lock);

	sk = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if (sk < 0) {
		pr_perror("Unable to create a socket");
		return -1;
	}

	if (fstat(sk, &st)) {
		pr_perror("Unable to stat a file descriptor");
		close(sk);
		return -1;
	}

	if (sk_setbufs(sk, buf)) {
		close(sk);
		return -1;
	}

	addr.sun_family = AF_UNIX;
	addrlen = snprintf(addr.sun_path, sizeof(addr.sun_path), "X/criu-fdstore-%" PRIx64 "-%s", st.st_ino,
			   criu_run_id);
	addrlen += sizeof(addr.sun_family);

	addr.sun_path[0] = 0;

	/*
	 * This socket is connected to itself, so all messages are queued to
	 * its receive queue. Here we are going to use this socket to store
	 * file descriptors. For that we need to send a file descriptor in
	 * a queue and remember its sequence number. Then we can set SO_PEEK_OFF
	 * to get a file descriptor without dequeuing it.
	 */
	if (bind(sk, (struct sockaddr *)&addr, addrlen)) {
		pr_perror("Unable to bind a socket");
		close(sk);
		return -1;
	}
	if (connect(sk, (struct sockaddr *)&addr, addrlen)) {
		pr_perror("Unable to connect a socket");
		close(sk);
		return -1;
	}

	ret = install_service_fd(FDSTORE_SK_OFF, sk);
	if (ret < 0)
		return -1;

	return 0;
}

int fdstore_add(int fd)
{
	int sk = get_service_fd(FDSTORE_SK_OFF);
	int id, ret;

	mutex_lock(&desc->lock);

	ret = send_fd(sk, NULL, 0, fd);
	if (ret) {
		pr_perror("Can't send fd %d into store", fd);
		mutex_unlock(&desc->lock);
		return -1;
	}

	id = desc->next_id++;

	mutex_unlock(&desc->lock);

	return id;
}

int fdstore_get(int id)
{
	int sk, fd;

	sk = get_service_fd(FDSTORE_SK_OFF);
	if (sk < 0) {
		pr_err("Cannot get FDSTORE_SK_OFF fd\n");
		return -1;
	}

	mutex_lock(&desc->lock);
	if (setsockopt(sk, SOL_SOCKET, SO_PEEK_OFF, &id, sizeof(id))) {
		mutex_unlock(&desc->lock);
		pr_perror("Unable to a peek offset");
		return -1;
	}

	if (__recv_fds(sk, &fd, 1, NULL, 0, MSG_PEEK) < 0) {
		mutex_unlock(&desc->lock);
		pr_perror("Unable to get a file descriptor with the %d id", id);
		return -1;
	}
	mutex_unlock(&desc->lock);

	return fd;
}
