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

static struct fdstore_desc {
	int next_id;
	mutex_t lock; /* to protect a peek offset */
} *desc;

int fdstore_init(void)
{
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

	addr.sun_family = AF_UNIX;
	addrlen = snprintf(addr.sun_path, sizeof(addr.sun_path), "X/criu-fdstore-%"PRIx64, st.st_ino);
	addrlen += sizeof(addr.sun_family);

	addr.sun_path[0] = 0;

	/*
	 * This socket is connected to itself, so all messages are queued to
	 * its receive queue. Here we are going to use this socket to store
	 * file descriptors. For that we need to send a file descriptor in
	 * a queue and remeber its sequence number. Then we can set SO_PEEK_OFF
	 * to get a file descriptor without dequeuing it.
	 */
	if (bind(sk, (struct sockaddr *) &addr, addrlen)) {
		pr_perror("Unable to bind a socket");
		close(sk);
		return -1;
	}
	if (connect(sk, (struct sockaddr *) &addr, addrlen)) {
		pr_perror("Unable to connect a socket");
		close(sk);
		return -1;
	}

	ret = install_service_fd(FDSTORE_SK_OFF, sk);
	close(sk);
	if (ret < 0)
		return -1;

	return 0;
}

int fdstore_add(int fd)
{
	int sk = get_service_fd(FDSTORE_SK_OFF);
	int id;

	mutex_lock(&desc->lock);

	if (send_fd(sk, NULL, 0, fd)) {
		mutex_unlock(&desc->lock);
		return -1;
	}

	id = desc->next_id++;

	mutex_unlock(&desc->lock);

	return id;
}

int fdstore_get(int id)
{
	int sk = get_service_fd(FDSTORE_SK_OFF);
	int fd;

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
