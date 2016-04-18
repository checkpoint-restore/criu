#include <netinet/tcp.h>
#include <stdlib.h>
#include "soccr.h"

static void (*log)(unsigned int loglevel, const char *format, ...)
	__attribute__ ((__format__ (__printf__, 2, 3)));
static unsigned int log_level = 0;

void libsoccr_set_log(unsigned int level, void (*fn)(unsigned int level, const char *fmt, ...))
{
	log_level = level;
	log = fn;
}

#define loge(msg, ...) do { if (log && (log_level >= SOCCR_LOG_ERR)) log(SOCCR_LOG_ERR, msg, ##__VA_ARGS__); } while (0)
#define logd(msg, ...) do { if (log && (log_level >= SOCCR_LOG_DBG)) log(SOCCR_LOG_DBG, msg, ##__VA_ARGS__); } while (0)

static int tcp_repair_on(int fd)
{
	int ret, aux = 1;

	ret = setsockopt(fd, SOL_TCP, TCP_REPAIR, &aux, sizeof(aux));
	if (ret < 0)
		loge("Can't turn TCP repair mode ON");

	return ret;
}

static void tcp_repair_off(int fd)
{
	int aux = 0, ret;

	ret = setsockopt(fd, SOL_TCP, TCP_REPAIR, &aux, sizeof(aux));
	if (ret < 0)
		loge("Failed to turn off repair mode on socket: %m\n");
}

struct libsoccr_sk {
	int fd;
};

struct libsoccr_sk *libsoccr_pause(int fd)
{
	struct libsoccr_sk *ret;

	ret = malloc(sizeof(*ret));
	if (!ret)
		return NULL;

	if (tcp_repair_on(fd) < 0) {
		free(ret);
		return NULL;
	}

	ret->fd = fd;
	return ret;
}

void libsoccr_resume(struct libsoccr_sk *sk)
{
	tcp_repair_off(sk->fd);
	free(sk);
}
