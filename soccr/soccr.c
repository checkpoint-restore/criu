#include <errno.h>
#include <libnet.h>
#include <linux/sockios.h>
#include <linux/types.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include "soccr.h"

#ifndef SIOCOUTQNSD
/* MAO - Define SIOCOUTQNSD ioctl if we don't have it */
#define SIOCOUTQNSD     0x894B
#endif

enum {
	TCPF_ESTABLISHED = (1 << 1),
	TCPF_SYN_SENT    = (1 << 2),
	TCPF_SYN_RECV    = (1 << 3),
	TCPF_FIN_WAIT1   = (1 << 4),
	TCPF_FIN_WAIT2   = (1 << 5),
	TCPF_TIME_WAIT   = (1 << 6),
	TCPF_CLOSE       = (1 << 7),
	TCPF_CLOSE_WAIT  = (1 << 8),
	TCPF_LAST_ACK    = (1 << 9),
	TCPF_LISTEN      = (1 << 10),
	TCPF_CLOSING     = (1 << 11),
};

/*
 * The TCP transition diagram for half closed connections
 *
 * ------------
 * FIN_WAIT1	\ FIN
 *			---------
 *		/ ACK   CLOSE_WAIT
 * -----------
 * FIN_WAIT2
 *			----------
 *		/ FIN   LAST_ACK
 * -----------
 * TIME_WAIT	\ ACK
 *			----------
 *			CLOSED
 *
 * How to get the TCP_CLOSING state
 *
 * -----------		----------
 * FIN_WAIT1	\/ FIN	FIN_WAIT1
 * -----------		----------
 *  CLOSING		CLOSING
 *		\/ ACK
 * -----------		----------
 *  TIME_WAIT		TIME_WAIT
 */

/* Restore a fin packet in a send queue first */
#define SNDQ_FIRST_FIN	(TCPF_FIN_WAIT1 | TCPF_FIN_WAIT2 | TCPF_CLOSING)
/* Restore fin in a send queue after restoring fi in the receive queue. */
#define SNDQ_SECOND_FIN (TCPF_LAST_ACK | TCPF_CLOSE)
#define SNDQ_FIN_ACKED	(TCPF_FIN_WAIT2 | TCPF_CLOSE)

#define RCVQ_FIRST_FIN	(TCPF_CLOSE_WAIT | TCPF_LAST_ACK | TCPF_CLOSE)
#define RCVQ_SECOND_FIN (TCPF_CLOSING)
#define RCVQ_FIN_ACKED	(TCPF_CLOSE)

static void (*log)(unsigned int loglevel, const char *format, ...)
	__attribute__ ((__format__ (__printf__, 2, 3)));
static unsigned int log_level = 0;

void libsoccr_set_log(unsigned int level, void (*fn)(unsigned int level, const char *fmt, ...))
{
	log_level = level;
	log = fn;
}

#define loge(msg, ...) do { if (log && (log_level >= SOCCR_LOG_ERR)) log(SOCCR_LOG_ERR, "Error (%s:%d): " msg, __FILE__, __LINE__, ##__VA_ARGS__); } while (0)
#define logerr(msg, ...) loge(msg ": %s\n", ##__VA_ARGS__, strerror(errno))
#define logd(msg, ...) do { if (log && (log_level >= SOCCR_LOG_DBG)) log(SOCCR_LOG_DBG, "Debug: " msg, ##__VA_ARGS__); } while (0)

static int tcp_repair_on(int fd)
{
	int ret, aux = 1;

	ret = setsockopt(fd, SOL_TCP, TCP_REPAIR, &aux, sizeof(aux));
	if (ret < 0)
		logerr("Can't turn TCP repair mode ON");

	return ret;
}

static int tcp_repair_off(int fd)
{
	int aux = 0, ret;

	ret = setsockopt(fd, SOL_TCP, TCP_REPAIR, &aux, sizeof(aux));
	if (ret < 0)
		logerr("Failed to turn off repair mode on socket");

	return ret;
}

struct libsoccr_sk {
	int fd;
	unsigned flags;
	char *recv_queue;
	char *send_queue;
	union libsoccr_addr *src_addr;
	union libsoccr_addr *dst_addr;
};

#define SK_FLAG_FREE_RQ		0x1
#define SK_FLAG_FREE_SQ		0x2
#define SK_FLAG_FREE_SA		0x4
#define SK_FLAG_FREE_DA		0x8

struct libsoccr_sk *libsoccr_pause(int fd)
{
	struct libsoccr_sk *ret;

	ret = malloc(sizeof(*ret));
	if (!ret) {
		loge("Unable to allocate memory\n");
		return NULL;
	}

	if (tcp_repair_on(fd) < 0) {
		free(ret);
		return NULL;
	}

	ret->flags = 0;
	ret->recv_queue = NULL;
	ret->send_queue = NULL;
	ret->src_addr = NULL;
	ret->dst_addr = NULL;
	ret->fd = fd;
	return ret;
}

void libsoccr_resume(struct libsoccr_sk *sk)
{
	tcp_repair_off(sk->fd);
	libsoccr_release(sk);
}

void libsoccr_release(struct libsoccr_sk *sk)
{
	if (sk->flags & SK_FLAG_FREE_RQ)
		free(sk->recv_queue);
	if (sk->flags & SK_FLAG_FREE_SQ)
		free(sk->send_queue);
	if (sk->flags & SK_FLAG_FREE_SA)
		free(sk->src_addr);
	if (sk->flags & SK_FLAG_FREE_DA)
		free(sk->dst_addr);
	free(sk);
}

static int refresh_sk(struct libsoccr_sk *sk, struct libsoccr_sk_data *data, struct tcp_info *ti)
{
	int size;
	socklen_t olen = sizeof(*ti);

	if (getsockopt(sk->fd, SOL_TCP, TCP_INFO, ti, &olen) || olen != sizeof(*ti)) {
		logerr("Failed to obtain TCP_INFO");
		return -1;
	}

	switch (ti->tcpi_state) {
	case TCP_ESTABLISHED:
	case TCP_FIN_WAIT1:
	case TCP_FIN_WAIT2:
	case TCP_LAST_ACK:
	case TCP_CLOSE_WAIT:
	case TCP_CLOSING:
	case TCP_CLOSE:
	case TCP_SYN_SENT:
		break;
	default:
		loge("Unknown state %d\n", ti->tcpi_state);
		return -1;
	}

	data->state = ti->tcpi_state;

	if (ioctl(sk->fd, SIOCOUTQ, &size) == -1) {
		logerr("Unable to get size of snd queue");
		return -1;
	}

	data->outq_len = size;

	if (ioctl(sk->fd, SIOCOUTQNSD, &size) == -1) {
		logerr("Unable to get size of unsent data");
		return -1;
	}

	data->unsq_len = size;

	/* Don't account the fin packet. It doesn't countain real data. */
	if ((1 << data->state) & (SNDQ_FIRST_FIN | SNDQ_SECOND_FIN)) {
		if (data->outq_len)
			data->outq_len--;
		data->unsq_len = data->unsq_len ? data->unsq_len - 1 : 0;
	}

	if (ioctl(sk->fd, SIOCINQ, &size) == -1) {
		logerr("Unable to get size of recv queue");
		return -1;
	}

	data->inq_len = size;

	return 0;
}

static int get_stream_options(struct libsoccr_sk *sk, struct libsoccr_sk_data *data, struct tcp_info *ti)
{
	int ret;
	socklen_t auxl;
	int val;

	auxl = sizeof(data->mss_clamp);
	ret = getsockopt(sk->fd, SOL_TCP, TCP_MAXSEG, &data->mss_clamp, &auxl);
	if (ret < 0)
		goto err_sopt;

	data->opt_mask = ti->tcpi_options;
	if (ti->tcpi_options & TCPI_OPT_WSCALE) {
		data->snd_wscale = ti->tcpi_snd_wscale;
		data->rcv_wscale = ti->tcpi_rcv_wscale;
	}

	if (ti->tcpi_options & TCPI_OPT_TIMESTAMPS) {
		auxl = sizeof(val);
		ret = getsockopt(sk->fd, SOL_TCP, TCP_TIMESTAMP, &val, &auxl);
		if (ret < 0)
			goto err_sopt;

		data->timestamp = val;
	}

	return 0;

err_sopt:
	logerr("\tsockopt failed");
	return -1;
}

static int get_window(struct libsoccr_sk *sk, struct libsoccr_sk_data *data)
{
	struct tcp_repair_window opt;
	socklen_t optlen = sizeof(opt);

	if (getsockopt(sk->fd, SOL_TCP,
			TCP_REPAIR_WINDOW, &opt, &optlen)) {
		/* Appeared since 4.8, but TCP_repair itself is since 3.11 */
		if (errno == ENOPROTOOPT)
			return 0;

		logerr("Unable to get window properties");
		return -1;
	}

	data->flags |= SOCCR_FLAGS_WINDOW;
	data->snd_wl1		= opt.snd_wl1;
	data->snd_wnd		= opt.snd_wnd;
	data->max_window	= opt.max_window;
	data->rcv_wnd		= opt.rcv_wnd;
	data->rcv_wup		= opt.rcv_wup;

	return 0;
}

/*
 * TCP queues sequences and their relations to the code below
 *
 *       output queue
 * net <----------------------------- sk
 *        ^       ^       ^    seq >>
 *        snd_una snd_nxt write_seq
 *
 *                     input  queue
 * net -----------------------------> sk
 *     << seq   ^       ^
 *              rcv_nxt copied_seq
 *
 *
 * inq_len  = rcv_nxt - copied_seq = SIOCINQ
 * outq_len = write_seq - snd_una  = SIOCOUTQ
 * inq_seq  = rcv_nxt
 * outq_seq = write_seq
 *
 * On restore kernel moves the option we configure with setsockopt,
 * thus we should advance them on the _len value in restore_tcp_seqs.
 *
 */

static int get_queue(int sk, int queue_id,
		__u32 *seq, __u32 len, char **bufp)
{
	int ret, aux;
	socklen_t auxl;
	char *buf;

	aux = queue_id;
	auxl = sizeof(aux);
	ret = setsockopt(sk, SOL_TCP, TCP_REPAIR_QUEUE, &aux, auxl);
	if (ret < 0)
		goto err_sopt;

	auxl = sizeof(*seq);
	ret = getsockopt(sk, SOL_TCP, TCP_QUEUE_SEQ, seq, &auxl);
	if (ret < 0)
		goto err_sopt;

	if (len) {
		/*
		 * Try to grab one byte more from the queue to
		 * make sure there are len bytes for real
		 */
		buf = malloc(len + 1);
		if (!buf) {
			loge("Unable to allocate memory\n");
			goto err_buf;
		}

		ret = recv(sk, buf, len + 1, MSG_PEEK | MSG_DONTWAIT);
		if (ret != len)
			goto err_recv;
	} else
		buf = NULL;

	*bufp = buf;
	return 0;

err_sopt:
	logerr("\tsockopt failed");
err_buf:
	return -1;

err_recv:
	logerr("\trecv failed (%d, want %d)", ret, len);
	free(buf);
	goto err_buf;
}

/*
 * This is how much data we've had in the initial libsoccr
 */
#define SOCR_DATA_MIN_SIZE	(17 * sizeof(__u32))

int libsoccr_save(struct libsoccr_sk *sk, struct libsoccr_sk_data *data, unsigned data_size)
{
	struct tcp_info ti;

	if (!data || data_size < SOCR_DATA_MIN_SIZE) {
		loge("Invalid input parameters\n");
		return -1;
	}

	memset(data, 0, data_size);

	if (refresh_sk(sk, data, &ti))
		return -2;

	if (get_stream_options(sk, data, &ti))
		return -3;

	if (get_window(sk, data))
		return -4;

	sk->flags |= SK_FLAG_FREE_SQ | SK_FLAG_FREE_RQ;

	if (get_queue(sk->fd, TCP_RECV_QUEUE, &data->inq_seq, data->inq_len, &sk->recv_queue))
		return -5;

	if (get_queue(sk->fd, TCP_SEND_QUEUE, &data->outq_seq, data->outq_len, &sk->send_queue))
		return -6;

	return sizeof(struct libsoccr_sk_data);
}

#define GET_Q_FLAGS	(SOCCR_MEM_EXCL)
char *libsoccr_get_queue_bytes(struct libsoccr_sk *sk, int queue_id, unsigned flags)
{
	char **p, *ret;

	if (flags & ~GET_Q_FLAGS)
		return NULL;

	switch (queue_id) {
		case TCP_RECV_QUEUE:
			p = &sk->recv_queue;
			break;
		case TCP_SEND_QUEUE:
			p = &sk->send_queue;
			break;
		default:
			return NULL;
	}

	ret = *p;
	if (flags & SOCCR_MEM_EXCL)
		*p = NULL;

	return ret;
}

#define GET_SA_FLAGS	(SOCCR_MEM_EXCL)
union libsoccr_addr *libsoccr_get_addr(struct libsoccr_sk *sk, int self, unsigned flags)
{
	if (flags & ~GET_SA_FLAGS)
		return NULL;

	/* FIXME -- implemeted in CRIU, makes sence to have it here too */
	return NULL;
}

static int set_queue_seq(struct libsoccr_sk *sk, int queue, __u32 seq)
{
	logd("\tSetting %d queue seq to %u\n", queue, seq);

	if (setsockopt(sk->fd, SOL_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue)) < 0) {
		logerr("Can't set repair queue");
		return -1;
	}

	if (setsockopt(sk->fd, SOL_TCP, TCP_QUEUE_SEQ, &seq, sizeof(seq)) < 0) {
		logerr("Can't set queue seq");
		return -1;
	}

	return 0;
}

#ifndef TCPOPT_SACK_PERM
#define TCPOPT_SACK_PERM TCPOPT_SACK_PERMITTED
#endif

static int libsoccr_set_sk_data_noq(struct libsoccr_sk *sk,
		struct libsoccr_sk_data *data, unsigned data_size)
{
	struct tcp_repair_opt opts[4];
	int addr_size, mstate;
	int onr = 0;
	__u32 seq;

	if (!data || data_size < SOCR_DATA_MIN_SIZE) {
		loge("Invalid input parameters\n");
		return -1;
	}

	if (!sk->dst_addr || !sk->src_addr) {
		loge("Destination or/and source addresses aren't set\n");
		return -1;
	}

	mstate = 1 << data->state;

	if (data->state == TCP_LISTEN) {
		loge("Unable to handle listen sockets\n");
		return -1;
	}

	if (sk->src_addr->sa.sa_family == AF_INET)
		addr_size = sizeof(sk->src_addr->v4);
	else
		addr_size = sizeof(sk->src_addr->v6);

	if (bind(sk->fd, &sk->src_addr->sa, addr_size)) {
		logerr("Can't bind inet socket back");
		return -1;
	}

	if (mstate & (RCVQ_FIRST_FIN | RCVQ_SECOND_FIN))
		data->inq_seq--;

	/* outq_seq is adjusted due to not accointing the fin packet */
	if (mstate & (SNDQ_FIRST_FIN | SNDQ_SECOND_FIN))
		data->outq_seq--;

	if (set_queue_seq(sk, TCP_RECV_QUEUE,
				data->inq_seq - data->inq_len))
		return -2;

	seq = data->outq_seq - data->outq_len;
	if (data->state == TCP_SYN_SENT)
		seq--;

	if (set_queue_seq(sk, TCP_SEND_QUEUE, seq))
		return -3;

	if (sk->dst_addr->sa.sa_family == AF_INET)
		addr_size = sizeof(sk->dst_addr->v4);
	else
		addr_size = sizeof(sk->dst_addr->v6);

	if (data->state == TCP_SYN_SENT && tcp_repair_off(sk->fd))
		return -1;

	if (connect(sk->fd, &sk->dst_addr->sa, addr_size) == -1 &&
						errno != EINPROGRESS) {
		loge("Can't connect inet socket back\n");
		return -1;
	}

	if (data->state == TCP_SYN_SENT && tcp_repair_on(sk->fd))
		return -1;

	logd("\tRestoring TCP options\n");

	if (data->opt_mask & TCPI_OPT_SACK) {
		logd("\t\tWill turn SAK on\n");
		opts[onr].opt_code = TCPOPT_SACK_PERM;
		opts[onr].opt_val = 0;
		onr++;
	}

	if (data->opt_mask & TCPI_OPT_WSCALE) {
		logd("\t\tWill set snd_wscale to %u\n", data->snd_wscale);
		logd("\t\tWill set rcv_wscale to %u\n", data->rcv_wscale);
		opts[onr].opt_code = TCPOPT_WINDOW;
		opts[onr].opt_val = data->snd_wscale + (data->rcv_wscale << 16);
		onr++;
	}

	if (data->opt_mask & TCPI_OPT_TIMESTAMPS) {
		logd("\t\tWill turn timestamps on\n");
		opts[onr].opt_code = TCPOPT_TIMESTAMP;
		opts[onr].opt_val = 0;
		onr++;
	}

	logd("Will set mss clamp to %u\n", data->mss_clamp);
	opts[onr].opt_code = TCPOPT_MAXSEG;
	opts[onr].opt_val = data->mss_clamp;
	onr++;

	if (data->state != TCP_SYN_SENT &&
	    setsockopt(sk->fd, SOL_TCP, TCP_REPAIR_OPTIONS,
				opts, onr * sizeof(struct tcp_repair_opt)) < 0) {
		logerr("Can't repair options");
		return -2;
	}

	if (data->opt_mask & TCPI_OPT_TIMESTAMPS) {
		if (setsockopt(sk->fd, SOL_TCP, TCP_TIMESTAMP,
				&data->timestamp, sizeof(data->timestamp)) < 0) {
			logerr("Can't set timestamp");
			return -3;
		}
	}

	return 0;
}

static int send_fin(struct libsoccr_sk *sk, struct libsoccr_sk_data *data,
		unsigned data_size, uint8_t flags)
{
	int ret, exit_code = -1;
	char errbuf[LIBNET_ERRBUF_SIZE];
	int mark = SOCCR_MARK;;
	int libnet_type;
	libnet_t *l;

	if (sk->dst_addr->sa.sa_family == AF_INET6)
		libnet_type = LIBNET_RAW6;
	else
		libnet_type = LIBNET_RAW4;

	l = libnet_init(
		libnet_type,		/* injection type */
		NULL,			/* network interface */
		errbuf);		/* errbuf */
	if (l == NULL) {
		loge("libnet_init failed (%s)\n", errbuf);
		return -1;
	}

	if (setsockopt(l->fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark))) {
		logerr("Can't set SO_MARK (%d) for socket\n", mark);
		goto err;
	}

	ret = libnet_build_tcp(
		ntohs(sk->dst_addr->v4.sin_port),		/* source port */
		ntohs(sk->src_addr->v4.sin_port),		/* destination port */
		data->inq_seq,			/* sequence number */
		data->outq_seq - data->outq_len,	/* acknowledgement num */
		flags,				/* control flags */
		data->rcv_wnd,			/* window size */
		0,				/* checksum */
		10,				/* urgent pointer */
		LIBNET_TCP_H + 20,		/* TCP packet size */
		NULL,				/* payload */
		0,				/* payload size */
		l,				/* libnet handle */
		0);				/* libnet id */
	if (ret == -1) {
		loge("Can't build TCP header: %s\n", libnet_geterror(l));
		goto err;
	}

	if (sk->dst_addr->sa.sa_family == AF_INET6) {
		struct libnet_in6_addr src, dst;

		memcpy(&dst, &sk->dst_addr->v6.sin6_addr, sizeof(dst));
		memcpy(&src, &sk->src_addr->v6.sin6_addr, sizeof(src));

		ret = libnet_build_ipv6(
			0, 0,
			LIBNET_TCP_H,	/* length */
			IPPROTO_TCP,	/* protocol */
			64,		/* hop limit */
			dst,		/* source IP */
			src,		/* destination IP */
			NULL,		/* payload */
			0,		/* payload size */
			l,		/* libnet handle */
			0);		/* libnet id */
	} else if (sk->dst_addr->sa.sa_family == AF_INET)
		ret = libnet_build_ipv4(
			LIBNET_IPV4_H + LIBNET_TCP_H + 20,	/* length */
			0,			/* TOS */
			242,			/* IP ID */
			0,			/* IP Frag */
			64,			/* TTL */
			IPPROTO_TCP,		/* protocol */
			0,			/* checksum */
			sk->dst_addr->v4.sin_addr.s_addr,	/* source IP */
			sk->src_addr->v4.sin_addr.s_addr,	/* destination IP */
			NULL,			/* payload */
			0,			/* payload size */
			l,			/* libnet handle */
			0);			/* libnet id */
	else {
		loge("Unknown socket family\n");
		goto err;
	}
	if (ret == -1) {
		loge("Can't build IP header: %s\n", libnet_geterror(l));
		goto err;
	}

	ret = libnet_write(l);
	if (ret == -1) {
		loge("Unable to send a fin packet: %s\n", libnet_geterror(l));
		goto err;
	}

	exit_code = 0;
err:
	libnet_destroy(l);
	return exit_code;
}

static int restore_fin_in_snd_queue(int sk, int acked)
{
	int queue = TCP_SEND_QUEUE;
	int ret;

	/*
	 * If TCP_SEND_QUEUE is set, a fin packet will be
	 * restored as a sent packet.
	 */
	if (acked &&
	    setsockopt(sk, SOL_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue)) < 0) {
		logerr("Can't set repair queue");
		return -1;
	}

	ret = shutdown(sk, SHUT_WR);
	if (ret < 0)
		logerr("Unable to shut down a socket");

	queue = TCP_NO_QUEUE;
	if (acked &&
	    setsockopt(sk, SOL_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue)) < 0) {
		logerr("Can't set repair queue");
		return -1;
	}

	return ret;
}

static int libsoccr_restore_queue(struct libsoccr_sk *sk, struct libsoccr_sk_data *data, unsigned data_size,
		int queue, char *buf);

int libsoccr_restore(struct libsoccr_sk *sk,
		struct libsoccr_sk_data *data, unsigned data_size)
{
	int mstate = 1 << data->state;

	if (libsoccr_set_sk_data_noq(sk, data, data_size))
		return -1;

	if (libsoccr_restore_queue(sk, data, sizeof(*data), TCP_RECV_QUEUE, sk->recv_queue))
		return -1;

	if (libsoccr_restore_queue(sk, data, sizeof(*data), TCP_SEND_QUEUE, sk->send_queue))
		return -1;

	if (data->flags & SOCCR_FLAGS_WINDOW) {
		struct tcp_repair_window wopt = {
			.snd_wl1 = data->snd_wl1,
			.snd_wnd = data->snd_wnd,
			.max_window = data->max_window,
			.rcv_wnd = data->rcv_wnd,
			.rcv_wup = data->rcv_wup,
		};

		if (mstate & (RCVQ_FIRST_FIN | RCVQ_SECOND_FIN)) {
			wopt.rcv_wup--;
			wopt.rcv_wnd++;
		}

		if (setsockopt(sk->fd, SOL_TCP, TCP_REPAIR_WINDOW, &wopt, sizeof(wopt))) {
			logerr("Unable to set window parameters");
			return -1;
		}
	}

	/*
	 * To restore a half closed sockets, fin packets has to be restored in
	 * recv and send queues. Here shutdown() is used to restore a fin
	 * packet in the send queue and a fake fin packet is send to restore it
	 * in the recv queue.
	 */
	if (mstate & SNDQ_FIRST_FIN)
		restore_fin_in_snd_queue(sk->fd, mstate & SNDQ_FIN_ACKED);

	/* Send a fin packet to the socket to restore it in a receive queue. */
	if (mstate & (RCVQ_FIRST_FIN | RCVQ_SECOND_FIN))
		if (send_fin(sk, data, data_size, TH_ACK | TH_FIN) < 0)
			return -1;

	if (mstate & SNDQ_SECOND_FIN)
		restore_fin_in_snd_queue(sk->fd, mstate & SNDQ_FIN_ACKED);

	if (mstate & RCVQ_FIN_ACKED)
		data->inq_seq++;

	if (mstate & SNDQ_FIN_ACKED) {
		data->outq_seq++;
		if (send_fin(sk, data, data_size, TH_ACK) < 0)
			return -1;
	}

	return 0;
}

static int __send_queue(struct libsoccr_sk *sk, int queue, char *buf, __u32 len)
{
	int ret, err = -1, max_chunk;
	int off;

	max_chunk = len;
	off = 0;

	do {
		int chunk = len;

		if (chunk > max_chunk)
			chunk = max_chunk;

		ret = send(sk->fd, buf + off, chunk, 0);
		if (ret <= 0) {
			if (max_chunk > 1024) {
				/*
				 * Kernel not only refuses the whole chunk,
				 * but refuses to split it into pieces too.
				 *
				 * When restoring recv queue in repair mode
				 * kernel doesn't try hard and just allocates
				 * a linear skb with the size we pass to the
				 * system call. Thus, if the size is too big
				 * for slab allocator, the send just fails
				 * with ENOMEM.
				 *
				 * In any case -- try smaller chunk, hopefully
				 * there's still enough memory in the system.
				 */
				max_chunk >>= 1;
				continue;
			}

			logerr("Can't restore %d queue data (%d), want (%d:%d:%d)",
				  queue, ret, chunk, len, max_chunk);
			goto err;
		}
		off += ret;
		len -= ret;
	} while (len);

	err = 0;
err:
	return err;
}

static int send_queue(struct libsoccr_sk *sk, int queue, char *buf, __u32 len)
{
	logd("\tRestoring TCP %d queue data %u bytes\n", queue, len);

	if (setsockopt(sk->fd, SOL_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue)) < 0) {
		logerr("Can't set repair queue");
		return -1;
	}

	return __send_queue(sk, queue, buf, len);
}

static int libsoccr_restore_queue(struct libsoccr_sk *sk, struct libsoccr_sk_data *data, unsigned data_size,
		int queue, char *buf)
{
	if (!buf)
		return 0;

	if (!data || data_size < SOCR_DATA_MIN_SIZE)
		return -1;

	if (queue == TCP_RECV_QUEUE) {
		if (!data->inq_len)
			return 0;
		return send_queue(sk, TCP_RECV_QUEUE, buf, data->inq_len);
	}

	if (queue == TCP_SEND_QUEUE) {
		__u32 len, ulen;

		/*
		 * All data in a write buffer can be divided on two parts sent
		 * but not yet acknowledged data and unsent data.
		 * The TCP stack must know which data have been sent, because
		 * acknowledgment can be received for them. These data must be
		 * restored in repair mode.
		 */
		ulen = data->unsq_len;
		len = data->outq_len - ulen;
		if (len && send_queue(sk, TCP_SEND_QUEUE, buf, len))
			return -2;

		if (ulen) {
			/*
			 * The second part of data have never been sent to outside, so
			 * they can be restored without any tricks.
			 */
			tcp_repair_off(sk->fd);
			if (__send_queue(sk, TCP_SEND_QUEUE, buf + len, ulen))
				return -3;
			if (tcp_repair_on(sk->fd))
				return -4;
		}

		return 0;
	}

	return -5;
}

#define SET_Q_FLAGS	(SOCCR_MEM_EXCL)
int libsoccr_set_queue_bytes(struct libsoccr_sk *sk, int queue_id, char *bytes, unsigned flags)
{
	if (flags & ~SET_Q_FLAGS)
		return -1;

	switch (queue_id) {
		case TCP_RECV_QUEUE:
			sk->recv_queue = bytes;
			if (flags & SOCCR_MEM_EXCL)
				sk->flags |= SK_FLAG_FREE_RQ;
			return 0;
		case TCP_SEND_QUEUE:
			sk->send_queue = bytes;
			if (flags & SOCCR_MEM_EXCL)
				sk->flags |= SK_FLAG_FREE_SQ;
			return 0;
	}

	return -1;
}

#define SET_SA_FLAGS	(SOCCR_MEM_EXCL)
int libsoccr_set_addr(struct libsoccr_sk *sk, int self, union libsoccr_addr *addr, unsigned flags)
{
	if (flags & ~SET_SA_FLAGS)
		return -1;

	if (self) {
		sk->src_addr = addr;
		if (flags & SOCCR_MEM_EXCL)
			sk->flags |= SK_FLAG_FREE_SA;
	} else {
		sk->dst_addr = addr;
		if (flags & SOCCR_MEM_EXCL)
			sk->flags |= SK_FLAG_FREE_DA;
	}

	return 0;
}
