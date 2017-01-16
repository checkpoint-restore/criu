#ifndef __LIBSOCCR_H__
#define __LIBSOCCR_H__
#include <linux/types.h>
#include <netinet/in.h>
#include <stdint.h>

#include "config.h"

/* All packets with this mark have not to be blocked. */
#define SOCCR_MARK 0xC114

#ifndef CONFIG_HAS_TCP_REPAIR_WINDOW
struct tcp_repair_window {
	uint32_t   snd_wl1;
	uint32_t   snd_wnd;
	uint32_t   max_window;

	uint32_t   rcv_wnd;
	uint32_t   rcv_wup;
};
#endif

#ifndef CONFIG_HAS_TCP_REPAIR
/*
 * It's been reported that both tcp_repair_opt
 * and TCP_ enum already shipped in netinet/tcp.h
 * system header by some distros thus we need a
 * test if we can use predefined ones or provide
 * our own.
 */
struct tcp_repair_opt {
	uint32_t	opt_code;
	uint32_t	opt_val;
};

enum {
	TCP_NO_QUEUE,
	TCP_RECV_QUEUE,
	TCP_SEND_QUEUE,
	TCP_QUEUES_NR,
};
#endif

#ifndef TCP_TIMESTAMP
#define TCP_TIMESTAMP	24
#endif

#ifndef TCP_REPAIR_WINDOW
#define TCP_REPAIR_WINDOW       29
#endif

struct libsoccr_sk;

void libsoccr_set_log(unsigned int level, void (*fn)(unsigned int level, const char *fmt, ...));

#define SOCCR_LOG_ERR	1
#define SOCCR_LOG_DBG	2

/*
 * An opaque handler for C/R-ing a TCP socket.
 */
struct libsoccr_sk;

union libsoccr_addr {
	struct sockaddr sa;
	struct sockaddr_in v4;
	struct sockaddr_in6 v6;
};

/*
 * Connection info that should be saved after fetching from the
 * socket and given back into the library in two steps (see below).
 */
struct libsoccr_sk_data {
	__u32	state;
	__u32	inq_len;
	__u32	inq_seq;
	__u32	outq_len;
	__u32	outq_seq;
	__u32	unsq_len;
	__u32	opt_mask;
	__u32	mss_clamp;
	__u32	snd_wscale;
	__u32	rcv_wscale;
	__u32	timestamp;

	__u32	flags; /* SOCCR_FLAGS_... below */
	__u32	snd_wl1;
	__u32	snd_wnd;
	__u32	max_window;
	__u32	rcv_wnd;
	__u32	rcv_wup;
};

/*
 * The flags below denote which data on libsoccr_sk_data was get
 * from the kernel and is required for restore. Not present data
 * is zeroified by the library.
 *
 * Ideally the caller should carry the whole _data structure between 
 * calls, but for optimization purposes it may analyze the flags
 * field and drop the unneeded bits.
 */

/*
 * Window parameters. Mark snd_wl1, snd_wnd, max_window, rcv_wnd
 * and rcv_wup fields.
 */
#define SOCCR_FLAGS_WINDOW	0x1

/*
 * These two calls pause and resume the socket for and after C/R
 * The first one returns an opaque handle that is to be used by all
 * the subsequent calls.
 *
 * For now the library only supports ESTABLISHED sockets. The caller
 * should check the socket is supported before calling the library.
 *
 * Before doing socket C/R make sure no packets can reach the socket
 * you're working with, nor any packet can leave the node from this
 * socket. This can be done by using netfilter DROP target (of by
 * DOWN-ing an interface in case of containers).
 */
struct libsoccr_sk *libsoccr_pause(int fd);
void libsoccr_resume(struct libsoccr_sk *sk);

/* This one is like _resume, but doesn't turn repair off on socket. */
void libsoccr_release(struct libsoccr_sk *sk);

/*
 * Flags for calls below
 */

/*
 * Memory given to or taken from library is in exclusive ownership
 * of the resulting owner. I.e. -- when taken by caller from library,
 * the former will free() one, when given to the library, the latter
 * is to free() it.
 */
#define SOCCR_MEM_EXCL		0x1

/*
 * CHECKPOINTING calls
 *
 * Roughly the checkpoint steps for sockets in supported states are
 *
 * 	h = libsoccr_pause(sk);
 * 	libsoccr_save(h, &data, sizeof(data))
 * 	inq = libsoccr_get_queue_bytes(h, TCP_RECV_QUEUE, 0)
 * 	outq = libsoccr_get_queue_bytes(h, TCP_SEND_QUEUE, 0)
 * 	getsocname(sk, &name, ...)
 * 	getpeername(sk, &peer, ...)
 *
 * 	save_all_bytes(h, inq, outq, name, peer)
 *
 * Resuming the socket afterwards effectively obsoletes the saved
 * info, as the connection resumes and old saved bytes become
 * outdated.
 *
 * Please note, that getsocname() and getpeername() are standard glibc
 * calls, not the libsoccr's ones.
 */

/*
 * Fills in the libsoccr_sk_data structure with connection info. The
 * data_size shows the size of a buffer. The returned value is the
 * amount of bytes put into data (the rest is zeroed with memcpy).
 */
int libsoccr_save(struct libsoccr_sk *sk, struct libsoccr_sk_data *data, unsigned data_size);

/*
 * Get a pointer on the contents of queues. The amount of bytes is
 * determined from the filled libsoccr_sk_data by queue_id.
 *
 * For TCP_RECV_QUEUE the lenght is .inq_len
 * For TCP_SEND_QUEUE the lenght is .outq_len
 *
 * For any other queues returns NULL.
 *
 * The steal argument means that the caller grabs the buffer from
 * library and should free() it himself. Otherwise the buffer can
 * be claimed again and will be free by library upon _resume call.
 */
char *libsoccr_get_queue_bytes(struct libsoccr_sk *sk, int queue_id, unsigned flags);

/*
 * Returns filled libsoccr_addr for a socket. This value is also required
 * on restore, but addresses may be obtained from somewhere else, these
 * are just common sockaddr-s.
 */
union libsoccr_addr *libsoccr_get_addr(struct libsoccr_sk *sk, int self, unsigned flags);

/*
 * RESTORING calls
 *
 * The restoring of a socket is like below
 *
 * 	get_all_bytes(h, inq, outq, name, peer)
 *
 * 	sk = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
 *
 * 	h = libsoccr_pause(sk)
 * 	libsoccr_set_queue_bytes(h, TCP_SEND_QUEUE, outq);
 * 	libsoccr_set_queue_bytes(h, TCP_RECV_QUEUE, inq);
 * 	libsoccr_set_addr(h, 1, src_addr);
 * 	libsoccr_set_addr(h, 0, dst_addr);
 * 	libsoccr_restore(h, &data, sizeof(data))
 *
 * 	libsoccr_resume(h)
 *
 * Only after this the packets path from and to the socket can be
 * enabled back.
 */

/*
 * Set a pointer on the send/recv queue data.
 * If flags have SOCCR_MEM_EXCL, the buffer is stolen by the library and is 
 * free()-ed after libsoccr_resume().
 */
int libsoccr_set_queue_bytes(struct libsoccr_sk *sk, int queue_id, char *bytes, unsigned flags);

/*
 * Set a pointer on the libsoccr_addr for src/dst.
 * If flags have SOCCR_MEM_EXCL, the buffer is stolen by the library and is 
 * fre()-ed after libsoccr_resume().
 */
int libsoccr_set_addr(struct libsoccr_sk *sk, int self, union libsoccr_addr *, unsigned flags);

/*
 * Performs restore actions on a socket
 */
int libsoccr_restore(struct libsoccr_sk *sk, struct libsoccr_sk_data *data, unsigned data_size);

#endif
