#ifndef __LIBSOCCR_H__
#define __LIBSOCCR_H__
#include <linux/types.h>

struct libsoccr_sk;

void libsoccr_set_log(unsigned int level, void (*fn)(unsigned int level, const char *fmt, ...));

#define SOCCR_LOG_ERR	1
#define SOCCR_LOG_DBG	2

struct libsoccr_sk;

struct libsoccr_sk_data {
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

struct libsoccr_sk *libsoccr_pause(int fd);
void libsoccr_resume(struct libsoccr_sk *sk);

int libsoccr_get_sk_data(struct libsoccr_sk *sk, struct libsoccr_sk_data *data, unsigned data_size);
char *libsoccr_get_queue_bytes(struct libsoccr_sk *sk, int queue_id, int steal);

int libsoccr_set_sk_data_unbound(struct libsoccr_sk *sk, struct libsoccr_sk_data *data, unsigned data_size);
int libsoccr_set_sk_data_noq(struct libsoccr_sk *sk, struct libsoccr_sk_data *data, unsigned data_size);
int libsoccr_set_sk_data(struct libsoccr_sk *sk, struct libsoccr_sk_data *data, unsigned data_size);
int libsoccr_set_queue_bytes(struct libsoccr_sk *sk, struct libsoccr_sk_data *data, unsigned data_size,
		int queue, char *buf);
#endif
