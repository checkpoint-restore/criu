#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <unistd.h>
#include <stdlib.h>

#include "crtools.h"
#include "util.h"
#include "list.h"
#include "log.h"
#include "types.h"
#include "files.h"
#include "sockets.h"
#include "files.h"
#include "sk-inet.h"
#include "netfilter.h"
#include "image.h"

#include "protobuf.h"
#include "protobuf/tcp-stream.pb-c.h"

#ifndef TCP_REPAIR
#define TCP_REPAIR		19      /* TCP sock is under repair right now */
#define TCP_REPAIR_QUEUE	20
#define TCP_QUEUE_SEQ		21
#define TCP_REPAIR_OPTIONS	22

struct tcp_repair_opt {
	u32	opt_code;
	u32	opt_val;
};

enum {
	TCP_NO_QUEUE,
	TCP_RECV_QUEUE,
	TCP_SEND_QUEUE,
	TCP_QUEUES_NR,
};
#endif

#ifndef TCPOPT_SACK_PERM
#define TCPOPT_SACK_PERM TCPOPT_SACK_PERMITTED
#endif

static LIST_HEAD(tcp_repair_sockets);

static int tcp_repair_on(int fd)
{
	int ret, aux = 1;

	ret = setsockopt(fd, SOL_TCP, TCP_REPAIR, &aux, sizeof(aux));
	if (ret < 0)
		pr_perror("Can't turn TCP repair mode ON");

	return ret;
}

static void tcp_repair_off(int fd)
{
	int aux = 0;

	if (setsockopt(fd, SOL_TCP, TCP_REPAIR, &aux, sizeof(aux)) < 0)
		pr_perror("Failed to turn off repair mode on socket");
}

static int tcp_repair_establised(int fd, struct inet_sk_desc *sk)
{
	int ret;

	pr_info("\tTurning repair on for socket %x\n", sk->sd.ino);
	/*
	 * Keep the socket open in crtools till the very end. In
	 * case we close this fd after one task fd dumping and
	 * fail we'll have to turn repair mode off
	 */
	sk->rfd = dup(fd);
	if (sk->rfd < 0) {
		pr_perror("Can't save socket fd for repair");
		goto err1;
	}

	ret = nf_lock_connection(sk);
	if (ret < 0)
		goto err2;

	ret = tcp_repair_on(sk->rfd);
	if (ret < 0)
		goto err3;

	list_add_tail(&sk->rlist, &tcp_repair_sockets);
	return 0;

err3:
	nf_unlock_connection(sk);
err2:
	close(sk->rfd);
err1:
	return -1;
}

static void tcp_unlock_one(struct inet_sk_desc *sk)
{
	int ret;

	list_del(&sk->rlist);

	ret = nf_unlock_connection(sk);
	if (ret < 0)
		pr_perror("Failed to unlock TCP connection");

	tcp_repair_off(sk->rfd);
	close(sk->rfd);
}

void tcp_unlock_all(void)
{
	struct inet_sk_desc *sk, *n;

	list_for_each_entry_safe(sk, n, &tcp_repair_sockets, rlist)
		tcp_unlock_one(sk);
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

static int tcp_stream_get_queue(int sk, int queue_id,
		u32 *seq, u32 len, char **bufp)
{
	int ret, aux;
	socklen_t auxl;
	char *buf;

	pr_debug("\tSet repair queue %d\n", queue_id);
	aux = queue_id;
	auxl = sizeof(aux);
	ret = setsockopt(sk, SOL_TCP, TCP_REPAIR_QUEUE, &aux, auxl);
	if (ret < 0)
		goto err_sopt;

	pr_debug("\tGet queue seq\n");
	auxl = sizeof(*seq);
	ret = getsockopt(sk, SOL_TCP, TCP_QUEUE_SEQ, seq, &auxl);
	if (ret < 0)
		goto err_sopt;

	pr_info("\t`- seq %u len %u\n", *seq, len);

	if (len) {
		/*
		 * Try to grab one byte more from the queue to
		 * make sure there are len bytes for real
		 */
		buf = xmalloc(len + 1);
		if (!buf)
			goto err_buf;

		pr_debug("\tReading queue (%d bytes)\n", len);
		ret = recv(sk, buf, len + 1, MSG_PEEK | MSG_DONTWAIT);
		if (ret != len)
			goto err_recv;
	} else
		buf = NULL;

	*bufp = buf;
	return 0;

err_sopt:
	pr_perror("\tsockopt failed");
err_buf:
	return -1;

err_recv:
	pr_perror("\trecv failed (%d, want %d, errno %d)", ret, len, errno);
	xfree(buf);
	goto err_buf;
}

static int tcp_stream_get_options(int sk, TcpStreamEntry *tse)
{
	int ret;
	socklen_t auxl;
	struct tcp_info ti;

	auxl = sizeof(ti);
	ret = getsockopt(sk, SOL_TCP, TCP_INFO, &ti, &auxl);
	if (ret < 0)
		goto err_sopt;

	auxl = sizeof(tse->mss_clamp);
	ret = getsockopt(sk, SOL_TCP, TCP_MAXSEG, &tse->mss_clamp, &auxl);
	if (ret < 0)
		goto err_sopt;

	tse->opt_mask = ti.tcpi_options;
	if (ti.tcpi_options & TCPI_OPT_WSCALE)
		tse->snd_wscale = ti.tcpi_snd_wscale;

	pr_info("\toptions: mss_clamp %x wscale %x tstamp %d sack %d\n",
			(int)tse->mss_clamp,
			ti.tcpi_options & TCPI_OPT_WSCALE ? (int)tse->snd_wscale : -1,
			ti.tcpi_options & TCPI_OPT_TIMESTAMPS ? 1 : 0,
			ti.tcpi_options & TCPI_OPT_SACK ? 1 : 0);

	return 0;

err_sopt:
	pr_perror("\tsockopt failed");
	return -1;
}

static int dump_tcp_conn_state(struct inet_sk_desc *sk)
{
	int ret, img_fd;
	TcpStreamEntry tse = TCP_STREAM_ENTRY__INIT;
	char *in_buf, *out_buf;

	/*
	 * Read queue
	 */

	pr_info("Reading inq for socket\n");
	tse.inq_len = sk->rqlen;
	ret = tcp_stream_get_queue(sk->rfd, TCP_RECV_QUEUE,
			&tse.inq_seq, tse.inq_len, &in_buf);
	if (ret < 0)
		goto err_in;

	/*
	 * Write queue
	 */

	pr_info("Reading outq for socket\n");
	tse.outq_len = sk->wqlen;
	ret = tcp_stream_get_queue(sk->rfd, TCP_SEND_QUEUE,
			&tse.outq_seq, tse.outq_len, &out_buf);
	if (ret < 0)
		goto err_out;

	/*
	 * Initial options
	 */

	pr_info("Reasing options for socket\n");
	ret = tcp_stream_get_options(sk->rfd, &tse);
	if (ret < 0)
		goto err_opt;

	/*
	 * Push the stuff to image
	 */

	img_fd = open_image(CR_FD_TCP_STREAM, O_DUMP, sk->sd.ino);
	if (img_fd < 0)
		goto err_img;

	ret = pb_write(img_fd, &tse, tcp_stream_entry);
	if (ret < 0)
		goto err_iw;

	if (in_buf) {
		ret = write_img_buf(img_fd, in_buf, tse.inq_len);
		if (ret < 0)
			goto err_iw;
	}

	if (out_buf) {
		ret = write_img_buf(img_fd, out_buf, tse.outq_len);
		if (ret < 0)
			goto err_iw;
	}

	pr_info("Done\n");
err_iw:
	close(img_fd);
err_img:
err_opt:
	xfree(out_buf);
err_out:
	xfree(in_buf);
err_in:
	return ret;
}

int dump_one_tcp(int fd, struct inet_sk_desc *sk)
{
	pr_info("Dumping TCP connection\n");

	if (tcp_repair_establised(fd, sk))
		return -1;

	if (dump_tcp_conn_state(sk))
		return -1;

	/*
	 * Socket is left in repair mode, so that at the end it's just
	 * closed and the connection is silently terminated
	 */
	return 0;
}

static int set_tcp_queue_seq(int sk, int queue, u32 seq)
{
	pr_debug("\tSetting %d queue seq to %u\n", queue, seq);

	if (setsockopt(sk, SOL_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue)) < 0) {
		pr_perror("Can't set repair queue");
		return -1;
	}

	if (setsockopt(sk, SOL_TCP, TCP_QUEUE_SEQ, &seq, sizeof(seq)) < 0) {
		pr_perror("Can't set queue seq");
		return -1;
	}

	return 0;
}

static int restore_tcp_seqs(int sk, TcpStreamEntry *tse)
{
	if (set_tcp_queue_seq(sk, TCP_RECV_QUEUE,
				tse->inq_seq - tse->inq_len))
		return -1;
	if (set_tcp_queue_seq(sk, TCP_SEND_QUEUE,
				tse->outq_seq - tse->outq_len))
		return -1;

	return 0;
}

static int send_tcp_queue(int sk, int queue, u32 len, int imgfd)
{
	int ret;
	char *buf;

	pr_debug("\tRestoring TCP %d queue data %u bytes\n", queue, len);

	if (setsockopt(sk, SOL_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue)) < 0) {
		pr_perror("Can't set repair queue");
		return -1;
	}

	buf = xmalloc(len);
	if (!buf)
		return -1;

	if (read_img_buf(imgfd, buf, len) < 0)
		return -1;

	ret = send(sk, buf, len, 0);

	xfree(buf);

	if (ret != len) {
		pr_perror("Can't restore %d queue data (%d), want %d",
				queue, ret, len);
		return -1;
	}

	return 0;
}

static int restore_tcp_queues(int sk, TcpStreamEntry *tse, int fd)
{
	if (tse->inq_len &&
			send_tcp_queue(sk, TCP_RECV_QUEUE, tse->inq_len, fd))
		return -1;
	if (tse->outq_len &&
			send_tcp_queue(sk, TCP_SEND_QUEUE, tse->outq_len, fd))
		return -1;

	return 0;
}

static int restore_tcp_opts(int sk, TcpStreamEntry *tse)
{
	struct tcp_repair_opt opts[4];
	int onr = 0;

	pr_debug("\tRestoring TCP options\n");

	if (tse->opt_mask & TCPI_OPT_SACK) {
		pr_debug("\t\tWill turn SAK on\n");
		opts[onr].opt_code = TCPOPT_SACK_PERM;
		opts[onr].opt_val = 0;
		onr++;
	}

	if (tse->opt_mask & TCPI_OPT_WSCALE) {
		pr_debug("\t\tWill set wscale to %u\n", tse->snd_wscale);
		opts[onr].opt_code = TCPOPT_WINDOW;
		opts[onr].opt_val = tse->snd_wscale;
		onr++;
	}

	if (tse->opt_mask & TCPI_OPT_TIMESTAMPS) {
		pr_debug("\t\tWill turn timestamps on\n");
		opts[onr].opt_code = TCPOPT_TIMESTAMP;
		opts[onr].opt_val = 0;
		onr++;
	}

	pr_debug("Will set mss clamp to %u\n", tse->mss_clamp);
	opts[onr].opt_code = TCPOPT_MAXSEG;
	opts[onr].opt_val = tse->mss_clamp;
	onr++;

	if (setsockopt(sk, SOL_TCP, TCP_REPAIR_OPTIONS,
				opts, onr * sizeof(struct tcp_repair_opt)) < 0) {
		pr_perror("Can't repair options");
		return -1;
	}

	return 0;
}

static int restore_tcp_conn_state(int sk, struct inet_sk_info *ii)
{
	int ifd;
	TcpStreamEntry *tse;

	pr_info("Restoring TCP connection id %x ino %x\n", ii->ie->id, ii->ie->ino);

	ifd = open_image_ro(CR_FD_TCP_STREAM, ii->ie->id);
	if (ifd < 0)
		goto err;

	if (pb_read(ifd, &tse, tcp_stream_entry) < 0)
		goto err_c;

	if (restore_tcp_seqs(sk, tse))
		goto err_c;

	if (inet_bind(sk, ii))
		goto err_c;

	if (inet_connect(sk, ii))
		goto err_c;

	if (restore_tcp_opts(sk, tse))
		goto err_c;

	if (restore_tcp_queues(sk, tse, ifd))
		goto err_c;

	tcp_stream_entry__free_unpacked(tse, NULL);
	close(ifd);
	return 0;

err_c:
	tcp_stream_entry__free_unpacked(tse, NULL);
	close(ifd);
err:
	return -1;
}

int restore_one_tcp(int fd, struct inet_sk_info *ii)
{
	pr_info("Restoring TCP connection\n");

	if (tcp_repair_on(fd))
		return -1;

	if (restore_tcp_conn_state(fd, ii))
		return -1;

	tcp_repair_off(fd);
	return 0;
}

void tcp_locked_conn_add(struct inet_sk_info *ii)
{
	list_add_tail(&ii->rlist, &tcp_repair_sockets);
}

void tcp_unlock_connections(void)
{
	struct inet_sk_info *ii;

	list_for_each_entry(ii, &tcp_repair_sockets, rlist)
		nf_unlock_connection_info(ii);
}

void show_tcp_stream(int fd, struct cr_options *opt)
{
	TcpStreamEntry *tse;
	pr_img_head(CR_FD_TCP_STREAM);

	if (pb_read_eof(fd, &tse, tcp_stream_entry) > 0) {
		pr_msg("IN:   seq %10u len %10u\n", tse->inq_seq, tse->inq_len);
		pr_msg("OUT:  seq %10u len %10u\n", tse->outq_seq, tse->outq_len);
		pr_msg("OPTS: %#x\n", (int)tse->opt_mask);
		pr_msg("\tmss_clamp %u\n", (int)tse->mss_clamp);
		if (tse->opt_mask & TCPI_OPT_WSCALE)
			pr_msg("\twscale %u\n", (int)tse->snd_wscale);
		if (tse->opt_mask & TCPI_OPT_TIMESTAMPS)
			pr_msg("\ttimestamps\n");
		if (tse->opt_mask & TCPI_OPT_SACK)
			pr_msg("\tsack\n");

		if (opt->show_pages_content) {
			unsigned char *buf;

			buf = xmalloc(max(tse->inq_len, tse->outq_len));
			if (!buf)
				goto out;

			if (tse->inq_len && read_img_buf(fd,
						buf, tse->inq_len) > 0) {
				pr_msg("IN queue:\n");
				print_data(0, buf, tse->inq_len);
			}

			if (tse->outq_len && read_img_buf(fd,
						buf, tse->outq_len) > 0) {
				pr_msg("OUT queue:\n");
				print_data(0, buf, tse->outq_len);
			}

			xfree(buf);
		}

		tcp_stream_entry__free_unpacked(tse, NULL);
		tse = NULL;
	}

out:
	if (tse)
		tcp_stream_entry__free_unpacked(tse, NULL);
	pr_img_tail(CR_FD_TCP_STREAM);
}

int check_tcp_repair(void)
{
	int sk, ret;

	sk = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sk < 0) {
		pr_perror("Can't create TCP socket :(\n");
		return -1;
	}

	ret = tcp_repair_on(sk);
	close(sk);

	return ret;
}
