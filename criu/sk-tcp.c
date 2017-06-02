#include <netinet/tcp.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <sched.h>
#include <netinet/in.h>

#include "../soccr/soccr.h"

#include "cr_options.h"
#include "util.h"
#include "common/list.h"
#include "log.h"
#include "files.h"
#include "sockets.h"
#include "sk-inet.h"
#include "netfilter.h"
#include "image.h"
#include "namespaces.h"
#include "xmalloc.h"
#include "config.h"
#include "kerndat.h"
#include "restorer.h"
#include "rst-malloc.h"

#include "protobuf.h"
#include "images/tcp-stream.pb-c.h"


static LIST_HEAD(cpt_tcp_repair_sockets);
static LIST_HEAD(rst_tcp_repair_sockets);

static int tcp_repair_establised(int fd, struct inet_sk_desc *sk)
{
	int ret;
	struct libsoccr_sk *socr;

	pr_info("\tTurning repair on for socket %x\n", sk->sd.ino);
	/*
	 * Keep the socket open in criu till the very end. In
	 * case we close this fd after one task fd dumping and
	 * fail we'll have to turn repair mode off
	 */
	sk->rfd = dup(fd);
	if (sk->rfd < 0) {
		pr_perror("Can't save socket fd for repair");
		goto err1;
	}

	if (!(root_ns_mask & CLONE_NEWNET)) {
		ret = nf_lock_connection(sk);
		if (ret < 0)
			goto err2;
	}

	socr = libsoccr_pause(sk->rfd);
	if (!socr)
		goto err3;

	sk->priv = socr;
	list_add_tail(&sk->rlist, &cpt_tcp_repair_sockets);
	return 0;

err3:
	if (!(root_ns_mask & CLONE_NEWNET))
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

	if (!(root_ns_mask & CLONE_NEWNET)) {
		ret = nf_unlock_connection(sk);
		if (ret < 0)
			pr_perror("Failed to unlock TCP connection");
	}

	libsoccr_resume(sk->priv);
	sk->priv = NULL;

	/*
	 * tcp_repair_off modifies SO_REUSEADDR so
	 * don't forget to restore original value.
	 */
	restore_opt(sk->rfd, SOL_SOCKET, SO_REUSEADDR, &sk->cpt_reuseaddr);

	close(sk->rfd);
}

void cpt_unlock_tcp_connections(void)
{
	struct inet_sk_desc *sk, *n;

	list_for_each_entry_safe(sk, n, &cpt_tcp_repair_sockets, rlist)
		tcp_unlock_one(sk);
}

static int dump_tcp_conn_state(struct inet_sk_desc *sk)
{
	struct libsoccr_sk *socr = sk->priv;
	int ret, aux;
	struct cr_img *img;
	TcpStreamEntry tse = TCP_STREAM_ENTRY__INIT;
	char *buf;
	struct libsoccr_sk_data data;

	ret = libsoccr_save(socr, &data, sizeof(data));
	if (ret < 0)
		goto err_r;
	if (ret != sizeof(data)) {
		pr_err("This libsocr is not supported (%d vs %d)\n",
				ret, (int)sizeof(data));
		goto err_r;
	}

	sk->state = data.state;

	tse.inq_len = data.inq_len;
	tse.inq_seq = data.inq_seq;
	tse.outq_len = data.outq_len;
	tse.outq_seq = data.outq_seq;
	tse.unsq_len = data.unsq_len;
	tse.has_unsq_len = true;
	tse.mss_clamp = data.mss_clamp;
	tse.opt_mask = data.opt_mask;

	if (tse.opt_mask & TCPI_OPT_WSCALE) {
		tse.snd_wscale = data.snd_wscale;
		tse.rcv_wscale = data.rcv_wscale;
		tse.has_rcv_wscale = true;
	}
	if (tse.opt_mask & TCPI_OPT_TIMESTAMPS) {
		tse.timestamp = data.timestamp;
		tse.has_timestamp = true;
	}

	if (data.flags & SOCCR_FLAGS_WINDOW) {
		tse.has_snd_wl1		= true;
		tse.has_snd_wnd		= true;
		tse.has_max_window	= true;
		tse.has_rcv_wnd		= true;
		tse.has_rcv_wup		= true;
		tse.snd_wl1		= data.snd_wl1;
		tse.snd_wnd		= data.snd_wnd;
		tse.max_window		= data.max_window;
		tse.rcv_wnd		= data.rcv_wnd;
		tse.rcv_wup		= data.rcv_wup;
	}

	/*
	 * TCP socket options
	 */

	if (dump_opt(sk->rfd, SOL_TCP, TCP_NODELAY, &aux))
		goto err_opt;

	if (aux) {
		tse.has_nodelay = true;
		tse.nodelay = true;
	}

	if (dump_opt(sk->rfd, SOL_TCP, TCP_CORK, &aux))
		goto err_opt;

	if (aux) {
		tse.has_cork = true;
		tse.cork = true;
	}

	/*
	 * Push the stuff to image
	 */

	img = open_image(CR_FD_TCP_STREAM, O_DUMP, sk->sd.ino);
	if (!img)
		goto err_img;

	ret = pb_write_one(img, &tse, PB_TCP_STREAM);
	if (ret < 0)
		goto err_iw;

	buf = libsoccr_get_queue_bytes(socr, TCP_RECV_QUEUE, SOCCR_MEM_EXCL);
	if (buf) {
		ret = write_img_buf(img, buf, tse.inq_len);
		if (ret < 0)
			goto err_iw;

		xfree(buf);
	}

	buf = libsoccr_get_queue_bytes(socr, TCP_SEND_QUEUE, SOCCR_MEM_EXCL);
	if (buf) {
		ret = write_img_buf(img, buf, tse.outq_len);
		if (ret < 0)
			goto err_iw;

		xfree(buf);
	}

	pr_info("Done\n");
err_iw:
	close_image(img);
err_img:
err_opt:
err_r:
	return ret;
}

int dump_one_tcp(int fd, struct inet_sk_desc *sk)
{
	if (sk->dst_port == 0)
		return 0;

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

static int read_tcp_queue(struct libsoccr_sk *sk, struct libsoccr_sk_data *data,
		int queue, u32 len, struct cr_img *img)
{
	char *buf;

	buf = xmalloc(len);
	if (!buf)
		return -1;

	if (read_img_buf(img, buf, len) < 0)
		goto err;

	return libsoccr_set_queue_bytes(sk, queue, buf, SOCCR_MEM_EXCL);

err:
	xfree(buf);
	return -1;
}

static int read_tcp_queues(struct libsoccr_sk *sk, struct libsoccr_sk_data *data, struct cr_img *img)
{
	u32 len;

	len = data->inq_len;
	if (len && read_tcp_queue(sk, data, TCP_RECV_QUEUE, len, img))
		return -1;

	len = data->outq_len;
	if (len && read_tcp_queue(sk, data, TCP_SEND_QUEUE, len, img))
		return -1;

	return 0;
}

static int restore_tcp_conn_state(int sk, struct libsoccr_sk *socr, struct inet_sk_info *ii)
{
	int aux;
	struct cr_img *img;
	TcpStreamEntry *tse;
	struct libsoccr_sk_data data = {};
	union libsoccr_addr sa_src, sa_dst;

	pr_info("Restoring TCP connection id %x ino %x\n", ii->ie->id, ii->ie->ino);

	img = open_image(CR_FD_TCP_STREAM, O_RSTR, ii->ie->ino);
	if (!img)
		goto err;

	if (pb_read_one(img, &tse, PB_TCP_STREAM) < 0)
		goto err_c;

	if (!tse->has_unsq_len) {
		pr_err("No unsq len in the image\n");
		goto err_c;
	}

	data.state = ii->ie->state;;
	data.inq_len = tse->inq_len;
	data.inq_seq = tse->inq_seq;
	data.outq_len = tse->outq_len;
	data.outq_seq = tse->outq_seq;
	data.unsq_len = tse->unsq_len;
	data.mss_clamp = tse->mss_clamp;
	data.opt_mask = tse->opt_mask;
	if (tse->opt_mask & TCPI_OPT_WSCALE) {
		if (!tse->has_rcv_wscale) {
			pr_err("No rcv wscale in the image\n");
			goto err_c;
		}

		data.snd_wscale = tse->snd_wscale;
		data.rcv_wscale = tse->rcv_wscale;
	}
	if (tse->opt_mask & TCPI_OPT_TIMESTAMPS) {
		if (!tse->has_timestamp) {
			pr_err("No timestamp in the image\n");
			goto err_c;
		}

		data.timestamp = tse->timestamp;
	}

	if (tse->has_snd_wnd) {
		data.flags |= SOCCR_FLAGS_WINDOW;
		data.snd_wl1 = tse->snd_wl1;
		data.snd_wnd = tse->snd_wnd;
		data.max_window = tse->max_window;
		data.rcv_wnd = tse->rcv_wnd;
		data.rcv_wup = tse->rcv_wup;
	}

	if (restore_sockaddr(&sa_src,
				ii->ie->family, ii->ie->src_port,
				ii->ie->src_addr, 0) < 0)
		goto err_c;
	if (restore_sockaddr(&sa_dst,
				ii->ie->family, ii->ie->dst_port,
				ii->ie->dst_addr, 0) < 0)
		goto err_c;

	libsoccr_set_addr(socr, 1, &sa_src, 0);
	libsoccr_set_addr(socr, 0, &sa_dst, 0);

	/*
	 * O_NONBLOCK has to be set before libsoccr_restore(),
	 * it is required to restore syn-sent sockets.
	 */
	if (restore_prepare_socket(sk))
		goto err_c;

	if (read_tcp_queues(socr, &data, img))
		goto err_c;

	if (libsoccr_restore(socr, &data, sizeof(data)))
		goto err_c;

	if (tse->has_nodelay && tse->nodelay) {
		aux = 1;
		if (restore_opt(sk, SOL_TCP, TCP_NODELAY, &aux))
			goto err_c;
	}

	if (tse->has_cork && tse->cork) {
		aux = 1;
		if (restore_opt(sk, SOL_TCP, TCP_CORK, &aux))
			goto err_c;
	}

	tcp_stream_entry__free_unpacked(tse, NULL);
	close_image(img);
	return 0;

err_c:
	tcp_stream_entry__free_unpacked(tse, NULL);
	close_image(img);
err:
	return -1;
}

int prepare_tcp_socks(struct task_restore_args *ta)
{
	struct inet_sk_info *ii;

	ta->tcp_socks = (struct rst_tcp_sock *) rst_mem_align_cpos(RM_PRIVATE);
	ta->tcp_socks_n = 0;

	list_for_each_entry(ii, &rst_tcp_repair_sockets, rlist) {
		struct rst_tcp_sock *rs;

		/*
		 * rst_tcp_repair_sockets contains all sockets, so we need to
		 * select sockets which restored in a current porcess.
		 */
		if (ii->sk_fd == -1)
			continue;

		rs = rst_mem_alloc(sizeof(*rs), RM_PRIVATE);
		if (!rs)
			return -1;

		rs->sk = ii->sk_fd;
		rs->reuseaddr = ii->ie->opts->reuseaddr;
		ta->tcp_socks_n++;
	}

	return 0;
}

int restore_one_tcp(int fd, struct inet_sk_info *ii)
{
	struct libsoccr_sk *sk;

	pr_info("Restoring TCP connection\n");

	if (opts.tcp_close &&
		ii->ie->state != TCP_LISTEN && ii->ie->state != TCP_CLOSE) {
		return 0;
	}

	sk = libsoccr_pause(fd);
	if (!sk)
		return -1;

	if (restore_tcp_conn_state(fd, sk, ii))
		return -1;

	return 0;
}

void tcp_locked_conn_add(struct inet_sk_info *ii)
{
	list_add_tail(&ii->rlist, &rst_tcp_repair_sockets);
	ii->sk_fd = -1;
}

void rst_unlock_tcp_connections(void)
{
	struct inet_sk_info *ii;

	/* Network will be unlocked by network-unlock scripts */
	if (root_ns_mask & CLONE_NEWNET)
		return;

	list_for_each_entry(ii, &rst_tcp_repair_sockets, rlist)
		nf_unlock_connection_info(ii);
}
