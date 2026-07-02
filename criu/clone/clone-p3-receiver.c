/*
 * CLONE P3 Parallel Receiver - target-side parallel page reception.
 *
 * Handles parallel page reception for CLONE migration:
 * - Creates connections to the source
 * - Spawns receiver threads for each connection
 * - Receives compressed batches and adds to page buffer
 */

#include <sys/socket.h>
#include <sys/mman.h>
#include <pthread.h>
#include <poll.h>
#include <unistd.h>
#include <errno.h>
#include <lz4.h>

#include "types.h"
#include "page.h"
#include "criu-log.h"
#include "page-xfer.h"
#include "clone/clone-page-xfer.h"
#include "clone/clone-conf.h"
#include "clone/clone-bulk-send.h"
#include "cr_options.h"
#include "tls.h"
#include "clone/tls-conn.h"
#include "clone/page-pool.h"
#include "clone/clone-uffd.h"
#include "util.h"
#include "common/bug.h"

#undef LOG_PREFIX
#define LOG_PREFIX "clone-p3-recv: "

/* Max batch size for P3 transfer (CLONE_BATCH_PAGES in clone-conf.h) */
#define P3_DECOMPRESS_BUF_SIZE (CLONE_BATCH_PAGES * PAGE_SIZE)
#define P3_COMPRESS_BUF_SIZE LZ4_compressBound(P3_DECOMPRESS_BUF_SIZE)

struct p3_receiver_ctx {
	pthread_t thread;
	int thread_id;
	int socket;
	struct tls_conn *tls;
	unsigned long pages_received;
	volatile bool active;
	/* Pre-allocated buffers to avoid malloc/mprotect contention */
	char *compressed_buf;
	char *decompressed_buf;
};

static struct p3_receiver_ctx p3_receivers[CLONE_MAX_P3_THREADS];
static volatile int p3_receivers_active = 0;

/*
 * Receive one compressed batch from socket and add to page buffer.
 * Uses pre-allocated buffers from ctx to avoid malloc contention.
 * Returns number of pages received, 0 on EOF, -1 on error.
 */
static int p3_receive_and_buffer(struct p3_receiver_ctx *ctx)
{
	struct page_server_iov pi;
	int compressed_size;
	char *compressed_buf = ctx->compressed_buf;
	int sk = ctx->socket;
	int nr_pages, i, ret = -1;
	int decomp_ret;

	/* Receive header */
	if (ctx->tls)
		ret = tls_conn_recv_all(ctx->tls, &pi, sizeof(pi), 0);
	else
		ret = page_server_recv_raw(sk, &pi, sizeof(pi), MSG_WAITALL);
	if (ret == 0)
		return 0;  /* EOF */
	if (ret != sizeof(pi)) {
		pr_perror("P3 receive: failed to read header");
		return -1;
	}

	nr_pages = pi.nr_pages;
	if (nr_pages <= 0 || nr_pages > CLONE_BATCH_PAGES) {
		pr_err("P3 receive: invalid nr_pages %d\n", nr_pages);
		return -1;
	}

	/* Receive compressed size */
	if (ctx->tls)
		ret = tls_conn_recv_all(ctx->tls, &compressed_size, sizeof(compressed_size), 0);
	else
		ret = page_server_recv_raw(sk, &compressed_size, sizeof(compressed_size), MSG_WAITALL);
	if (ret != sizeof(compressed_size)) {
		pr_perror("P3 receive: failed to read compressed size");
		return -1;
	}

	if (compressed_size <= 0 || compressed_size > P3_COMPRESS_BUF_SIZE) {
		pr_err("P3 receive: invalid compressed size %d\n", compressed_size);
		return -1;
	}

	/* Receive compressed data (using pre-allocated buffer) */
	if (ctx->tls)
		ret = tls_conn_recv_all(ctx->tls, compressed_buf, compressed_size, 0);
	else
		ret = page_server_recv_raw(sk, compressed_buf, compressed_size, MSG_WAITALL);
	if (ret != compressed_size) {
		pr_perror("P3 receive: failed to read compressed data");
		return -1;
	}

	{
		unsigned long base = pi.vaddr & CLONE_BATCH_ALIGN_MASK;
		int page_offset = ((pi.vaddr - base) >> PAGE_SHIFT);

		if (page_offset == 0 && nr_pages == CLONE_BATCH_PAGES) {
			/*
			 * Path A: Full aligned batch (bulk transfer common case).
			 * Pool alloc → decompress → add_batch(owns_data=true).
			 */
			char *pool_buf = page_pool_get_pages(ctx->thread_id, CLONE_BATCH_PAGES);
			BUG_ON(!pool_buf);

			decomp_ret = LZ4_decompress_safe(compressed_buf, pool_buf,
							 compressed_size, nr_pages * PAGE_SIZE);
			BUG_ON(decomp_ret != nr_pages * (int)PAGE_SIZE);

			if (clone_page_buffer_add_batch(base, pool_buf, nr_pages,
						      0, ctx->thread_id, true) < 0) {
				for (i = 0; i < CLONE_BATCH_PAGES; i++)
					page_pool_put(pool_buf + i * PAGE_SIZE);
				return -1;
			}
		} else if (page_offset + nr_pages <= CLONE_BATCH_PAGES) {
			/*
			 * Path B: Partial batch within one 256KB region.
			 * If entry exists (dirty overwrite): decompress directly
			 * into entry->data. Zero allocation, zero memcpy.
			 * If new entry: decompress into temp buf, add_batch allocates.
			 */
			void *existing = clone_page_buffer_get_data_ptr(base,
								      page_offset, nr_pages);
			if (existing) {
				decomp_ret = LZ4_decompress_safe(compressed_buf,
								 (char *)existing + page_offset * PAGE_SIZE,
								 compressed_size, nr_pages * PAGE_SIZE);
				BUG_ON(decomp_ret != nr_pages * (int)PAGE_SIZE);

				clone_page_buffer_mark_pages(base, page_offset, nr_pages);
			} else {
				decomp_ret = LZ4_decompress_safe(compressed_buf,
								 ctx->decompressed_buf + page_offset * PAGE_SIZE,
								 compressed_size, nr_pages * PAGE_SIZE);
				BUG_ON(decomp_ret != nr_pages * (int)PAGE_SIZE);

				if (clone_page_buffer_add_batch(base, ctx->decompressed_buf,
							      nr_pages, page_offset,
							      ctx->thread_id, false) < 0)
					return -1;
			}
		} else {
			/*
			 * Path C: Batch crosses 256KB boundary.
			 * Decompress into temp buffer, split into two add_batch calls.
			 */
			int first_nr = CLONE_BATCH_PAGES - page_offset;
			int second_nr = nr_pages - first_nr;

			pr_debug("P3 receive: batch crosses boundary vaddr=0x%lx base=0x%lx "
			       "offset=%d nr=%d first=%d second=%d thread=%d\n",
			       (unsigned long)pi.vaddr, base, page_offset, nr_pages,
			       first_nr, second_nr, ctx->thread_id);

			/* Decompress into start of temp buffer (fits, nr_pages <= 64) */
			decomp_ret = LZ4_decompress_safe(compressed_buf,
							 ctx->decompressed_buf,
							 compressed_size, nr_pages * PAGE_SIZE);
			BUG_ON(decomp_ret != nr_pages * (int)PAGE_SIZE);

			/*
			 * First part: pages [page_offset..63] in base.
			 * Decompressed data [0..first_nr) goes to entry at page_offset.
			 * Try direct overwrite first, fall back to add_batch.
			 */
			{
				void *existing1 = clone_page_buffer_get_data_ptr(base,
									       page_offset, first_nr);
				if (existing1) {
					memcpy((char *)existing1 + page_offset * PAGE_SIZE,
					       ctx->decompressed_buf, first_nr * PAGE_SIZE);
					clone_page_buffer_mark_pages(base, page_offset, first_nr);
				} else {
					/*
					 * New entry — need pool alloc. Copy first_nr pages
					 * at the right offset in a temp pool buf.
					 */
					char *pool_buf = page_pool_get_pages(ctx->thread_id, CLONE_BATCH_PAGES);
					BUG_ON(!pool_buf);
					memcpy(pool_buf + page_offset * PAGE_SIZE,
					       ctx->decompressed_buf, first_nr * PAGE_SIZE);
					if (clone_page_buffer_add_batch(base, pool_buf,
								      first_nr, page_offset,
								      ctx->thread_id, true) < 0) {
						for (i = 0; i < CLONE_BATCH_PAGES; i++)
							page_pool_put(pool_buf + i * PAGE_SIZE);
						return -1;
					}
				}
			}

			/*
			 * Second part: pages [0..second_nr) in next 256KB region.
			 * Decompressed data [first_nr..nr_pages) goes to offset 0.
			 */
			{
				void *existing2 = clone_page_buffer_get_data_ptr(
							base + CLONE_BATCH_SIZE, 0, second_nr);
				if (existing2) {
					memcpy(existing2,
					       ctx->decompressed_buf + first_nr * PAGE_SIZE,
					       second_nr * PAGE_SIZE);
					clone_page_buffer_mark_pages(base + CLONE_BATCH_SIZE,
								   0, second_nr);
				} else {
					char *pool_buf = page_pool_get_pages(ctx->thread_id, CLONE_BATCH_PAGES);
					BUG_ON(!pool_buf);
					memcpy(pool_buf,
					       ctx->decompressed_buf + first_nr * PAGE_SIZE,
					       second_nr * PAGE_SIZE);
					if (clone_page_buffer_add_batch(base + CLONE_BATCH_SIZE,
								      pool_buf, second_nr, 0,
								      ctx->thread_id, true) < 0) {
						for (i = 0; i < CLONE_BATCH_PAGES; i++)
							page_pool_put(pool_buf + i * PAGE_SIZE);
						return -1;
					}
				}
			}
		}
	}

	return nr_pages;
}

static void *p3_receiver_thread_func(void *arg)
{
	struct p3_receiver_ctx *ctx = (struct p3_receiver_ctx *)arg;
	unsigned long pages = 0;
	int ret = 0;
	char thread_name[16];

	snprintf(thread_name, sizeof(thread_name), "clone-p3rcv-%d", ctx->thread_id);
	pthread_setname_np(pthread_self(), thread_name);

	pr_info("P3 receiver[%d] started on socket %d\n", ctx->thread_id, ctx->socket);

	/* Initialize per-thread page pool for lock-free allocation */
	BUG_ON(clone_page_buffer_thread_init(ctx->thread_id) < 0);

	/* Per-connection TLS handshake (client side - target connects to source) */
	if (opts.tls) {
		pr_debug("P3 receiver[%d] starting TLS handshake on fd=%d\n",
		       ctx->thread_id, ctx->socket);
		ctx->tls = tls_conn_new(ctx->socket, false);
		if (!ctx->tls) {
			pr_err("P3 receiver[%d] TLS handshake FAILED\n", ctx->thread_id);
			BUG();
		}
		pr_debug("P3 receiver[%d] TLS handshake OK\n", ctx->thread_id);
	}

	/* Receive pages until socket closes */
	while ((ret = p3_receive_and_buffer(ctx)) > 0)
		pages += ret;

	BUG_ON(ret < 0);

	ctx->pages_received = pages;
	ctx->active = false;
	__sync_fetch_and_sub(&p3_receivers_active, 1);
	pr_info("P3 receiver[%d] done: %lu pages\n", ctx->thread_id, pages);
	return NULL;
}

/*
 * Accept P3 connections for parallel transfer (source/server side).
 * Returns sockets to caller for use with clone_start_p3_threads().
 * Does NOT spawn threads - caller is responsible for using the sockets.
 *
 * Returns number of connections accepted, fills sockets array.
 */
int accept_p3_connections(int *sockets, int max_connections, int timeout_ms)
{
	int listen_sk = get_listen_socket();
	int num_accepted = 0;
	struct sockaddr_storage caddr;
	socklen_t clen;
	int elapsed_ms = 0;

	BUG_ON(listen_sk < 0);

	pr_info("Waiting for up to %d P3 connections (timeout=%dms)\n",
		max_connections, timeout_ms);

	while (num_accepted < max_connections && elapsed_ms < timeout_ms) {
		int sk;
		struct pollfd pfd = { .fd = listen_sk, .events = POLLIN };
		int poll_timeout = 100;  /* 100ms poll intervals */

		if (poll(&pfd, 1, poll_timeout) <= 0) {
			elapsed_ms += poll_timeout;
			continue;
		}

		clen = sizeof(caddr);
		sk = accept(listen_sk, (struct sockaddr *)&caddr, &clen);
		if (sk < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				continue;
			pr_perror("accept_p3_connections: accept failed");
			BUG();
		}

		sockets[num_accepted] = sk;
		num_accepted++;
		pr_info("Accepted P3 connection %d (fd=%d)\n", num_accepted, sk);

		/* Reset timeout after each successful accept */
		elapsed_ms = 0;
	}

	pr_info("Accepted %d/%d P3 connections\n", num_accepted, max_connections);
	return num_accepted;
}

/*
 * Create multiple connections to page server for parallel P3 transfer.
 * Returns number of connections created, fills sockets array.
 */
static int connect_p3_sockets(int *sockets, int num_requested)
{
	int i, num_created = 0;

	if (!opts.use_page_server || !opts.addr)
		return 0;

	for (i = 0; i < num_requested; i++) {
		int sk = setup_tcp_client(opts.addr);
		BUG_ON(sk < 0);

		sockets[i] = sk;
		num_created++;
	}

	pr_info("Created %d P3 sockets for parallel transfer\n", num_created);
	return num_created;
}

/*
 * Close P3 sockets after transfer completes.
 */
void close_p3_sockets(int *sockets, int num_sockets)
{
	int i;
	for (i = 0; i < num_sockets; i++) {
		if (sockets[i] >= 0) {
			close(sockets[i]);
			sockets[i] = -1;
		}
	}
}

/*
 * Target side: Create P3 connections to the source and start receiver
 * threads. Called during lazy-pages startup to enable parallel page
 * reception. Returns number of receiver threads started, 0 if page server
 * not configured.
 */
int start_p3_receiver_connections(int num_connections)
{
	int p3_sockets[CLONE_MAX_P3_THREADS];
	int num_sockets, i;

	if (num_connections > CLONE_MAX_P3_THREADS)
		num_connections = CLONE_MAX_P3_THREADS;

	/* Create connections to the source */
	num_sockets = connect_p3_sockets(p3_sockets, num_connections);
	if (num_sockets == 0)
		return 0;

	/* Initialize per-connection TLS credentials before spawning threads */
	if (opts.tls) {
		pr_debug("P3 receiver: calling tls_global_init()\n");
		BUG_ON(tls_global_init());
		pr_debug("P3 receiver: tls_global_init() OK\n");
	}

	/* Start receiver thread for each connection */
	for (i = 0; i < num_sockets; i++) {
		p3_receivers[i].thread_id = i;
		p3_receivers[i].socket = p3_sockets[i];
		p3_receivers[i].tls = NULL;
		p3_receivers[i].pages_received = 0;
		p3_receivers[i].active = true;

		/* Pre-allocate buffers to avoid malloc/mprotect contention */
		p3_receivers[i].compressed_buf = mmap(NULL, P3_COMPRESS_BUF_SIZE,
						      PROT_READ | PROT_WRITE,
						      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		p3_receivers[i].decompressed_buf = mmap(NULL, P3_DECOMPRESS_BUF_SIZE,
							PROT_READ | PROT_WRITE,
							MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		BUG_ON(p3_receivers[i].compressed_buf == MAP_FAILED);
		BUG_ON(p3_receivers[i].decompressed_buf == MAP_FAILED);

		__sync_fetch_and_add(&p3_receivers_active, 1);

		BUG_ON(pthread_create(&p3_receivers[i].thread, NULL,
				      p3_receiver_thread_func, &p3_receivers[i]));
	}

	pr_info("Started %d P3 receiver threads\n", p3_receivers_active);
	return p3_receivers_active;
}

/*
 * Target side: Stop P3 receiver threads and close connections.
 * Called when page transfer is complete.
 */
void stop_p3_receiver_connections(void)
{
	int i;
	unsigned long total_pages = 0;

	for (i = 0; i < CLONE_MAX_P3_THREADS; i++) {
		if (p3_receivers[i].thread) {
			pthread_join(p3_receivers[i].thread, NULL);
			total_pages += p3_receivers[i].pages_received;
			if (p3_receivers[i].tls) {
				tls_conn_free(p3_receivers[i].tls);
				p3_receivers[i].tls = NULL;
			}
			if (p3_receivers[i].socket >= 0) {
				close(p3_receivers[i].socket);
				p3_receivers[i].socket = -1;
			}
			/* Free pre-allocated buffers */
			if (p3_receivers[i].compressed_buf) {
				munmap(p3_receivers[i].compressed_buf, P3_COMPRESS_BUF_SIZE);
				p3_receivers[i].compressed_buf = NULL;
			}
			if (p3_receivers[i].decompressed_buf) {
				munmap(p3_receivers[i].decompressed_buf, P3_DECOMPRESS_BUF_SIZE);
				p3_receivers[i].decompressed_buf = NULL;
			}
			p3_receivers[i].thread = 0;
		}
	}

	p3_receivers_active = 0;
	pr_info("P3 receivers stopped: %lu total pages\n", total_pages);
}
