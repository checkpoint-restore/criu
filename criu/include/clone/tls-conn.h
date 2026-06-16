#ifndef __CR_TLS_CONN_H__
#define __CR_TLS_CONN_H__

#include <stdbool.h>
#include <sys/types.h>

#ifdef CONFIG_GNUTLS

struct tls_conn;

/*
 * Initialize global TLS credential context (load certificates).
 * Thread-safe; only performs initialization on first call.
 * Returns 0 on success, -1 on failure.
 */
int tls_global_init(void);

/*
 * Shut down global TLS context and free credentials.
 * Call once at process exit.
 */
void tls_global_deinit(void);

/*
 * Create a new TLS connection on an existing connected socket.
 * Performs the TLS handshake and verifies peer certificate.
 * Each returned tls_conn is independent and thread-safe for use
 * by a single thread (no internal locking needed).
 *
 * Returns NULL on failure (handshake or verification error).
 */
struct tls_conn *tls_conn_new(int sockfd, bool is_server);

/*
 * Close TLS session gracefully and free resources.
 * Does NOT close the underlying socket fd.
 */
void tls_conn_free(struct tls_conn *conn);

/*
 * Send data over TLS. Semantics match send():
 * returns bytes sent, or -1 with errno set.
 */
ssize_t tls_conn_send(struct tls_conn *conn, const void *buf,
		      size_t len, int flags);

/*
 * Receive data over TLS. Semantics match recv():
 * returns bytes received, 0 on EOF, or -1 with errno set.
 */
ssize_t tls_conn_recv(struct tls_conn *conn, void *buf,
		      size_t len, int flags);

/*
 * Blocking send-all: retries short writes and EINTR until all
 * bytes are delivered. Returns len on success, -1 on error.
 */
ssize_t tls_conn_send_all(struct tls_conn *conn, const void *buf,
			  size_t len, int flags);

/*
 * Blocking recv-all: retries until exactly len bytes received.
 * Returns len on success, 0 on EOF, -1 on error.
 */
ssize_t tls_conn_recv_all(struct tls_conn *conn, void *buf,
			  size_t len, int flags);

/*
 * Get the underlying socket fd from a TLS connection.
 */
int tls_conn_get_fd(struct tls_conn *conn);

#else /* !CONFIG_GNUTLS */

struct tls_conn;

#define tls_global_init()			(0)
#define tls_global_deinit()
#define tls_conn_new(sockfd, is_server)		(NULL)
#define tls_conn_free(conn)
#define tls_conn_send(conn, buf, len, flags)	(-1)
#define tls_conn_recv(conn, buf, len, flags)	(-1)
#define tls_conn_send_all(conn, buf, len, flags)(-1)
#define tls_conn_recv_all(conn, buf, len, flags)(-1)
#define tls_conn_get_fd(conn)			(-1)

#endif /* CONFIG_GNUTLS */

#endif /* __CR_TLS_CONN_H__ */
