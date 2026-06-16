/*
 * Per-connection TLS implementation for CRIU CLONE migration.
 *
 * Provides thread-safe TLS sessions: one shared credential context
 * (certificates loaded once) with independent per-socket sessions.
 */

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <gnutls/gnutls.h>

#include "cr_options.h"
#include "xmalloc.h"
#include "criu-log.h"
#include "clone/tls-conn.h"

#undef LOG_PREFIX
#define LOG_PREFIX "tls-conn: "

#define CRIU_PKI_DIR	SYSCONFDIR "/pki"
#define CRIU_CACERT	CRIU_PKI_DIR "/CA/cacert.pem"
#define CRIU_CACRL	CRIU_PKI_DIR "/CA/cacrl.pem"
#define CRIU_CERT	CRIU_PKI_DIR "/criu/cert.pem"
#define CRIU_KEY	CRIU_PKI_DIR "/criu/private/key.pem"

#define tls_perror(msg, ret) pr_err("%s: %s\n", msg, gnutls_strerror(ret))

struct tls_conn {
	gnutls_session_t session;
	int socket_fd;
	int io_flags;
};

/* Shared global credential context */
static struct {
	gnutls_certificate_credentials_t x509_cred;
	bool initialized;
	pthread_mutex_t lock;
} g_tls_ctx = {
	.initialized = false,
	.lock = PTHREAD_MUTEX_INITIALIZER,
};

static int _load_credentials(void)
{
	int ret;
	char *cacert = CRIU_CACERT;
	char *cacrl = CRIU_CACRL;
	char *cert = CRIU_CERT;
	char *key = CRIU_KEY;
	gnutls_x509_crt_fmt_t pem = GNUTLS_X509_FMT_PEM;

	if (opts.tls_cacert)
		cacert = opts.tls_cacert;
	if (opts.tls_cacrl)
		cacrl = opts.tls_cacrl;
	if (opts.tls_cert)
		cert = opts.tls_cert;
	if (opts.tls_key)
		key = opts.tls_key;

	ret = gnutls_certificate_allocate_credentials(&g_tls_ctx.x509_cred);
	if (ret != GNUTLS_E_SUCCESS) {
		tls_perror("Failed to allocate credentials", ret);
		return -1;
	}

	/* Load system trust if no explicit CA cert provided */
	if (!opts.tls_cacert) {
		ret = gnutls_certificate_set_x509_system_trust(g_tls_ctx.x509_cred);
		if (ret < 0) {
			tls_perror("Failed to load system trust", ret);
			return -1;
		}
	}

	ret = gnutls_certificate_set_x509_trust_file(g_tls_ctx.x509_cred,
						     cacert, pem);
	if (ret == 0) {
		pr_info("No trusted CAs from %s\n", cacert);
		if (opts.tls_cacert)
			return -1;
	}

	/* Load CRL if available */
	if (opts.tls_cacrl) {
		ret = gnutls_certificate_set_x509_crl_file(g_tls_ctx.x509_cred,
							   cacrl, pem);
		if (ret < 0) {
			tls_perror("Failed to load CRL", ret);
			return -1;
		}
	}

	/* Load our certificate and key */
	ret = gnutls_certificate_set_x509_key_file(g_tls_ctx.x509_cred,
						   cert, key, pem);
	if (ret != GNUTLS_E_SUCCESS) {
		tls_perror("Failed to load cert/key", ret);
		return -1;
	}

	return 0;
}

int tls_global_init(void)
{
	int ret = 0;

	pthread_mutex_lock(&g_tls_ctx.lock);
	if (g_tls_ctx.initialized)
		goto out;

	gnutls_global_init();

	if (_load_credentials()) {
		gnutls_global_deinit();
		ret = -1;
		goto out;
	}

	g_tls_ctx.initialized = true;
	pr_info("Global TLS context initialized\n");
out:
	pthread_mutex_unlock(&g_tls_ctx.lock);
	return ret;
}

void tls_global_deinit(void)
{
	pthread_mutex_lock(&g_tls_ctx.lock);
	if (g_tls_ctx.initialized) {
		gnutls_certificate_free_credentials(g_tls_ctx.x509_cred);
		gnutls_global_deinit();
		g_tls_ctx.initialized = false;
	}
	pthread_mutex_unlock(&g_tls_ctx.lock);
}

static ssize_t _push_cb(gnutls_transport_ptr_t ptr,
			 const void *data, size_t sz)
{
	struct tls_conn *conn = (struct tls_conn *)ptr;
	ssize_t ret = send(conn->socket_fd, data, sz, conn->io_flags);

	if (ret < 0 && errno != EAGAIN) {
		int saved = errno;
		pr_perror("TLS push send failed");
		errno = saved;
	}
	return ret;
}

static ssize_t _pull_cb(gnutls_transport_ptr_t ptr,
			 void *data, size_t sz)
{
	struct tls_conn *conn = (struct tls_conn *)ptr;
	ssize_t ret = recv(conn->socket_fd, data, sz, conn->io_flags);

	if (ret < 0 && errno != EAGAIN) {
		int saved = errno;
		pr_perror("TLS pull recv failed");
		errno = saved;
	}
	return ret;
}

static int _verify_peer(struct tls_conn *conn)
{
	int ret;
	unsigned status;
	const char *hostname = NULL;

	if (!opts.tls_no_cn_verify)
		hostname = opts.addr;

	ret = gnutls_certificate_verify_peers3(conn->session, hostname,
					       &status);
	if (ret != GNUTLS_E_SUCCESS) {
		tls_perror("Unable to verify peer", ret);
		return -1;
	}

	if (status != 0) {
		gnutls_datum_t out;
		int type = gnutls_certificate_type_get(conn->session);

		if (!gnutls_certificate_verification_status_print(status,
								  type, &out, 0)) {
			pr_err("Certificate error: %s\n", out.data);
			gnutls_free(out.data);
		}
		return -1;
	}

	return 0;
}

struct tls_conn *tls_conn_new(int sockfd, bool is_server)
{
	struct tls_conn *conn;
	unsigned int flags;
	int ret;

	if (!g_tls_ctx.initialized) {
		if (tls_global_init())
			return NULL;
	}

	conn = xzalloc(sizeof(*conn));
	if (!conn)
		return NULL;

	conn->socket_fd = sockfd;
	conn->io_flags = 0;

	flags = is_server ? GNUTLS_SERVER : GNUTLS_CLIENT;
	ret = gnutls_init(&conn->session, flags);
	if (ret != GNUTLS_E_SUCCESS) {
		tls_perror("Failed to init session", ret);
		goto err_free;
	}

	ret = gnutls_credentials_set(conn->session, GNUTLS_CRD_CERTIFICATE,
				     g_tls_ctx.x509_cred);
	if (ret != GNUTLS_E_SUCCESS) {
		tls_perror("Failed to set credentials", ret);
		goto err_session;
	}

	ret = gnutls_set_default_priority(conn->session);
	if (ret != GNUTLS_E_SUCCESS) {
		tls_perror("Failed to set priority", ret);
		goto err_session;
	}

	/* Transport callbacks use conn as the opaque pointer */
	gnutls_transport_set_ptr(conn->session, conn);
	gnutls_transport_set_push_function(conn->session, _push_cb);
	gnutls_transport_set_pull_function(conn->session, _pull_cb);

	if (is_server) {
		gnutls_certificate_server_set_request(conn->session,
						      GNUTLS_CERT_REQUIRE);
		gnutls_certificate_send_x509_rdn_sequence(conn->session, 1);
	}

	/* Perform handshake */
	do {
		ret = gnutls_handshake(conn->session);
	} while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);

	if (ret != GNUTLS_E_SUCCESS) {
		tls_perror("Handshake failed", ret);
		goto err_session;
	}

	pr_info("TLS handshake OK (fd=%d, %s)\n", sockfd,
		is_server ? "server" : "client");

	/* Verify peer certificate */
	if (_verify_peer(conn))
		goto err_session;

	return conn;

err_session:
	gnutls_deinit(conn->session);
err_free:
	xfree(conn);
	return NULL;
}

void tls_conn_free(struct tls_conn *conn)
{
	if (!conn)
		return;

	gnutls_bye(conn->session, GNUTLS_SHUT_WR);
	gnutls_deinit(conn->session);
	xfree(conn);
}

ssize_t tls_conn_send(struct tls_conn *conn, const void *buf,
		      size_t len, int flags)
{
	ssize_t ret;

	conn->io_flags = flags;
	ret = gnutls_record_send(conn->session, buf, len);
	conn->io_flags = 0;

	if (ret < 0) {
		switch (ret) {
		case GNUTLS_E_AGAIN:
			errno = EAGAIN;
			break;
		case GNUTLS_E_INTERRUPTED:
			errno = EINTR;
			break;
		default:
			tls_perror("Send failed", ret);
			errno = EIO;
			break;
		}
		return -1;
	}

	return ret;
}

ssize_t tls_conn_recv(struct tls_conn *conn, void *buf,
		      size_t len, int flags)
{
	ssize_t ret;

	conn->io_flags = flags;
	ret = gnutls_record_recv(conn->session, buf, len);
	conn->io_flags = 0;

	/* Check pending data for non-blocking reads */
	if (flags == MSG_DONTWAIT &&
	    (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED)) {
		size_t pending = gnutls_record_check_pending(conn->session);

		if (pending > 0)
			ret = gnutls_record_recv(conn->session, buf, len);
	}

	if (ret < 0) {
		switch (ret) {
		case GNUTLS_E_AGAIN:
			errno = EAGAIN;
			break;
		case GNUTLS_E_INTERRUPTED:
			errno = EINTR;
			break;
		default:
			tls_perror("Recv failed", ret);
			errno = EIO;
			break;
		}
		return -1;
	}

	return ret;
}

ssize_t tls_conn_send_all(struct tls_conn *conn, const void *buf,
			  size_t len, int flags)
{
	const char *cursor = buf;
	size_t remaining = len;

	while (remaining > 0) {
		ssize_t ret = tls_conn_send(conn, cursor, remaining, flags);

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (ret == 0)
			return len - remaining;

		cursor += ret;
		remaining -= ret;
	}
	return len;
}

ssize_t tls_conn_recv_all(struct tls_conn *conn, void *buf,
			  size_t len, int flags)
{
	char *cursor = buf;
	size_t remaining = len;

	while (remaining > 0) {
		ssize_t ret = tls_conn_recv(conn, cursor, remaining, flags);

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (ret == 0)
			return len - remaining;

		cursor += ret;
		remaining -= ret;
	}
	return len;
}

int tls_conn_get_fd(struct tls_conn *conn)
{
	if (!conn)
		return -1;
	return conn->socket_fd;
}
