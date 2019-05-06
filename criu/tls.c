#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/limits.h>

#include <gnutls/gnutls.h>

#include "cr_options.h"
#include "xmalloc.h"

/* Compatability with GnuTLS verson <3.5 */
#ifndef GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR
# define GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR GNUTLS_E_CERTIFICATE_ERROR
#endif

#undef	LOG_PREFIX
#define LOG_PREFIX "tls: "

#define CRIU_PKI_DIR SYSCONFDIR "/pki"
#define CRIU_CACERT CRIU_PKI_DIR "/CA/cacert.pem"
#define CRIU_CACRL CRIU_PKI_DIR "/CA/cacrl.pem"
#define CRIU_CERT CRIU_PKI_DIR "/criu/cert.pem"
#define CRIU_KEY CRIU_PKI_DIR "/criu/private/key.pem"

#define SPLICE_BUF_SZ_MAX (PIPE_BUF * 100)

#define tls_perror(msg, ret) pr_err("%s: %s\n", msg, gnutls_strerror(ret))

static gnutls_session_t session;
static gnutls_certificate_credentials_t x509_cred;
static int tls_sk = -1;
static int tls_sk_flags = 0;

void tls_terminate_session()
{
	int ret;

	if (!opts.tls)
		return;

	if (session) {
		do {
			/* don't wait for peer to close connection */
			ret = gnutls_bye(session, GNUTLS_SHUT_WR);
		} while(ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);
		gnutls_deinit(session);
	}

	tls_sk = -1;
	if (x509_cred)
		gnutls_certificate_free_credentials(x509_cred);
}

ssize_t tls_send(const void *buf, size_t len, int flags)
{
	int ret;

	tls_sk_flags = flags;
	ret = gnutls_record_send(session, buf, len);
	tls_sk_flags = 0;

	if (ret < 0) {
		switch(ret) {
		case GNUTLS_E_AGAIN:
			errno = EAGAIN;
			break;
		case GNUTLS_E_INTERRUPTED:
			errno = EINTR;
			break;
		case GNUTLS_E_UNEXPECTED_PACKET_LENGTH:
			errno = ENOMSG;
			break;
		default:
			tls_perror("Failed to send data", ret);
			errno = EIO;
			break;
		}
	}

	return ret;
}

/*
 * Read data from a file descriptor, then encrypt and send it with GnuTLS.
 * This function is used for cases when we would otherwise use splice()
 * to transfer data from PIPE to TCP socket.
 */
int tls_send_data_from_fd(int fd, unsigned long len)
{
	ssize_t copied;
	unsigned long buf_size = min(len, (unsigned long)SPLICE_BUF_SZ_MAX);
	void *buf = xmalloc(buf_size);

	if (!buf)
		return -1;

	while (len > 0) {
		int ret, sent;

		copied = read(fd, buf, min(len, buf_size));
		if (copied <= 0) {
			pr_perror("Can't read from pipe");
			goto err;
		}

		for(sent = 0; sent < copied; sent += ret) {
			ret = tls_send((buf + sent), (copied - sent), 0);
			if (ret < 0) {
				tls_perror("Failed sending data", ret);
				goto err;
			}
		}
		len -= copied;
	}
err:
	xfree(buf);
	return (len > 0);
}

ssize_t tls_recv(void *buf, size_t len, int flags)
{
	int ret;

	tls_sk_flags = flags;
	ret = gnutls_record_recv(session, buf, len);
	tls_sk_flags = 0;

	/* Check if there are any data to receive in the gnutls buffers. */
	if (flags == MSG_DONTWAIT
	    && (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED)) {
		size_t pending = gnutls_record_check_pending(session);
		if (pending > 0) {
			pr_debug("Receiving pending data (%zu bytes)\n", pending);
			ret = gnutls_record_recv(session, buf, len);
		}
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
			tls_perror("Failed receiving data", ret);
			errno = EIO;
			break;
		}
		ret = -1;
	}

	return ret;
}

/*
 * Read and decrypt data with GnuTLS, then write it to a file descriptor.
 * This function is used for cases when we would otherwise use splice()
 * to transfer data from a TCP socket to a PIPE.
 */
int tls_recv_data_to_fd(int fd, unsigned long len)
{
	gnutls_packet_t packet;

	while (len > 0) {
		int ret, w;
		gnutls_datum_t pdata;

		ret = gnutls_record_recv_packet(session, &packet);
		if (ret == 0) {
			pr_info("Connection closed by peer\n");
			break;
		} else if (ret < 0) {
			tls_perror("Received corrupted data", ret);
			break;
		}

		gnutls_packet_get(packet, &pdata, NULL);
		for(w = 0; w < pdata.size; w += ret) {
			ret = write(fd, (pdata.data + w), (pdata.size - w));
			if (ret < 0) {
				pr_perror("Failed writing to fd");
				goto err;
			}
		}
		len -= pdata.size;
	}
err:
	gnutls_packet_deinit(packet);
	return (len > 0);
}

static inline void tls_handshake_verification_status_print(int ret, unsigned status)
{
	gnutls_datum_t out;
	int type = gnutls_certificate_type_get(session);

	if (!gnutls_certificate_verification_status_print(status, type, &out, 0))
		pr_err("%s\n", out.data);

	gnutls_free(out.data);
}

static int tls_x509_verify_peer_cert(void)
{
	int ret;
	unsigned status;
	const char *hostname = NULL;

	if (!opts.tls_no_cn_verify)
		hostname = opts.addr;

	ret = gnutls_certificate_verify_peers3(session, hostname, &status);
	if (ret != GNUTLS_E_SUCCESS) {
		tls_perror("Unable to verify TLS peer", ret);
		return -1;
	}

	if (status != 0) {
		pr_err("Invalid certificate\n");
		tls_handshake_verification_status_print(
			GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR, status);
		return -1;
	}

	return 0;
}

static int tls_handshake()
{
	int ret = -1;
	while (ret != GNUTLS_E_SUCCESS) {
		ret = gnutls_handshake(session);
		if (gnutls_error_is_fatal(ret)) {
			tls_perror("TLS handshake failed", ret);
			return -1;
		}
	}
	pr_info("TLS handshake completed\n");
	return 0;
}

static int tls_x509_setup_creds()
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

	ret = gnutls_certificate_allocate_credentials(&x509_cred);
	if (ret != GNUTLS_E_SUCCESS) {
		tls_perror("Failed to allocate x509 credentials", ret);
		return -1;
	}

	if (!opts.tls_cacert) {
		ret = gnutls_certificate_set_x509_system_trust(x509_cred);
		if (ret < 0) {
			tls_perror("Failed to load default trusted CAs", ret);
			return -1;
		}
	}

	ret = gnutls_certificate_set_x509_trust_file(x509_cred, cacert, pem);
	if (ret == 0) {
		pr_info("No trusted CA certificates added (%s)\n", cacert);
		if (opts.tls_cacert)
			return -1;
	}

	if (!access(cacrl, R_OK)) {
		ret = gnutls_certificate_set_x509_crl_file(x509_cred, cacrl, pem);
		if (ret < 0) {
			tls_perror("Can't set certificate revocation list", ret);
			return -1;
		}
	} else if (opts.tls_cacrl) {
		pr_perror("Can't read certificate revocation list %s", cacrl);
		return -1;
	}

	ret = gnutls_certificate_set_x509_key_file(x509_cred, cert, key, pem);
	if (ret != GNUTLS_E_SUCCESS) {
		tls_perror("Failed to set certificate/private key pair", ret);
		return -1;
	}

	return 0;
}

static ssize_t _tls_push_cb(void *p, const void* data, size_t sz)
{
	int fd = *(int *)(p);
	return send(fd, data, sz, tls_sk_flags);
}

static ssize_t _tls_pull_cb(void *p, void* data, size_t sz)
{
	int fd = *(int *)(p);
	return recv(fd, data, sz, tls_sk_flags);
}

static int tls_x509_setup_session(unsigned int flags)
{
	int ret;

	ret = gnutls_init(&session, flags);
	if (ret != GNUTLS_E_SUCCESS) {
		tls_perror("Failed to initialize session", ret);
		return -1;
	}

	ret = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred);
	if (ret != GNUTLS_E_SUCCESS) {
		tls_perror("Failed to set session credentials", ret);
		return -1;
	}

	ret = gnutls_set_default_priority(session);
	if (ret != GNUTLS_E_SUCCESS) {
		tls_perror("Failed to set priority", ret);
		return -1;
	}

	gnutls_transport_set_ptr(session, &tls_sk);
	gnutls_transport_set_push_function(session, _tls_push_cb);
	gnutls_transport_set_pull_function(session, _tls_pull_cb);

	if (flags == GNUTLS_SERVER) {
		/* Require client certificate */
		gnutls_certificate_server_set_request(session, GNUTLS_CERT_REQUIRE);
		/* Do not advertise trusted CAs to the client */
		gnutls_certificate_send_x509_rdn_sequence(session, 1);
	}

	return 0;
}

int tls_x509_init(int sockfd, bool is_server)
{
	if (!opts.tls)
		return 0;

	tls_sk = sockfd;
	if (tls_x509_setup_creds())
		goto err;
	if (tls_x509_setup_session(is_server ? GNUTLS_SERVER : GNUTLS_CLIENT))
		goto err;
	if (tls_handshake())
		goto err;
	if (tls_x509_verify_peer_cert())
		goto err;

	return 0;
err:
	tls_terminate_session();
	return -1;
}
