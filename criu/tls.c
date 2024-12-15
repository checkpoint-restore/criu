#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <linux/limits.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/crypto.h>
#include <gnutls/abstract.h>

#include "page.h"
#include "imgset.h"
#include "images/cipher.pb-c.h"
#include "protobuf.h"
#include "cr_options.h"
#include "xmalloc.h"
#include "tls.h"

/* Compatibility with GnuTLS version < 3.5 */
#ifndef GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR
#define GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR GNUTLS_E_CERTIFICATE_ERROR
#endif

#undef LOG_PREFIX
#define LOG_PREFIX "tls: "

#define CRIU_PKI_DIR SYSCONFDIR "/pki"
#define CRIU_CACERT  CRIU_PKI_DIR "/CA/cacert.pem"
#define CRIU_CACRL   CRIU_PKI_DIR "/CA/cacrl.pem"
#define CRIU_CERT    CRIU_PKI_DIR "/criu/cert.pem"
#define CRIU_KEY     CRIU_PKI_DIR "/criu/private/key.pem"

#define SPLICE_BUF_SZ_MAX (PIPE_BUF * 100)

#define tls_perror(msg, ret) pr_err("%s: %s\n", msg, gnutls_strerror(ret))

#define cleanup_gnutls_datum __attribute__((cleanup(_cleanup_gnutls_datum)))
static inline void _cleanup_gnutls_datum(gnutls_datum_t *p)
{
	if (p->data != NULL) {
		gnutls_free(p->data);
	}
}

static gnutls_session_t session;
static gnutls_certificate_credentials_t x509_cred;
static gnutls_pubkey_t pubkey;
static int tls_sk = -1;
static int tls_sk_flags = 0;

/* 256-bits key for ChaCha20-Poly1305 */
static uint8_t token[32];
static const gnutls_cipher_algorithm_t stream_cipher_algorithm = GNUTLS_CIPHER_CHACHA20_POLY1305;

void tls_terminate_session(bool async)
{
	int ret;

	if (!opts.tls)
		return;

	if (session) {
		do {
			/*
			 * Initiate a connection shutdown but don't
			 * wait for peer to close connection.
			 */
			ret = gnutls_bye(session, async ? GNUTLS_SHUT_WR : GNUTLS_SHUT_RDWR);
		} while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);
		/* Free the session object */
		gnutls_deinit(session);
	}

	tls_sk = -1;

	/* Free the credentials object */
	if (x509_cred)
		gnutls_certificate_free_credentials(x509_cred);
}

ssize_t tls_send(const void *buf, size_t len, int flags)
{
	ssize_t ret;

	tls_sk_flags = flags;
	ret = gnutls_record_send(session, buf, len);
	tls_sk_flags = 0;

	if (ret < 0) {
		switch (ret) {
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
	char *buf = xmalloc(buf_size);
	if (!buf)
		return -1;

	while (len > 0) {
		ssize_t ret, sent;

		copied = read(fd, buf, min(len, buf_size));
		if (copied <= 0) {
			pr_perror("Can't read from pipe");
			goto err;
		}

		for (sent = 0; sent < copied; sent += ret) {
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
	ssize_t ret;

	tls_sk_flags = flags;
	ret = gnutls_record_recv(session, buf, len);
	tls_sk_flags = 0;

	/* Check if there are any data to receive in the gnutls buffers. */
	if (flags == MSG_DONTWAIT && (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED)) {
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
		ssize_t ret, w;
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
		for (w = 0; w < pdata.size; w += ret) {
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
		tls_handshake_verification_status_print(GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR, status);
		return -1;
	}

	return 0;
}

static int tls_handshake(void)
{
	int ret = -1;
	while (ret != GNUTLS_E_SUCCESS) {
		/* Establish TLS session */
		ret = gnutls_handshake(session);
		if (gnutls_error_is_fatal(ret)) {
			tls_perror("TLS handshake failed", ret);
			return -1;
		}
	}
	pr_info("TLS handshake completed\n");
	return 0;
}

static int tls_x509_setup_creds(void)
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

	/* Load the trusted CA certificates */
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

/**
 * A function used by gnutls to send data. It returns a positive
 * number indicating the bytes sent, and -1 on error.
 */
static ssize_t _tls_push_cb(void *p, const void *data, size_t sz)
{
	int fd = *(int *)(p);
	ssize_t ret = send(fd, data, sz, tls_sk_flags);
	if (ret < 0 && errno != EAGAIN) {
		int _errno = errno;
		pr_perror("Push callback send failed");
		errno = _errno;
	}
	return ret;
}

/**
 * A callback function used by gnutls to receive data.
 * It returns 0 on connection termination, a positive number
 * indicating the number of bytes received, and -1 on error.
 */
static ssize_t _tls_pull_cb(void *p, void *data, size_t sz)
{
	int fd = *(int *)(p);
	ssize_t ret = recv(fd, data, sz, tls_sk_flags);
	if (ret < 0 && errno != EAGAIN) {
		int _errno = errno;
		pr_perror("Pull callback recv failed");
		errno = _errno;
	}
	return ret;
}

static int tls_x509_setup_session(unsigned int flags)
{
	int ret;

	/* Create the session object */
	ret = gnutls_init(&session, flags);
	if (ret != GNUTLS_E_SUCCESS) {
		tls_perror("Failed to initialize session", ret);
		return -1;
	}

	/* Install the trusted certificates */
	ret = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred);
	if (ret != GNUTLS_E_SUCCESS) {
		tls_perror("Failed to set session credentials", ret);
		return -1;
	}

	/* Configure the cipher preferences */
	ret = gnutls_set_default_priority(session);
	if (ret != GNUTLS_E_SUCCESS) {
		tls_perror("Failed to set priority", ret);
		return -1;
	}

	/* Associate the socket with the session object */
	gnutls_transport_set_ptr(session, &tls_sk);

	/* Set a push function for gnutls to use to send data */
	gnutls_transport_set_push_function(session, _tls_push_cb);
	/* set a pull function for gnutls to use to receive data */
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
	tls_terminate_session(true);
	return -1;
}

static inline int _tls_generate_token(void)
{
	return gnutls_rnd(GNUTLS_RND_KEY, &token, sizeof(token));
}

/**
 * tls_initialize_cipher initializes GnuTLS, loads a public key,
 * and initializes a cipher context that is used to encrypt the
 * content of images during dump and pre-dump.
 */
int tls_initialize_cipher(void)
{
	int ret;
	char *cert_file_path = CRIU_CERT;
	gnutls_x509_crt_t crt;
	cleanup_gnutls_datum gnutls_datum_t cert_data = { NULL, 0 };

	if (!opts.encrypt)
		return 0;

	if (opts.tls_cert)
		cert_file_path = opts.tls_cert;

	pr_debug("Loading public key from %s\n", cert_file_path);
	ret = gnutls_load_file(cert_file_path, &cert_data);
	if (ret < 0) {
		tls_perror("Failed to load certificate file", ret);
		return -1;
	}

	ret = gnutls_pubkey_init(&pubkey);
	if (ret < 0) {
		tls_perror("Failed to initialize public key", ret);
		return -1;
	}

	ret = gnutls_x509_crt_init(&crt);
	if (ret < 0) {
		tls_perror("Failed to initialize X.509 certificate structure", ret);
		return -1;
	}

	ret = gnutls_x509_crt_import(crt, &cert_data, GNUTLS_X509_FMT_PEM);
	if (ret < 0) {
		tls_perror("Failed to import certificate", ret);
		return -1;
	}

	ret = gnutls_pubkey_import_x509(pubkey, crt, 0);
	if (ret < 0) {
		tls_perror("Failed to load public key", ret);
		return -1;
	}

	ret = _tls_generate_token();
	if (ret < 0) {
		tls_perror("Failed to generate token", ret);
		return -1;
	}

	gnutls_x509_crt_deinit(crt);

	return 0;
}

static int read_fp(FILE *fp, void *buf, const size_t buf_len)
{
	size_t len_read;

	len_read = fread(buf, 1, buf_len, fp);
	if (len_read != buf_len) {
		pr_perror("Unable to read file (read:%ld buf_len:%ld)", len_read, buf_len);
		return -EIO;
	}
	return 0;
}

static int read_file(const char *file_path, void *buf, const size_t buf_len)
{
	int ret;
	FILE *fp;

	fp = fopen(file_path, "r");
	if (!fp) {
		pr_perror("Cannot fopen %s", file_path);
		return -errno;
	}

	ret = read_fp(fp, buf, buf_len);
	fclose(fp); /* this will also close fd */
	return ret;
}

/**
 * rsa_load_pem_key loads a private key from a file in PEM format.
 * It returns a pointer to the key on success or NULL on error. The
 * caller is responsible for freeing the key. This function is based
 * on code from wireshark:
 * https://github.com/wireshark/wireshark/blob/24c8d79d/wsutil/rsa.c#L89
 */
static gnutls_x509_privkey_t rsa_load_pem_key(const char *privkey_file_path)
{
	gnutls_x509_privkey_t x509_key;
	gnutls_datum_t key;
	struct stat statbuf;
	int ret;

	if (stat(privkey_file_path, &statbuf) < 0) {
		pr_perror("Can't stat %s", privkey_file_path);
		return NULL;
	}

	if (S_ISDIR(statbuf.st_mode)) {
		pr_err("%s is a directory\n", privkey_file_path);
		return NULL;
	}

	if (S_ISFIFO(statbuf.st_mode)) {
		pr_err("%s is a FIFO\n", privkey_file_path);
		return NULL;
	}

	if (!S_ISREG(statbuf.st_mode)) {
		pr_err("%s is not a regular file\n", privkey_file_path);
		return NULL;
	}

	key.data = gnutls_malloc((size_t)statbuf.st_size);
	if (!key.data) {
		pr_perror("Can't allocate %lu bytes for %s", statbuf.st_size, privkey_file_path);
		return NULL;
	}
	key.size = (int)statbuf.st_size;

	ret = read_file(privkey_file_path, key.data, key.size);
	if (ret < 0) {
		goto err;
	}

	ret = gnutls_x509_privkey_init(&x509_key);
	if (ret != GNUTLS_E_SUCCESS) {
		tls_perror("Failed to initialize X.509 private key", ret);
		goto err;
	}

	ret = gnutls_x509_privkey_import(x509_key, &key, GNUTLS_X509_FMT_PEM);
	if (ret != GNUTLS_E_SUCCESS) {
		tls_perror("Failed to load X.509 private key", ret);
		goto err;
	}

	if (gnutls_x509_privkey_get_pk_algorithm(x509_key) != GNUTLS_PK_RSA) {
		pr_err("Private key is not RSA\n");
		goto err;
	}

	gnutls_free(key.data);
	return x509_key;

err:
	gnutls_free(key.data);
	return NULL;
}

/**
 * tls_initialize_cipher_from_image loads a private key and
 * decrypts the token from the cipher.img that is then used
 * to decrypt all other images.
 */
int tls_initialize_cipher_from_image(void)
{
	int ret;
	char *privkey_file_path = CRIU_KEY;
	struct cr_img *img;
	CipherEntry *ce;

	gnutls_privkey_t privkey;
	gnutls_x509_privkey_t x509_key;
	gnutls_datum_t ciphertext;
	gnutls_datum_t decrypted_token;

	img = open_image(CR_FD_CIPHER, O_RSTR);
	if (!img)
		return -1;

	/* If cipher.img is empty, then encryption is not used */
	if (empty_image(img)) {
		close_image(img);
		opts.encrypt = false;
		return 0;
	}
	opts.encrypt = true;

	if (opts.tls_key)
		privkey_file_path = opts.tls_key;

	pr_debug("Loading private key from %s\n", privkey_file_path);
	x509_key = rsa_load_pem_key(privkey_file_path);
	if (!x509_key)
		return -1;

	ret = gnutls_privkey_init(&privkey);
	if (ret < 0) {
		tls_perror("Failed to initialize private key", ret);
		return -1;
	}

	ret = gnutls_privkey_import_x509(privkey, x509_key, 0);
	if (ret < 0) {
		tls_perror("Failed to import private key", ret);
		return -1;
	}

	ret = pb_read_one(img, &ce, PB_CIPHER);
	if (ret < 0) {
		pr_err("Failed to read cipher entry\n");
		goto out_close;
	}

	ciphertext.data = ce->token.data;
	ciphertext.size = ce->token.len;

	ret = gnutls_privkey_decrypt_data(privkey, 0, &ciphertext, &decrypted_token);
	if (ret < 0) {
		tls_perror("Failed to decrypt token data", ret);
		goto out_close;
	}

	if (decrypted_token.size != sizeof(token)) {
		pr_err("Invalid token size (%d != %lu)\n", decrypted_token.size, sizeof(token));
		goto out_close;
	}

	if (memcpy(token, decrypted_token.data, sizeof(token)) != token) {
		pr_perror("Failed to copy token data");
		goto out_close;
	}

	ret = 0;
out_close:
	close_image(img);
	return ret;
}

/**
 * _encrypt_data_with_pubkey encrypts the given plaintext with the
 * given public key and returns the ciphertext. On success, it
 * returns zero or a negative error code on error.
 */
static int _encrypt_data_with_pubkey(gnutls_datum_t *plaintext, gnutls_datum_t *ciphertext)
{
	unsigned int max_block_size, key_len = 0;
	int ret;

	ret = gnutls_pubkey_get_pk_algorithm(pubkey, &key_len);
	if (ret < 0) {
		pr_err("Failed to read public key length\n");
		return -1;
	}
	if (ret != GNUTLS_PK_RSA) {
		pr_err("Public key must be RSA\n");
		return -1;
	}

	/* The data must be small enough to use plain RSA
	 * https://github.com/gnutls/nettle/blob/fe7ae87d/pkcs1-encrypt.c#L66
	 */
	max_block_size = key_len / 8 - 11;
	if (plaintext->size > max_block_size) {
		pr_err("Data size must be less than %u bytes\n", max_block_size);
		return -1;
	}

	ret = gnutls_pubkey_encrypt_data(pubkey, 0, plaintext, ciphertext);
	if (ret < 0) {
		tls_perror("Failed to encrypt data", ret);
		return -1;
	}

	return 0;
}

/**
 * write_img_cipher encrypts the token with RSA public key and writes
 * it to cipher.img.
 */
int write_img_cipher(void)
{
	int ret;
	struct cr_img *img;
	CipherEntry ce = CIPHER_ENTRY__INIT;
	gnutls_datum_t plaintext, ciphertext;

	if (!opts.encrypt) {
		return 0;
	}

	if (!pubkey) {
		pr_err("Public key is not initialized\n");
		return -1;
	}

	plaintext.data = token;
	plaintext.size = sizeof(token);
	ret = _encrypt_data_with_pubkey(&plaintext, &ciphertext);
	if (ret < 0) {
		return -1;
	}
	ce.token.len = ciphertext.size;
	ce.token.data = ciphertext.data;

	pr_debug("Writing cipher image\n");
	img = open_image(CR_FD_CIPHER, O_DUMP);
	if (!img)
		return -1;

	ret = pb_write_one(img, &ce, PB_CIPHER);
	if (ret < 0) {
		pr_err("Failed to write ciphertext size to image\n");
		goto err;
	}

err:
	gnutls_free(ciphertext.data);
	close_image(img);
	return ret;
}

/**
 * tls_encrypt_data performs in-place encryption of data with ChaCha20-Poly1305
 * AEAD cipher. A 16-bytes tag and 12-bytes nonce are generated and written to
 * tag_data and nonce_data. The caller must ensure that there is enough space
 * allocated for the tag and nonce. Different tag and nonce are used for each
 * invocation, and they must be provided to decrypt the data. The tag's purpose
 * is to verify the integrity of the data, while the nonce is used to prevent
 * replay attacks.
 */
int tls_encrypt_data(void *data, size_t data_size, uint8_t *tag_data, uint8_t *nonce_data)
{
	int ret;
	giovec_t iov[1];
	gnutls_datum_t key;
	static gnutls_aead_cipher_hd_t handle = NULL;
	size_t tag_size = gnutls_cipher_get_tag_size(stream_cipher_algorithm);
	size_t nonce_len = gnutls_cipher_get_iv_size(stream_cipher_algorithm);

	if (!opts.encrypt)
		return -1;

	if (handle == NULL) {
		key.data = token;
		key.size = gnutls_cipher_get_key_size(stream_cipher_algorithm);

		ret = gnutls_aead_cipher_init(&handle, stream_cipher_algorithm, &key);
		if (ret < 0) {
			tls_perror("Failed to initialize cipher", ret);
			return -1;
		}
	}

	/* A different 96-bit nonce must be used for each invocation.
	 * The nonce should never be reused with the same key.
	 * (RFC 8439, Section 2.8 "AEAD Construction")
	 */
	ret = gnutls_rnd(GNUTLS_RND_NONCE, nonce_data, nonce_len);
	if (ret < 0) {
		tls_perror("Failed to generate random nonce", ret);
		return -1;
	}

	iov[0].iov_base = data;
	iov[0].iov_len = data_size;

	ret = gnutls_aead_cipher_encryptv2(handle, nonce_data, nonce_len, NULL, 0, iov, 1, tag_data, &tag_size);
	if (ret < 0) {
		tls_perror("Failed to encrypt data", ret);
		return -1;
	}

	return 0;
}

/**
 * tls_decrypt_data performs in-place decryption of given data
 * with corresponding tag and nonce. On success, it returns zero
 * or a negative error code on error.
 */
int tls_decrypt_data(void *data, size_t data_size, uint8_t *tag_data, uint8_t *nonce_data)
{
	int ret;
	giovec_t iov[1];
	gnutls_datum_t key;
	gnutls_aead_cipher_hd_t handle = NULL;
	size_t tag_size = gnutls_cipher_get_tag_size(stream_cipher_algorithm);
	size_t nonce_len = gnutls_cipher_get_iv_size(stream_cipher_algorithm);

	key.data = token;
	key.size = gnutls_cipher_get_key_size(stream_cipher_algorithm);

	ret = gnutls_aead_cipher_init(&handle, stream_cipher_algorithm, &key);
	if (ret < 0) {
		tls_perror("Failed to initialize cipher", ret);
		return -1;
	}

	iov[0].iov_base = data;
	iov[0].iov_len = data_size;

	ret = gnutls_aead_cipher_decryptv2(handle, nonce_data, nonce_len, NULL, 0, iov, 1, tag_data, tag_size);
	if (ret < 0) {
		tls_perror("Failed to decrypt data", ret);
		return -1;
	}

	gnutls_aead_cipher_deinit(handle);

	return ret;
}

/**
 * tls_encrypt_pipe_data reads data from fd_in, encrypts the data, and writes
 * the encrypted data to fd_out. If data_size is zero, then the function
 * returns immediately without reading or writing any data.
 */
int tls_encrypt_pipe_data(int fd_in, int fd_out, size_t data_size)
{
	int exit_code = -1;
	ssize_t ret, bytes_read = 0;
	cleanup_free uint8_t *buf = NULL;
	chacha20_poly1305_t cipher_data;

	if (data_size == 0)
		return 0;

	buf = xmalloc(data_size);
	if (!buf)
		return -1;

	while (bytes_read < data_size) {
		ret = read(fd_in, buf + bytes_read, data_size - bytes_read);
		if (ret < 0) {
			pr_perror("Can't read file data");
			goto err;
		}
		if (ret == 0) {
			break;
		}
		bytes_read += ret;
	}

	/* Encrypt buffer data using ChaCha20-Poly1305 */
	if (tls_encrypt_data(buf, data_size, cipher_data.tag, cipher_data.nonce) < 0) {
		pr_err("Failed to encrypt buffer data\n");
		goto err;
	}

	/* Write ciphertext data */
	ret = write(fd_out, buf, data_size);
	if (ret != data_size) {
		if (ret < 0)
			pr_perror("Failed to write file data");
		else
			pr_err("Failed to write all data to image file (%zd != %zd)\n", ret, bytes_read);
		goto err;
	}

	/* Write tag data */
	if (write(fd_out, cipher_data.tag, sizeof(cipher_data.tag)) != sizeof(cipher_data.tag)) {
		pr_err("Failed to write tag data to image file\n");
		goto err;
	}

	/* Write nonce data */
	if (write(fd_out, cipher_data.nonce, sizeof(cipher_data.nonce)) != sizeof(cipher_data.nonce)) {
		pr_err("Failed to write nonce data to image file\n");
		goto err;
	}

	exit_code = 0;
err:
	return exit_code;
}

/**
 * tls_encrypt_file_data reads data from fd_in, encrypts the data, and writes
 * the encrypted data to fd_out. The function reads all data from fd_in until EOF.
 * If data_size is non-zero, then it checks that the total number of bytes read
 * is equal to data_size.
 */
int tls_encrypt_file_data(int fd_in, int fd_out, size_t data_size)
{
	int exit_code = -1;
	ssize_t ret, bytes_read = 0, total = 0;
	uint8_t buf[PAGE_SIZE];
	chacha20_poly1305_t cipher_data;

	while (1) {
		bytes_read = 0;
		while (bytes_read < sizeof(buf)) {
			ret = read(fd_in, buf + bytes_read, sizeof(buf) - bytes_read);
			if (ret < 0) {
				pr_perror("Can't read file data");
				goto err;
			}
			if (ret == 0)
				break; /* EOF */

			bytes_read += ret;
		}

		if (bytes_read == 0)
			break; /* EOF */

		/* Encrypt buffer data using ChaCha20-Poly1305 */
		if (tls_encrypt_data(buf, bytes_read, cipher_data.tag, cipher_data.nonce) < 0) {
			pr_err("Failed to encrypt buffer data\n");
			goto err;
		}

		/* Write tag data */
		if (write(fd_out, cipher_data.tag, sizeof(cipher_data.tag)) != sizeof(cipher_data.tag)) {
			pr_err("Failed to write tag data to image file\n");
			goto err;
		}

		/* Write nonce data */
		if (write(fd_out, cipher_data.nonce, sizeof(cipher_data.nonce)) != sizeof(cipher_data.nonce)) {
			pr_err("Failed to write nonce data to image file\n");
			goto err;
		}

		/* Write size of data */
		if (write(fd_out, &bytes_read, sizeof(bytes_read)) != sizeof(bytes_read)) {
			pr_err("Failed to write size of data to image file\n");
			goto err;
		}

		/* Write ciphertext data */
		ret = write(fd_out, buf, bytes_read);
		if (ret != bytes_read) {
			if (ret < 0)
				pr_perror("Failed to write file data");
			else
				pr_err("Failed to write all data to image file (%zd != %zd)\n", ret, bytes_read);
			goto err;
		}
		total += ret;
	}

	if (data_size && total != data_size) {
		pr_err("File size mismatch (%zd != %zd)\n", total, data_size);
		goto err;
	}

	exit_code = 0;
err:
	return exit_code;
}

/**
 * tls_decrypt_file_data reads encrypted data from fd_in, decrypts the data,
 * and writes the decrypted data to fd_out. The function reads all data from
 * fd_in until EOF and if data_size is non-zero, then it checks that the
 * total number of bytes read is equal to data_size.
 */
int tls_decrypt_file_data(int fd_in, int fd_out, size_t data_size)
{
	chacha20_poly1305_t cipher_data;
	ssize_t ret, bytes_read = 0, total = 0;
	int exit_code = -1;
	uint8_t buf[PAGE_SIZE];

	while (1) {
		/* Read tag data */
		ret = read(fd_in, cipher_data.tag, sizeof(cipher_data.tag));
		if (ret == 0)
			break; /* EOF */
		if (ret != sizeof(cipher_data.tag)) {
			pr_perror("Failed to read tag data (%lu != %lu)", ret, sizeof(cipher_data.tag));
			goto err;
		}

		/* Read nonce data */
		ret = read(fd_in, cipher_data.nonce, sizeof(cipher_data.nonce));
		if (ret != sizeof(cipher_data.nonce)) {
			pr_perror("Failed to read nonce data (%lu != %lu)", ret, sizeof(cipher_data.nonce));
			goto err;
		}

		/* Read data size */
		ret = read(fd_in, &bytes_read, sizeof(bytes_read));
		if (ret != sizeof(bytes_read)) {
			pr_perror("Failed to read data size (%lu != %lu)", ret, sizeof(bytes_read));
			goto err;
		}

		ret = read(fd_in, buf, bytes_read);
		if (ret != bytes_read) {
			pr_perror("Failed to read file data (%lu != %lu)", ret, bytes_read);
			goto err;
		}

		/* Decrypt buffer data using ChaCha20-Poly1305 */
		if (tls_decrypt_data(buf, bytes_read, cipher_data.tag, cipher_data.nonce) < 0) {
			pr_err("Failed to decrypt buffer data\n");
			goto err;
		}

		/* Write plaintext data */
		ret = write(fd_out, buf, bytes_read);
		if (ret != bytes_read) {
			if (ret < 0)
				pr_perror("Failed to write file data");
			else
				pr_err("Failed to write all data to file (%zd != %zd)\n", ret, bytes_read);
			goto err;
		}
		total += ret;
	}

	if (data_size && total != data_size) {
		pr_err("File size mismatch (%zd != %zd)\n", total, data_size);
		goto err;
	}

	exit_code = 0;
err:
	return exit_code;
}

int tls_encryption_pipe(int output_fd, int pipe_read_fd)
{
	while (1) {
		criu_datum_t datum;

		ssize_t ret = read(pipe_read_fd, datum.data, sizeof(datum.data));
		if (ret < 0) {
			pr_perror("Failed to read data from pipe");
			return -1;
		}

		if (ret == 0)
			break; /* EOF */

		datum.size = ret;

		if (tls_encrypt_data(datum.data, datum.size, datum.cipher_data.tag, datum.cipher_data.nonce) < 0) {
			pr_err("Failed to encrypt buffer data\n");
			return -1;
		}

		if (write(output_fd, &datum, sizeof(datum)) != sizeof(datum)) {
			pr_perror("Failed to write data packet");
			return -1;
		}
	}

	return 0;
}

int tls_decryption_pipe(int input_fd, int pipe_write_fd)
{
	while (1) {
		criu_datum_t datum;

		ssize_t ret = read(input_fd, &datum, sizeof(datum));
		if (ret == 0)
			break; /* EOF */

		if (ret != sizeof(datum)) {
			pr_err("Failed to read metadata: %ld != %ld\n", ret, sizeof(datum));
			return -1;
		}

		if (tls_decrypt_data(datum.data, datum.size, datum.cipher_data.tag, datum.cipher_data.nonce) < 0) {
			pr_err("Failed to decrypt buffer data\n");
			return -1;
		}

		if (write(pipe_write_fd, datum.data, datum.size) == -1) {
			pr_perror("Failed to write decrypted data");
			return -1;
		}
	}
	return 0;
}
