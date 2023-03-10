#ifndef __CR_TLS_H__
#define __CR_TLS_H__

/* 96-bits nonce and 128-bits tag for ChaCha20-Poly1305 */
typedef struct {
	uint8_t tag[16];
	uint8_t nonce[12];
} chacha20_poly1305_t;

#ifdef CONFIG_GNUTLS

#include <stdbool.h>

int tls_x509_init(int sockfd, bool is_server);
void tls_terminate_session(bool async);

ssize_t tls_send(const void *buf, size_t len, int flags);
ssize_t tls_recv(void *buf, size_t len, int flags);

int tls_send_data_from_fd(int fd, unsigned long len);
int tls_recv_data_to_fd(int fd, unsigned long len);

int write_img_cipher(void);
int tls_initialize_cipher(void);
int tls_initialize_cipher_from_image(void);
int tls_encrypt_data(void *data, size_t data_size, uint8_t *tag_data, uint8_t *nonce_data);
int tls_decrypt_data(void *data, size_t data_size, uint8_t *tag_data, uint8_t *nonce_data);
int tls_encrypt_pipe_data(int fd_in, int fd_out, size_t data_size);
int tls_encrypt_file_data(int fd_in, int fd_out, size_t data_size);
int tls_decrypt_file_data(int fd_in, int fd_out, size_t data_size);

#else /* CONFIG_GNUTLS */

#define tls_x509_init(sockfd, is_server) (0)
#define tls_send(buf, len, flags)	 (-1)
#define tls_recv(buf, len, flags)	 (-1)
#define tls_send_data_from_fd(fd, len)	 (-1)
#define tls_recv_data_to_fd(fd, len)	 (-1)
#define tls_terminate_session(async)
#define tls_initialize_cipher() (0)
#define tls_initialize_cipher_from_image() (0)
#define tls_encrypt_data(data, data_size, tag_data, nonce_data) (-1)
#define tls_decrypt_data(data, data_size, tag_data, nonce_data) (-1)
#define tls_encrypt_pipe_data(fd_in, fd_out, data_size) (-1)
#define tls_encrypt_file_data(fd_in, fd_out, data_size) (-1)
#define tls_decrypt_file_data(fd_in, fd_out, data_size) (-1)
#define write_img_cipher() (0)

#endif /* CONFIG_HAS_GNUTLS */

#endif /* __CR_TLS_H__ */
