#ifndef __CR_TLS_H__
#define __CR_TLS_H__

/* 96-bits nonce and 128-bits tag for ChaCha20-Poly1305 */
typedef struct {
	uint8_t tag[16];
	uint8_t nonce[12];
} chacha20_poly1305_t;

typedef struct {
	chacha20_poly1305_t cipher_data;
	ssize_t size;
	char data[4096];
} criu_datum_t;

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
int tls_encryption_pipe(int output_file_fd, int pipe_read_fd);
int tls_decryption_pipe(int intput_file_fd, int pipe_write_fd);
int tls_block_cipher_encrypt_data(void *ptext, size_t ptext_len);
int tls_block_cipher_decrypt_data(void *ctext, size_t ctext_len);
int tls_vma_io_pipe(int pages_img_fd, int pipe_fds[2][2]);
bool tls_verify_hmac(void);
void tls_set_hmac_vma_metadata(uint64_t vma_addr);
void tls_increment_hmac_vma_metadata(uint64_t n);
void tls_set_hmac_pid_metadata(pid_t pid);

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
#define tls_encryption_pipe(output_file_fd, pipe_read_fd) (-1)
#define tls_decryption_pipe(intput_file_fd, pipe_write_fd) (-1)
#define tls_block_cipher_encrypt_data(ptext, ptext_len)		(-1)
#define tls_block_cipher_decrypt_data(ctext, ctext_len)		(-1)
#define tls_vma_io_pipe(pages_img_fd, pipe_fds) (-1)
#define write_img_cipher() (0)
#define tls_verify_hmac() (true)
#define tls_set_hmac_vma_metadata(vma_addr)
#define tls_increment_hmac_vma_metadata(n)
#define tls_set_hmac_pid_metadata(pid)

#endif /* CONFIG_HAS_GNUTLS */

#endif /* __CR_TLS_H__ */
