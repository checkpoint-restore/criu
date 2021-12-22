#ifndef __CR_TLS_H__
#define __CR_TLS_H__

#ifdef CONFIG_GNUTLS

int tls_x509_init(int sockfd, bool is_server);
void tls_terminate_session(bool async);

ssize_t tls_send(const void *buf, size_t len, int flags);
ssize_t tls_recv(void *buf, size_t len, int flags);

int tls_send_data_from_fd(int fd, unsigned long len);
int tls_recv_data_to_fd(int fd, unsigned long len);

#else /* CONFIG_GNUTLS */

#define tls_x509_init(sockfd, is_server) (0)
#define tls_send(buf, len, flags)	 (-1)
#define tls_recv(buf, len, flags)	 (-1)
#define tls_send_data_from_fd(fd, len)	 (-1)
#define tls_recv_data_to_fd(fd, len)	 (-1)
#define tls_terminate_session(async)

#endif /* CONFIG_HAS_GNUTLS */

#endif /* __CR_TLS_H__ */
