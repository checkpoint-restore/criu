#ifndef IMAGE_REMOTE_PVT_H
#define	IMAGE_REMOTE_PVT_H

#include <stdbool.h>
#include <stdint.h>
#include "common/list.h"
#include "img-remote.h"
#include <pthread.h>
#include <semaphore.h>

#define DEFAULT_LISTEN 50
#ifndef PAGESIZE
#define PAGESIZE 4096
#endif
#define BUF_SIZE PAGESIZE

struct rbuf {
	char buffer[BUF_SIZE];
	int nbytes; /* How many bytes are in the buffer. */
	struct list_head l;
};

struct rimage {
	char path[PATHLEN];
	char snapshot_id[PATHLEN];
	struct list_head l;
	struct list_head buf_head;
	/* Used to track already sent buffers when the image is appended. */
	struct rbuf *curr_sent_buf;
	/* Similar to the previous field. Number of bytes sent in 'curr_sent_buf'. */
	int curr_sent_bytes;
	uint64_t size; /* number of bytes */
	pthread_mutex_t in_use; /* Only one operation at a time, per image. */
};

struct wthread {
	pthread_t tid;
	struct list_head l;
	/* Client fd. */
	int fd;
	/* The path and snapshot_id identify the request handled by this thread. */
	char path[PATHLEN];
	char snapshot_id[PATHLEN];
	int flags;
	/* This semph is used to wake this thread if the image is in memory.*/
	sem_t wakeup_sem;
};

/* This variable is used to indicate when the dump is finished. */
extern bool finished;
/* This is the proxy to cache TCP socket FD. */
extern int proxy_to_cache_fd;
/* This the unix socket used to fulfill local requests. */
extern int local_req_fd;

int init_daemon(bool background, struct rimage *(*wfi)(struct wthread*));

void join_workers(void);
void unlock_workers(void);

void prepare_recv_rimg(void);
void finalize_recv_rimg(struct rimage *rimg);
struct rimage *prepare_remote_image(char *path, char *namesapce, int flags);
struct rimage *get_rimg_by_name(const char *snapshot_id, const char *path);
bool is_receiving(void);

void *accept_local_image_connections(void *ptr);
void *accept_remote_image_connections(void *ptr);

int64_t forward_image(struct rimage *rimg);
int64_t send_image(int fd, struct rimage *rimg, int flags, bool image_check);
int64_t recv_image(int fd, struct rimage *rimg, uint64_t size, int flags, bool image_check);

int64_t pb_write_obj(int fd, void *obj, int type);
int64_t pb_read_obj(int fd, void **obj, int type);

int64_t write_header(int fd, char *snapshot_id, char *path, int open_mode);
int64_t read_header(int fd, char *snapshot_id, char *path, int *open_mode);
int64_t write_reply_header(int fd, int error);
int64_t read_reply_header(int fd, int *error);
int64_t read_remote_header(int fd, char *snapshot_id, char *path, int *open_mode, uint64_t *size);
int64_t write_remote_header(int fd, char *snapshot_id, char *path, int open_mode, uint64_t size);

int setup_TCP_server_socket(int port);
int setup_TCP_client_socket(char *hostname, int port);
int setup_UNIX_client_socket(char *path);
int setup_UNIX_server_socket(char *path);
#endif
