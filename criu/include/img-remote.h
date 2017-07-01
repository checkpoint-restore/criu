#include <limits.h>
#include <stdbool.h>

#include <stdint.h>
#include "common/list.h"
#include <pthread.h>
#include <semaphore.h>

#ifndef IMAGE_REMOTE_H
#define	IMAGE_REMOTE_H

#define PATHLEN PATH_MAX
#define DUMP_FINISH "DUMP_FINISH"
#define RESTORE_FINISH "RESTORE_FINISH"
#define PARENT_IMG "parent"
#define NULL_SNAPSHOT_ID "null"
#define DEFAULT_CACHE_SOCKET "img-cache.sock"
#define DEFAULT_PROXY_SOCKET "img-proxy.sock"
#define DEFAULT_CACHE_PORT 9996
#define DEFAULT_CACHE_HOST "localhost"

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

int64_t read_remote_header(int fd, char *snapshot_id, char *path, int *open_mode, uint64_t *size);
int64_t write_remote_header(int fd, char *snapshot_id, char *path, int open_mode, uint64_t size);

int setup_TCP_server_socket(int port);
int setup_TCP_client_socket(char *hostname, int port);
int setup_UNIX_server_socket(char *path);

/* Called by restore to get the fd correspondent to a particular path.  This call
 * will block until the connection is received.
 */
int read_remote_image_connection(char *snapshot_id, char *path);

/* Called by dump to create a socket connection to the restore side. The socket
 * fd is returned for further writing operations.
 */
int write_remote_image_connection(char *snapshot_id, char *path, int flags);

/* Called by dump/restore when everything is dumped/restored. This function
 * creates a new connection with a special control name. The receiver side uses
 * it to ack that no more files are coming.
 */
int finish_remote_dump();
int finish_remote_restore();

/* Starts an image proxy daemon (dump side). It receives image files through
 * socket connections and forwards them to the image cache (restore side).
 */
int image_proxy(bool background, char *local_proxy_path, char *cache_host, unsigned short cache_port);

/* Starts an image cache daemon (restore side). It receives image files through
 * socket connections and caches them until they are requested by the restore
 * process.
 */
int image_cache(bool background, char *local_cache_path, unsigned short cache_port);

/* Reads (discards) 'len' bytes from fd. This is used to emulate the function
 * lseek, which is used to advance the file needle.
 */
int skip_remote_bytes(int fd, unsigned long len);

/* To support iterative migration, the concept of snapshot_id is introduced
 * (only when remote migration is enabled). Each image is tagged with one
 * snapshot_id. The snapshot_id is the image directory used for the operation
 * that creates the image (either predump or dump). Images stored in memory
 * (both in Image Proxy and Image Cache) are identified by their name and
 * snapshot_id. Snapshot_ids are ordered so that we can find parent pagemaps
 * (that will be used when restoring the process).
 */

/* Sets the current snapshot_id */
void init_snapshot_id(char *ns);

/* Returns the current snapshot_id. */
char *get_curr_snapshot_id();

/* Returns the snapshot_id index representing the current snapshot_id. This
 * index represents the hierarchy position. For example: images tagged with
 * the snapshot_id with index 1 are more recent than the images tagged with
 * the snapshot_id with index 0.
 */
int get_curr_snapshot_id_idx();

/* Returns the snapshot_id associated with the snapshot_id index. */
char *get_snapshot_id_from_idx(int idx);

/* Pushes the current snapshot_id into the snapshot_id hierarchy (into the Image
 * Proxy and Image Cache).
 */
int push_snapshot_id();

/* Returns the snapshot id index that preceeds the current snapshot_id. */
int get_curr_parent_snapshot_id_idx();

#endif
