#include <limits.h>
#include <stdbool.h>

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
