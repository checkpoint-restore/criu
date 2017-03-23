#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include "xmalloc.h"
#include "criu-log.h"
#include "img-remote.h"
#include "img-remote-proto.h"
#include "images/remote-image.pb-c.h"
#include "protobuf-desc.h"
#include <fcntl.h>
#include "servicefd.h"
#include "common/compiler.h"
#include "cr_options.h"

#define PB_LOCAL_IMAGE_SIZE PATHLEN

static char *snapshot_id;
bool restoring = true;

LIST_HEAD(snapshot_head);

/* A snapshot is a dump or pre-dump operation. Each snapshot is identified by an
 * ID which corresponds to the working directory specefied by the user.
 */
struct snapshot {
	char snapshot_id[PATHLEN];
	struct list_head l;
};

struct snapshot *new_snapshot(char *snapshot_id)
{
	struct snapshot *s = xmalloc(sizeof(struct snapshot));

	if (!s)
		return NULL;

	strncpy(s->snapshot_id, snapshot_id, PATHLEN - 1);
	s->snapshot_id[PATHLEN - 1]= '\0';
	return s;
}

void add_snapshot(struct snapshot *snapshot)
{
	list_add_tail(&(snapshot->l), &snapshot_head);
}

int read_remote_image_connection(char *snapshot_id, char *path)
{
	int error;
	int sockfd = setup_UNIX_client_socket(restoring ? DEFAULT_CACHE_SOCKET: DEFAULT_PROXY_SOCKET);

	if (sockfd < 0) {
		pr_perror("Error opening local connection for %s:%s", path, snapshot_id);
		return -1;
	}

	if (write_header(sockfd, snapshot_id, path, O_RDONLY) < 0) {
		pr_perror("Error writing header for %s:%s", path, snapshot_id);
		return -1;
	}

	if (read_reply_header(sockfd, &error) < 0) {
		pr_perror("Error reading reply header for %s:%s", path, snapshot_id);
		return -1;
	}
	if (!error || !strncmp(path, RESTORE_FINISH, sizeof(RESTORE_FINISH)))
		return sockfd;
	else if (error == ENOENT) {
		pr_info("Image does not exist (%s:%s)\n", path, snapshot_id);
		close(sockfd);
		return -ENOENT;
	}
	pr_perror("Unexpected error returned: %d (%s:%s)\n", error, path, snapshot_id);
	close(sockfd);
	return -1;
}

int write_remote_image_connection(char *snapshot_id, char *path, int flags)
{
	int sockfd = setup_UNIX_client_socket(DEFAULT_PROXY_SOCKET);

	if (sockfd < 0)
		return -1;

	if (write_header(sockfd, snapshot_id, path, flags) < 0) {
		pr_perror("Error writing header for %s:%s", path, snapshot_id);
		return -1;
	}
	return sockfd;
}

int finish_remote_dump(void)
{
	pr_info("Dump side is calling finish\n");
	int fd = write_remote_image_connection(NULL_SNAPSHOT_ID, DUMP_FINISH, O_WRONLY);

	if (fd == -1) {
		pr_perror("Unable to open finish dump connection");
		return -1;
	}

	close(fd);
	return 0;
}

int finish_remote_restore(void)
{
	pr_info("Restore side is calling finish\n");
	int fd = read_remote_image_connection(NULL_SNAPSHOT_ID, RESTORE_FINISH);

	if (fd == -1) {
		pr_perror("Unable to open finish restore connection");
		return -1;
	}

	close(fd);
	return 0;
}

int skip_remote_bytes(int fd, unsigned long len)
{
	static char buf[4096];
	int n = 0;
	unsigned long curr = 0;

	for (; curr < len; ) {
		n = read(fd, buf, min(len - curr, (unsigned long)4096));
		if (n == 0) {
			pr_perror("Unexpected end of stream (skipping %lx/%lx bytes)",
				curr, len);
			return -1;
		} else if (n > 0) {
			curr += n;
		} else {
			pr_perror("Error while skipping bytes from stream (%lx/%lx)",
				curr, len);
			return -1;
		}
	}

	if (curr != len) {
		pr_perror("Unable to skip the current number of bytes: %lx instead of %lx",
			curr, len);
		return -1;
	}
	return 0;
}

static int pull_snapshot_ids(void)
{
	int n, sockfd;
	SnapshotIdEntry *ls;
	struct snapshot *s = NULL;

	sockfd = read_remote_image_connection(NULL_SNAPSHOT_ID, PARENT_IMG);

	/* The connection was successful but there is not file. */
	if (sockfd < 0 && errno == ENOENT)
		return 0;
	else if (sockfd < 0) {
		pr_perror("Unable to open snapshot id read connection");
		return -1;
	}

	while (1) {
		n = pb_read_obj(sockfd, (void **)&ls, PB_SNAPSHOT_ID);
		if (!n) {
			close(sockfd);
			return n;
		} else if (n < 0) {
			pr_perror("Unable to read remote snapshot ids");
			close(sockfd);
			return n;
		}

		s = new_snapshot(ls->snapshot_id);
		if (!s) {
			close(sockfd);
			return -1;
		}
		add_snapshot(s);
		pr_info("[read_snapshot ids] parent = %s\n", ls->snapshot_id);
	}
	free(ls);
	close(sockfd);
	return n;
}

int push_snapshot_id(void)
{
	int n;
	restoring = false;
	SnapshotIdEntry rn = SNAPSHOT_ID_ENTRY__INIT;
	int sockfd = write_remote_image_connection(NULL_SNAPSHOT_ID, PARENT_IMG, O_APPEND);

	if (sockfd < 0) {
		pr_perror("Unable to open snapshot id push connection");
		return -1;
	}

	rn.snapshot_id = xmalloc(sizeof(char) * PATHLEN);
	if (!rn.snapshot_id) {
		close(sockfd);
		return -1;
	}
	strncpy(rn.snapshot_id, snapshot_id, PATHLEN);

	n = pb_write_obj(sockfd, &rn, PB_SNAPSHOT_ID);

	xfree(rn.snapshot_id);
	close(sockfd);
	return n;
}

void init_snapshot_id(char *si)
{
	snapshot_id = si;
}

char *get_curr_snapshot_id(void)
{
	return snapshot_id;
}

int get_curr_snapshot_id_idx(void)
{
	struct snapshot *si;
	int idx = 0;

	if (list_empty(&snapshot_head))
		pull_snapshot_ids();

	list_for_each_entry(si, &snapshot_head, l) {
	if (!strncmp(si->snapshot_id, snapshot_id, PATHLEN))
			return idx;
		idx++;
	}

	pr_perror("Error, could not find current snapshot id (%s) fd", snapshot_id);
	return -1;
}

char *get_snapshot_id_from_idx(int idx)
{
	struct snapshot *si;

	if (list_empty(&snapshot_head))
		pull_snapshot_ids();

	/* Note: if idx is the service fd then we need the current
	 * snapshot_id idx. Else we need a parent snapshot_id idx.
	 */
	if (idx == get_service_fd(IMG_FD_OFF))
		idx = get_curr_snapshot_id_idx();

	list_for_each_entry(si, &snapshot_head, l) {
		if (!idx)
			return si->snapshot_id;
		idx--;
	}

	pr_perror("Error, could not find snapshot id for idx %d", idx);
	return NULL;
}

int get_curr_parent_snapshot_id_idx(void)
{
	return get_curr_snapshot_id_idx() - 1;
}
