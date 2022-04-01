#include <sys/socket.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <stdio.h>
#include <poll.h>

#include "compel/plugins/std/syscall-codes.h"
#include "cr_options.h"
#include "common/scm.h"
#include "common/list.h"
#include "kerndat.h"
#include "log.h"
#include "util.h"
#include "pidfd-store.h"

struct pidfd_entry {
	pid_t pid;
	int pidfd;
	struct hlist_node hash; /* To lookup pidfd by pid */
};

static int pidfd_store_sk = -1;
#define PIDFD_HASH_SIZE 32
static struct hlist_head pidfd_hash[PIDFD_HASH_SIZE];

/*
 * Steal (sk) from remote RPC client (pid) and prepare it to
 * be used as the pidfd storage socket.
 */
int init_pidfd_store_sk(pid_t pid, int sk)
{
	int pidfd;
	int sock_type;
	socklen_t len;
	struct sockaddr_un addr;
	unsigned int addrlen;
	/* In kernel a bufsize has type int and a value is doubled. */
	uint32_t buf[2] = { INT_MAX / 2, INT_MAX / 2 };

	if (!kdat.has_pidfd_open) {
		pr_err("pidfd_open syscall is not supported\n");
		return -1;
	}

	if (!kdat.has_pidfd_getfd) {
		pr_err("pidfd_getfd syscall is not supported\n");
		return -1;
	}

	/* Steal pidfd store socket from RPC client */
	pidfd = syscall(SYS_pidfd_open, pid, 0);
	if (pidfd == -1) {
		pr_perror("Can't get pidfd of (pid: %d)", pid);
		goto err;
	}

	close_safe(&pidfd_store_sk);
	pidfd_store_sk = syscall(SYS_pidfd_getfd, pidfd, sk, 0);
	if (pidfd_store_sk == -1) {
		pr_perror("Can't steal fd %d using pidfd_getfd", sk);
		close(pidfd);
		goto err;
	}
	close(pidfd);

	/* Check that stolen socket is a connectionless unix domain socket */
	len = sizeof(sock_type);
	if (getsockopt(pidfd_store_sk, SOL_SOCKET, SO_TYPE, &sock_type, &len)) {
		pr_perror("Can't get socket type (fd: %d)", pidfd_store_sk);
		goto err;
	}

	if (sock_type != SOCK_DGRAM) {
		pr_err("Pidfd store socket must be of type SOCK_DGRAM\n");
		goto err;
	}

	addrlen = sizeof(addr);
	if (getsockname(pidfd_store_sk, (struct sockaddr *)&addr, &addrlen)) {
		pr_perror("Can't get socket bound name (fd: %d)", pidfd_store_sk);
		goto err;
	}

	if (addr.sun_family != AF_UNIX) {
		pr_err("Pidfd store socket must be AF_UNIX\n");
		goto err;
	}

	/*
	 * Unnamed socket needs to be initialized and connected to itself.
	 * This only occurs once in the first predump, after the socket is
	 * bound, addrlen will be sizeof(struct sockaddr_un).
	 * This is similar to how fdstore_init() works.
	 */
	if (addrlen == sizeof(sa_family_t)) {
		if (setsockopt(pidfd_store_sk, SOL_SOCKET, SO_SNDBUFFORCE, &buf[0], sizeof(buf[0])) < 0 ||
		    setsockopt(pidfd_store_sk, SOL_SOCKET, SO_RCVBUFFORCE, &buf[1], sizeof(buf[1])) < 0) {
			pr_perror("Unable to set SO_SNDBUFFORCE/SO_RCVBUFFORCE");
			goto err;
		}

		addrlen = snprintf(addr.sun_path, sizeof(addr.sun_path), "X/criu-pidfd-store-%d-%d-%" PRIx64, pid, sk,
				   criu_run_id);
		addrlen += sizeof(addr.sun_family);

		addr.sun_path[0] = 0;

		if (bind(pidfd_store_sk, (struct sockaddr *)&addr, addrlen)) {
			pr_perror("Unable to bind a socket");
			goto err;
		}

		if (connect(pidfd_store_sk, (struct sockaddr *)&addr, addrlen)) {
			pr_perror("Unable to connect a socket");
			goto err;
		}
	}

	return 0;
err:
	close_safe(&pidfd_store_sk);
	return -1;
}

void free_pidfd_store(void)
{
	int i;
	struct pidfd_entry *entry;
	struct hlist_node *tmp;

	for (i = 0; i < PIDFD_HASH_SIZE; i++) {
		hlist_for_each_entry_safe(entry, tmp, &pidfd_hash[i], hash) {
			close(entry->pidfd);
			xfree(entry);
		}
		INIT_HLIST_HEAD(&pidfd_hash[i]);
	}

	close_safe(&pidfd_store_sk);
}

int init_pidfd_store_hash(void)
{
	int i, cnt, ret;
	struct pidfd_entry *entry;

	for (i = 0; i < PIDFD_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&pidfd_hash[i]);

	/* Skip building pidfd_hash if pidfd_store_sk is not initialized */
	if (pidfd_store_sk == -1)
		return 0;

	/*
	 * Drain all queued pidfd entries in pidfd_store_sk from
	 * the last predump into pidfd_hash.
	 */
	cnt = 0;
	while (1) {
		entry = xmalloc(sizeof(struct pidfd_entry));
		if (entry == NULL)
			goto err;
		INIT_HLIST_NODE(&entry->hash);

		ret = __recv_fds(pidfd_store_sk, &entry->pidfd, 1, &entry->pid, sizeof(pid_t), MSG_DONTWAIT);
		if (ret == -EAGAIN || ret == -EWOULDBLOCK) {
			/* No more fds to read */
			xfree(entry);
			goto check_empty;
		} else if (ret) {
			pr_perror("Can't read pidfd");
			xfree(entry);
			goto err;
		}

		cnt++;
		hlist_add_head(&entry->hash, &pidfd_hash[entry->pid % PIDFD_HASH_SIZE]);
	}

err:
	free_pidfd_store();
	return -1;
check_empty:
	/*
	 * If no pidfds exist in pidfd_store. This would cause full page
	 * dumps which goes against the purpose of the pidfd store.
	 * This is probably due to sending a different pidfd_store socket.
	 */
	if (cnt == 0 && opts.img_parent) {
		pr_err("No pidfds found in pidfd store\n");
		pr_err("The same socket from the previous iteration should be passed\n");
		return -1;
	}

	return 0;
}

static struct pidfd_entry *find_pidfd_entry_by_pid(pid_t pid)
{
	struct pidfd_entry *entry;
	struct hlist_head *chain;

	chain = &pidfd_hash[pid % PIDFD_HASH_SIZE];
	hlist_for_each_entry(entry, chain, hash) {
		if (entry->pid == pid)
			return entry;
	}

	return NULL;
}

/*
 * 1 - task closed
 * 0 - task still running
 * -1 - error
 */
static int check_pidfd_entry_state(struct pidfd_entry *entry)
{
	struct pollfd pollfd;
	int ret, restart_cnt = 0;
	const int MAX_RESTARTS = 10; /* Reasonable limit to avoid getting stuck */

	/*
	 * When there is data to read from the pidfd, it means
	 * that the task associated with this pidfd is closed.
	 */
	pollfd.fd = entry->pidfd;
	pollfd.events = POLLIN;

	while (1) {
		ret = poll(&pollfd, 1, 0);
		if (ret == -1 && errno == EINTR && restart_cnt < MAX_RESTARTS) {
			restart_cnt++;
			continue; /* restart polling */
		}

		return ret;
	}
}

int pidfd_store_add(pid_t pid)
{
	int pidfd, entry_state;
	struct pidfd_entry *entry;

	/* Skip sending if pidfd_store_sk is not initialized */
	if (pidfd_store_sk == -1)
		return 0;

	/*
	 * Use existing pidfd entry or create pidfd for task.
	 * If entry exists with same pid we must check that
	 * it is not a case of pid reuse (i.e. task is closed).
	 */
	entry = find_pidfd_entry_by_pid(pid);
	if (entry != NULL) {
		entry_state = check_pidfd_entry_state(entry);
		if (entry_state == -1) {
			pr_perror("Can't get state of pidfd entry of pid %d", pid);
			return -1;
		} else if (entry_state == 1) {
			/* Task is closed, We need to create a new pidfd for task. */
			entry = NULL;
		}
	}

	if (entry == NULL) {
		if (!kdat.has_pidfd_open) {
			pr_err("pidfd_open syscall is not supported\n");
			return -1;
		}

		pidfd = syscall(SYS_pidfd_open, pid, 0);
		if (pidfd == -1) {
			pr_perror("Can't get pidfd of pid %d", pid);
			return -1;
		}
	} else {
		pidfd = entry->pidfd;
	}

	if (send_fds(pidfd_store_sk, NULL, 0, &pidfd, 1, &pid, sizeof(pid_t))) {
		pr_perror("Can't send pidfd %d of pid %d", pidfd, pid);
		if (!entry)
			close(pidfd);
		return -1;
	}

	if (!entry)
		close(pidfd);

	return 0;
}

/*
 * 1 - pid reuse detected
 * 0 - task still running
 * -1 - error
 */
int pidfd_store_check_pid_reuse(pid_t pid)
{
	struct pidfd_entry *entry;
	int ret;

	entry = find_pidfd_entry_by_pid(pid);
	if (entry == NULL) {
		/*
		 * This task was created between two iteration so it
		 * should be marked as a pid reuse to make a full memory dump.
		 */
		pr_warn("Pid reuse detected for pid %d\n", pid);
		return 1;
	}

	ret = check_pidfd_entry_state(entry);
	if (ret == -1)
		pr_err("Failed to get pidfd entry state for pid %d\n", pid);
	else if (ret == 1)
		pr_warn("Pid reuse detected for pid %d\n", pid);

	return ret;
}

bool pidfd_store_ready(void)
{
	return pidfd_store_sk != -1;
}
