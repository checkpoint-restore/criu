#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <linux/un.h>

struct ticket
{
	struct ticket *next;
	int val;
	int id;
};

struct ticket *tickets;

#define SK_NAME "/tmp/criu.unix.callback.test"

int main()
{
	int sk, ret, id;
	char buf[4096];
	struct ticket *t;
	struct sockaddr_un addr;
	socklen_t addr_len;
	struct stat st;

	unlink(SK_NAME);

	sk = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sk < 0) {
		perror("socket");
		return -1;
	}

	addr.sun_family = AF_UNIX;
	addr_len = snprintf(addr.sun_path, UNIX_PATH_MAX, SK_NAME);
	addr_len += sizeof(addr.sun_family);

	if (bind(sk, (struct sockaddr *) &addr, addr_len) < 0) {
		perror("bind");
		return 1;
	}

	fstat(sk, &st);

	while (1) {
		addr_len = sizeof(struct sockaddr_un);
		ret = recvfrom(sk, buf, sizeof(buf), 0, (struct sockaddr *) &addr, &addr_len);
		if (ret == 0)
			return 0;
		if (ret < 0) {
			perror("recvfrom");
			return 1;
		}
		id = 0;
		switch (buf[0]) {
		case 'l':
			ret = sprintf(buf, "%ld", st.st_ino);
			if (sendto(sk, buf, ret + 1, 0, (struct sockaddr *) &addr, addr_len) < 0) {
				perror("sendto");
				return -1;
			}
			break;
		case 't': /* ticket */
			t = malloc(sizeof(struct ticket));
			if (t == 0) {
				perror("Can't allocate memory");
				return 1;
			}

			t->val = atoi(buf + 1);
			t->next = tickets;
			t->id = atoi(addr.sun_path +strlen(SK_NAME));
			printf("t: id %d val %d\n", t->id, t->val);
			tickets = t;
			break;
		case 'd': /* dump */
			id = atoi(buf + 1);
		case 'r': /* request */
			if (!id)
				id = atoi(addr.sun_path + strlen(SK_NAME));
			for (t = tickets; t; t = t->next)
				if (t->id == id)
					break;
			if (t == NULL)
				return 1;
			printf("r: id %d val %d\n", id, t->val);
			ret = sprintf(buf, "%d", t->val);
			if (sendto(sk, buf, ret + 1, 0, (struct sockaddr *) &addr, addr_len) < 0) {
				perror("sendto");
				return 1;
			}
			break;
		default:
			return -1;
		}
	}

	return 0;
}
