#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/inotify.h>

#define EVENT_SIZE	(sizeof(struct inotify_event))
#define BUF_LEN		(1024 * (EVENT_SIZE + 16))

int main(int argc, char **argv)
{
	char buf[BUF_LEN];
	int fd, wd, len, i;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <path>\n", argv[0]);
		return 1;
	}

	fd = inotify_init();
	if (fd < 0) {
		perror("inotify_init");
		return 1;
	}

	wd = inotify_add_watch(fd, argv[1],
			       IN_MODIFY | IN_CREATE | IN_DELETE |
			       IN_OPEN | IN_CLOSE);
	if (wd < 0) {
		perror("inotify_add_watch");
		close(fd);
		return 1;
	}

	printf("Watching %s for events...\n", argv[1]);

	while (1) {
		len = read(fd, buf, BUF_LEN);
		if (len < 0) {
			perror("read");
			break;
		}

		i = 0;
		while (i < len) {
			struct inotify_event *event;

			event = (struct inotify_event *)&buf[i];

			if (event->mask & IN_CREATE)
				printf("CREATE: %s\n", event->name);
			if (event->mask & IN_DELETE)
				printf("DELETE: %s\n", event->name);
			if (event->mask & IN_MODIFY)
				printf("MODIFY: %s\n", event->name);
			if (event->mask & IN_OPEN)
				printf("OPEN: %s\n", event->name);
			if (event->mask & IN_CLOSE)
				printf("CLOSE: %s\n", event->name);

			i += EVENT_SIZE + event->len;
		}
	}

	inotify_rm_watch(fd, wd);
	close(fd);

	return 0;
}
