#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <signal.h>
#include <string.h>

#include "zdtmtst.h"

const char *test_doc	= "Inotify on symlink should be checked";
#ifndef NODEL
char filename[] = "file";
char linkname[] = "file.lnk";
const char *inot_dir = "./inotify";
#else
char filename[] = "file.nodel";
char linkname[] = "file.nodel.lnk";
const char *inot_dir = "./inotify.nodel";
#endif

#ifdef __NR_inotify_init
#include <sys/inotify.h>

#ifndef IN_DONT_FOLLOW
/* Missed in SLES 10 header */
#define IN_DONT_FOLLOW		0x02000000
#endif

#define EVENT_MAX 1024
/* size of the event structure, not counting name */
#define EVENT_SIZE  (sizeof (struct inotify_event))
/* reasonable guess as to size of 1024 events */
#define EVENT_BUF_LEN        (EVENT_MAX * (EVENT_SIZE + 16))
#define BUF_SIZE 256

#define min_value(a,b) (a<b) ? a : b
#define handle_event(MASK) (MASK == IN_ACCESS) ? "IN_ACCESS" : \
(MASK == IN_MODIFY) ? "IN_MODIFY" : \
(MASK == IN_ATTRIB) ? "IN_ATTRIB" : \
(MASK == IN_CLOSE) ? "IN_CLOSE" : \
(MASK == IN_CLOSE_WRITE) ? "IN_CLOSE_WRITE" : \
(MASK == IN_CLOSE_NOWRITE) ? "IN_CLOSE_NOWRITE" : \
(MASK == IN_OPEN) ? "IN_OPEN" : \
(MASK == IN_MOVED_FROM) ? "IN_MOVED_FROM" : \
(MASK == IN_MOVED_TO) ? "IN_MOVED_TO" : \
(MASK == IN_DELETE) ? "IN_DELETE" : \
(MASK == IN_CREATE) ? "IN_CREATE" : \
(MASK == IN_DELETE_SELF) ? "IN_DELETE_SELF" : \
(MASK == IN_MOVE_SELF) ? "IN_MOVE_SELF" : \
(MASK == IN_UNMOUNT) ? "IN_UNMOUNT" : \
(MASK == IN_Q_OVERFLOW) ? "IN_Q_OVERFLOW" : \
(MASK == IN_IGNORED) ? "IN_IGNORED" : \
"UNKNOWN"

#include <unistd.h>
#include <fcntl.h>

typedef struct {
	int inot;
	uint32_t file;
	uint32_t link;
	uint32_t dir;
} desc;

void do_wait() {
	test_daemon();
	test_waitsig();
}

int createFiles(char *path, char *target, char *link) {
	int fd;
	fd = open(path,O_CREAT, 0644);
	if (fd < 0) {
		pr_perror("can't open %s", path);
		return -1;
	}
	close(fd);
	if (symlink(target, link) < 0) {
		pr_perror("can't symlink %s to %s", path, link);
		return -1;
	}
	return 0;
}

int addWatcher(int fd, const char *path) {
	int wd;
	wd = inotify_add_watch(fd, path, IN_ALL_EVENTS | IN_DONT_FOLLOW);
	if (wd < 0) {
		pr_perror("inotify_add_watch(%d, %s, IN_ALL_EVENTS) Failed, %s",
			fd, path, strerror(errno));
		return -1;
	}
	return wd;
}

int fChmod(char *path) {
	if (chmod(path, 0755) < 0) {
		pr_perror("chmod(%s, 0755) Failed, %s",
			path, strerror(errno));
		return -1;
	}
	return 0;
}

int fWriteClose(char *path) {
	int fd = open(path, O_RDWR | O_CREAT, 0700);
	if (fd == -1) {
		pr_perror("open(%s, O_RDWR|O_CREAT,0700) Failed, %s",
			path, strerror(errno));
		return -1;
	}
	if (write(fd, "string", 7) == -1) {
		pr_perror("write(%d, %s, 1) Failed, %s", fd, path, strerror(errno));
		return -1;
	}
	if (close(fd) == -1) {
		pr_perror("close(%s) Failed, %s", path, strerror(errno));
		return -1;
	}
	return 0;
}

int fNoWriteClose(char *path) {
	char buf[BUF_SIZE];
	int fd = open(path, O_RDONLY);
	if ( fd < 0 ) {
		pr_perror("open(%s, O_RDONLY) Failed, %s",
			path, strerror(errno));
		return -1;
	}
	if (read(fd, buf, BUF_SIZE) == -1) {
		pr_perror("read error: %s", strerror(errno));
		close(fd);
		return -1;
	}
	if (close(fd) == -1) {
		pr_perror("close(%s) Failed, %s", path, strerror(errno));
		return -1;
	}
	return 0;
}

int fMove(char *from, char *to) {
	if (rename(from, to) == -1) {
		pr_perror("rename error (from: %s to: %s) : %s",
			from, to, strerror(errno));
		return -1;
	}
	return 0;
}

desc init_env(const char *dir, char *file_path, char *link_path) {
	desc in_desc = {-1, -1, -1, -1};
	if (mkdir(dir, 0777) < 0) {
		pr_perror("error in creating directory: %s, %s",
			dir, strerror(errno));
		return in_desc;
	}
	in_desc.inot = inotify_init();
	if (in_desc.inot < 0) {
		pr_perror("inotify_init () Failed, %s", strerror(errno));
		rmdir(dir);
		return in_desc;
	}

	if (snprintf(file_path, BUF_SIZE, "%s/%s", dir, filename) >= BUF_SIZE) {
		pr_perror("filename %s is too long", filename);
		rmdir(dir);
		return in_desc;
	}

	if (snprintf(link_path, BUF_SIZE, "%s/%s", dir, linkname) >= BUF_SIZE) {
		pr_perror("filename %s is too long", linkname);
		rmdir(dir);
		return in_desc;
	}

	in_desc.dir = addWatcher(in_desc.inot, dir);
	if (createFiles(file_path, filename, link_path)) {
		return in_desc;
	}
	in_desc.link = addWatcher(in_desc.inot, link_path);
	in_desc.file = addWatcher(in_desc.inot, file_path);

	return in_desc;
}

int fDelete(char *path) {
	if (unlink(path) != 0) {
		pr_perror("unlink: (%s)", strerror(errno));
		return -1;
	}
	return 0;
}

int fRemDir(const char *target) {
	if(rmdir(target)) {
		pr_perror("rmdir: (%s)", strerror(errno));
		return -1;
	}
	return 0;
}

int test_actions(const char *dir, char *file_path, char *link_path) {

	if (
		fChmod(link_path) == 0 &&
		fWriteClose(link_path) == 0 &&
		fNoWriteClose(link_path) == 0 &&
		fMove(file_path, filename) == 0 &&
		fMove(filename, file_path) == 0
#ifndef NODEL
		&& fDelete(file_path) == 0 &&
		fDelete(link_path) == 0 &&
		fRemDir(dir) == 0
#endif
	)
	{
		return 0;
	}
	return -1;
}

void dump_events(char *buf, int len) {
	int marker = 0;
	struct inotify_event *event;
	while (marker < len) {
		event = (struct inotify_event *) &buf[marker];
		test_msg("\t%s (%x mask, %d len", handle_event(event->mask), event->mask, event->len);
		if (event->len)
			test_msg(", '%s' name", event->name);
		test_msg(")\n");
		marker += EVENT_SIZE + event->len;
	}
}

int harmless(int mask)
{
	switch (mask) {
		case IN_CLOSE_NOWRITE:
		case IN_ATTRIB:
			return 1;
	}
	return 0;
}

int errors(int exp_len, int len, char *etalon_buf, char *buf) {
	int marker=0;
	int error=0;
	while (marker < len){
		struct inotify_event *event;
		struct inotify_event *exp_event;
		event = (struct inotify_event *) &buf[marker];
		/* It's OK if some additional events are recevived */
		if (marker < exp_len)
			exp_event = (struct inotify_event *) &etalon_buf[marker];
		else {
			if (!harmless(event->mask)) {
				fail("got unexpected event %s (%x mask)\n",
					handle_event(event->mask), event->mask);
				error++;
			}
			goto next_event;
		}

		if (event->mask != exp_event->mask) {
			fail("Handled %s (%x mask), expected %s (%x mask)",
				handle_event(event->mask), event->mask,
				handle_event(exp_event->mask),
				exp_event->mask);
				error++;
		}
		if (event->len != exp_event->len) {
			fail("Incorrect length of field name.");
			error++;
			break;
		}
		else if (event->len && strncmp(event->name, exp_event->name, event->len)) {
			fail("Handled file name %s, expected %s",
				event->name,
				exp_event->name);
				error++;
		}
next_event:
		marker += EVENT_SIZE + event->len;
	}
	return error;
}

int read_set(int inot_fd, char *event_set) {
	int len;
	if ((len = read(inot_fd, event_set, EVENT_BUF_LEN)) < 0) {
		pr_perror("read(%d, buf, %lu) Failed, errno=%d",
			inot_fd, (unsigned long)EVENT_BUF_LEN, errno);
		return -1;
	}
	return len;
}

void common_close(desc *descr) {
	if (descr->inot > 0) {
		close(descr->inot);
		descr->inot=-1;
		descr->file=-1;
		descr->dir=-1;
		descr->link=-1;
	}
}

int get_event_set(char *event_set, int wait) {
	int len;
	char link_path[BUF_SIZE];
	char file_path[BUF_SIZE];
	desc common_desc;

	common_desc = init_env(inot_dir, file_path, link_path);
	if ((common_desc.inot < 0) || (common_desc.file < 0) || \
			(common_desc.dir < 0) || (common_desc.link < 0)) {
		common_close(&common_desc);
		return -1;
	}
	if(test_actions(inot_dir, file_path, link_path) < 0) {
		common_close(&common_desc);
		return -1;
	}
	if (wait) {
		do_wait();
	}
	len = read_set(common_desc.inot, event_set);
	common_close(&common_desc);
#ifdef NODEL
	if (! (fDelete(file_path) == 0 &&
		fDelete(link_path) == 0 &&
		fRemDir(inot_dir) == 0))
		return -1;
#endif
	return len;
}

int check(int len, char *event_set, int exp_len, char *etalon_event_set) {

	if ((exp_len < 0) || (len < 0)){
		fail("Error in preparing event sets.");
		return -1;
	}
	if (len < exp_len) {
		fail("Events are lost. Read: %d, Expected: %d", len, exp_len);
		test_msg("expected events\n");
		dump_events(etalon_event_set, exp_len);
		test_msg("real events\n");
		dump_events(event_set, len);
		return -1;
	}
	if (errors(exp_len, len, etalon_event_set, event_set) == 0) {
		pass();
		return 0;
	}
	return -1;
}

int main(int argc, char ** argv)
{
	int exp_len=-1, len=-1;
	char etalon_event_set[EVENT_BUF_LEN];
	char event_set[EVENT_BUF_LEN];

	test_init(argc, argv);

	exp_len = get_event_set(etalon_event_set, 0);
	len = get_event_set(event_set, 1);

	if (check(len, event_set, exp_len, etalon_event_set)) {
		return 1;
	}
	return 0;
}
#else

int main(int argc, char ** argv)
{
	test_init(argc, argv);
	skip("Inotify not supported.");
	return 0;
}
#endif //__NR_inotify_init
