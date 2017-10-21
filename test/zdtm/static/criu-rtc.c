#include <stdio.h>
#include <linux/rtc.h>
#include <sys/ioctl.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <unistd.h>
#include <errno.h>

#include "criu-plugin.h"
#include "criu-log.h"

#include "criu-rtc.pb-c.h"

extern cr_plugin_dump_file_t cr_plugin_dump_file;
extern cr_plugin_restore_file_t cr_plugin_restore_file;

int cr_plugin_dump_file(int fd, int id)
{
	CriuRtc e = CRIU_RTC__INIT;
	char img_path[PATH_MAX];
	unsigned char buf[4096];
	int img_fd, ret, len;
	unsigned long irqp;
	struct stat st, st_rtc;

	if (fstat(fd, &st) == -1) {
		pr_perror("fstat");
		return -1;
	}

	ret = stat("/dev/rtc", &st_rtc);
	if (ret == -1) {
		pr_perror("fstat");
		return -1;
	}

	if (major(st.st_rdev) != major(st_rtc.st_rdev) ||
	    minor(st.st_rdev) != 0)
		return -ENOTSUP;

	if (ioctl(fd, RTC_IRQP_READ, &irqp) == -1) {
		pr_perror("RTC_IRQP_READ");
		return -1;
	}

	e.irqp = irqp;

	snprintf(img_path, sizeof(img_path), "rtc.%x", id);
	img_fd = openat(criu_get_image_dir(), img_path, O_WRONLY | O_CREAT);
	if (img_fd < 0) {
		pr_perror("Can't open %s", img_path);
		return -1;
	}

	len = criu_rtc__get_packed_size(&e);
	if (len > sizeof(buf))
		return -1;

	criu_rtc__pack(&e, buf);

	ret = write(img_fd,  buf, len);
	if (ret != len) {
		pr_perror("Unable to write in %s", img_path);
		close(img_fd);
		return -1;
	}

	close(img_fd);
	return 0;
}

int cr_plugin_restore_file(int id)
{
	unsigned char buf[4096];
	char img_path[PATH_MAX];
	int img_fd, len, fd;
	CriuRtc *e;

	snprintf(img_path, sizeof(img_path), "rtc.%x", id);
	img_fd = openat(criu_get_image_dir(), img_path, O_RDONLY);
	if (img_fd < 0) {
		pr_perror("open(%s)", img_path);
		return -ENOTSUP;
	}

	len = read(img_fd, &buf, sizeof(buf));
	if (len <= 0) {
		pr_perror("Unable to read from %s", img_path);
		close(img_fd);
		return -1;
	}
	close(img_fd);

	e = criu_rtc__unpack(NULL, len, buf);
	if (e == NULL) {
		pr_err("Unable to parse the RTC message %#x", id);
		return -1;
	}

	fd = open("/dev/rtc", O_RDWR);
	if (fd < 0) {
		pr_perror("open");
		return -1;
	}

	if (ioctl(fd, RTC_IRQP_SET, e->irqp) == -1) {
		pr_perror("RTC_IRQP_SET");
		close(fd);
		return -1;
	}

	criu_rtc__free_unpacked(e, NULL);

	if (ioctl(fd, RTC_PIE_ON, 0) == -1) {
		pr_perror("RTC_PIE_ON");
		close(fd);
		return -1;
	}

	return fd;
}
