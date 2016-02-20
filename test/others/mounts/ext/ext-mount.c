#include <sys/mount.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

#include "criu-plugin.h"
#include "criu-log.h"

#define IMG_NAME	"ext-mount-test-%d.img"

extern cr_plugin_init_t cr_plugin_init;
extern cr_plugin_dump_ext_mount_t cr_plugin_dump_ext_mount;
extern cr_plugin_restore_ext_mount_t cr_plugin_restore_ext_mount;

int cr_plugin_init(void)
{
	pr_info("Initialized ext mount c/r\n");
	return 0;
}

int cr_plugin_dump_ext_mount(char *mountpoint, int id)
{
	char *aux, *dst;
	int fd;
	char img[64];

	pr_info("Check for ext mount %s being mine\n", mountpoint);
	aux = strrchr(mountpoint, '/');
	if (!aux) {
		pr_err("Bad path provided\n");
		return -ENOTSUP;
	}

	dst = getenv("EMP_MOUNTPOINT");
	if (!dst) {
		pr_err("No EMP_MOUNTPOINT env\n");
		return -1;
	}

	if (strcmp(aux + 1, dst)) {
		pr_info("Not mine\n");
		return -ENOTSUP;
	}

	pr_info("Dumping my mount %d\n", id);
	sprintf(img, IMG_NAME, id);
	fd = openat(criu_get_image_dir(), img,
			O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) {
		pr_perror("Can't open image");
		return -1;
	}

	close(fd);
	return 0;
}

int cr_plugin_restore_ext_mount(int id, char *mountpoint, char *old_root, int *is_file)
{
	int fd;
	char img[64], src[256], *src_file;

	pr_info("Restoring my mount %d?\n", id);
	sprintf(img, IMG_NAME, id);
	fd = openat(criu_get_image_dir(), img, O_RDONLY);
	if (fd < 0) {
		if (errno == ENOENT)
			return -ENOTSUP;
		pr_perror("Can't open my image");
		return -1;
	}
	close(fd);

	src_file = getenv("EMP_ROOT_P");
	if (!src_file) {
		pr_err("Can't get EMP_ROOT_P env\n");
		return -1;
	}

	if (creat(mountpoint, 0600) < 0) {
		if (errno != EEXIST) {
			pr_perror("Can't make mountpoint");
			return -1;
		}
	}

	if (is_file)
		*is_file = 1;

	sprintf(src, "/%s/%s", old_root, src_file);
	pr_info("Mount %s -> %s\n", src, mountpoint);
	if (mount(src, mountpoint, NULL, MS_BIND, NULL) < 0) {
		pr_perror("Can't bind mount");
		return -1;
	}

	return 0;
}
