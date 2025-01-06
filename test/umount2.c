#include <stdio.h>
#include <sys/mount.h>

int main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "umount PATH\n");
		return 1;
	}
	if (umount2(argv[1], MNT_DETACH)) {
		fprintf(stderr, "umount %s: %m\n", argv[1]);
		return 1;
	}

	return 0;
}
