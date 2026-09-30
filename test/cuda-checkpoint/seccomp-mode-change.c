/*
 * Target of seccomp-mode-change.sh. The mocked CUDA driver reports the only
 * thread of this task as the CUDA restore thread, which the CUDA plugin lets
 * run during the checkpoint action. When the mock starts that action (it
 * appends "checkpoint" to the API marker, argv[1]), the thread installs a
 * seccomp filter that denies only uname() and creates argv[2], which lets the
 * mock finish the action. Whenever argv[2] is missing after that, the thread
 * creates it again if uname() still fails with EPERM, so that the test can
 * check that the task still runs with its filter.
 */
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

static int checkpoint_started(const char *marker)
{
	char line[256];
	int found = 0;
	FILE *file;

	file = fopen(marker, "r");
	if (!file)
		return 0;
	while (fgets(line, sizeof(line), file))
		if (!strncmp(line, "checkpoint ", strlen("checkpoint ")))
			found = 1;
	fclose(file);
	return found;
}

static int install_filter(void)
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_uname, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog program = {
		.len = sizeof(filter) / sizeof(filter[0]),
		.filter = filter,
	};

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
		return -1;
	return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program);
}

int main(int argc, char **argv)
{
	struct utsname name;
	int installed = 0;
	int fd;

	if (argc != 3)
		return 2;

	while (1) {
		if (!installed && checkpoint_started(argv[1])) {
			if (install_filter())
				return 1;
			installed = 1;
		}
		if (installed && access(argv[2], F_OK)) {
			if (uname(&name) != -1 || errno != EPERM)
				return 1;
			fd = open(argv[2], O_CREAT | O_WRONLY, 0600);
			if (fd < 0 || close(fd))
				return 1;
		}
		usleep(10000);
	}
}
