#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "zdtmtst.h"

const char *test_doc	= "Test that env/cmdline/auxv restored well\n";
const char *test_author	= "Cyrill Gorcunov <gorcunov@openvz.org";

static char *arg1, *arg2, *arg3;

TEST_OPTION(arg1, string, "arg1", 1);
TEST_OPTION(arg2, string, "arg2", 1);
TEST_OPTION(arg3, string, "arg3", 1);

static void read_from_proc(const char *path, char *buf, size_t size)
{
	size_t r = 0, ret;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		fail("Can't open cmdline\n");
		exit(1);
	}

	while (r < size) {
		ret = read(fd, buf + r, size - r);
		if (ret < 0) {
			err("Read failed");
			exit(1);
		} else if (ret == 0) {
			break;
		}

		r += ret;
	}
	close(fd);
}

int main(int argc, char *argv[])
{
	char cmdline_orig[4096];
	char cmdline[4096];
	char env_orig[4096];
	char env[4096];
	char auxv_orig[1024];
	char auxv[1024];

	memset(cmdline_orig,	0, sizeof(cmdline_orig));
	memset(cmdline,		0, sizeof(cmdline));
	memset(env_orig,	0, sizeof(env_orig));
	memset(env,		0, sizeof(env));
	memset(auxv_orig,	0, sizeof(auxv_orig));
	memset(auxv,		0, sizeof(auxv));

	test_init(argc, argv);

	read_from_proc("/proc/self/cmdline", cmdline_orig, sizeof(cmdline_orig));
	read_from_proc("/proc/self/environ", env_orig, sizeof(env_orig));
	read_from_proc("/proc/self/auxv", auxv_orig, sizeof(auxv_orig));

	test_msg("old cmdline: %s\n", cmdline_orig);
	test_msg("old environ: %s\n", env_orig);

	test_daemon();
	test_waitsig();

	read_from_proc("/proc/self/cmdline", cmdline, sizeof(cmdline));
	read_from_proc("/proc/self/environ", env, sizeof(env));
	read_from_proc("/proc/self/auxv", auxv, sizeof(auxv));

	test_msg("new cmdline: %s\n", cmdline);
	test_msg("new environ: %s\n", env);

	if (strncmp(cmdline_orig, cmdline, sizeof(cmdline_orig))) {
		fail("cmdline corrupted on restore");
		exit(1);
	}

	if (strncmp(env_orig, env, sizeof(env_orig))) {
		fail("envirion corrupted on restore");
		exit(1);
	}

	if (memcmp(auxv_orig, auxv, sizeof(auxv_orig))) {
		fail("auxv corrupted on restore");
		exit(1);
	}

	pass();

	return 0;
}
