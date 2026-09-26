#include "criu.h"
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "lib.h"

/*
 * Check that the TLS options exposed by libcriu are actually applied to the
 * page server connection.
 *
 * The test runs two dumps against a page server that requires TLS:
 *
 *   1. with the libcriu TLS options set    -> the dump must succeed;
 *   2. without the libcriu TLS options set -> the dump must fail and the
 *      page server must report a failed TLS handshake.
 *
 * The second case is what makes the first one meaningful: the only
 * difference between the two runs is the libcriu TLS configuration, so a
 * successful first run cannot be explained by the page server silently
 * accepting a plaintext connection.
 */

#define PS_PORT_OK 27015
#define PS_PORT_NG 27016

#define PKI_DIR "../../pki"

static char *criu_binary;
static char *images_dir;

/*
 * CRIU changes its working directory to the images directory, so every path
 * handed to it has to be absolute.
 */
static char pki_key[PATH_MAX];
static char pki_cert[PATH_MAX];
static char pki_cacert[PATH_MAX];

static int resolve_pki(void)
{
	struct {
		const char *name;
		char *dst;
	} files[] = {
		{ PKI_DIR "/key.pem", pki_key },
		{ PKI_DIR "/cert.pem", pki_cert },
		{ PKI_DIR "/cacert.pem", pki_cacert },
	};
	size_t i;

	for (i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
		if (!realpath(files[i].name, files[i].dst)) {
			fprintf(stderr, "Can't resolve %s: %s\n", files[i].name, strerror(errno));
			return -1;
		}
	}

	return 0;
}

/*
 * Start "criu page-server" with TLS enabled. Returns 0 on success, the
 * server daemonizes itself and is reaped by init.
 */
static int start_tls_page_server(int port, const char *log_file)
{
	char port_str[16], images[PATH_MAX], status_str[16];
	int status, pid, p[2];
	char c;

	snprintf(port_str, sizeof(port_str), "%d", port);
	snprintf(images, sizeof(images), "%s", images_dir);

	/*
	 * The page server serves a single client, so its readiness cannot be
	 * probed by connecting to it. Use --status-fd instead: CRIU writes a
	 * zero byte to it once the server is ready to handle requests.
	 */
	if (pipe(p)) {
		perror("Can't create a status pipe");
		return -1;
	}
	snprintf(status_str, sizeof(status_str), "%d", p[1]);

	pid = fork();
	if (pid < 0) {
		perror("Can't fork a page server");
		close(p[0]);
		close(p[1]);
		return -1;
	}

	if (!pid) {
		close(p[0]);
		execl(criu_binary, "criu", "page-server", "--images-dir", images, "--port", port_str, "--daemon",
		      "--status-fd", status_str, "--tls", "--tls-no-cn-verify", "--tls-key", pki_key, "--tls-cert",
		      pki_cert, "--tls-cacert", pki_cacert, "--log-file", log_file, "-v4", NULL);
		perror("Can't exec the page server");
		exit(1);
	}

	close(p[1]);

	/*
	 * --daemon makes the page server fork and the parent exit, so the
	 * process we spawned here returns as soon as the server is started.
	 */
	if (waitpid(pid, &status, 0) < 0) {
		perror("Can't wait for the page server");
		close(p[0]);
		return -1;
	}

	if (chk_exit(status, 0)) {
		close(p[0]);
		return -1;
	}

	if (read(p[0], &c, 1) != 1 || c != 0) {
		printf("Page server did not report readiness on port %d\n", port);
		close(p[0]);
		return -1;
	}

	close(p[0]);
	return 0;
}

/* Start a process that just waits to be dumped. */
static int start_victim(int *victim_pid)
{
	int p[2], pid, ret;

	if (pipe(p)) {
		perror("Can't create a pipe");
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		perror("Can't fork a victim");
		return -1;
	}

	if (!pid) {
		if (setsid() < 0)
			exit(1);

		close(0);
		close(1);
		close(2);
		close(p[0]);

		ret = SUCC_ECODE;
		if (write(p[1], &ret, sizeof(ret)) != sizeof(ret))
			exit(1);
		close(p[1]);

		while (1)
			sleep(1);
		exit(1);
	}

	close(p[1]);

	ret = -1;
	if (read(p[0], &ret, sizeof(ret)) != sizeof(ret) || ret != SUCC_ECODE) {
		printf("Error starting the victim process\n");
		close(p[0]);
		return -1;
	}
	close(p[0]);

	*victim_pid = pid;
	return 0;
}

static int set_tls_opts(void)
{
	criu_set_tls(true);
	criu_set_tls_no_cn_verify(true);

	if (criu_set_tls_key(pki_key))
		return -1;

	if (criu_set_tls_cert(pki_cert))
		return -1;

	if (criu_set_tls_cacert(pki_cacert))
		return -1;

	return 0;
}

static int dump_via_page_server(int victim_pid, int port, const char *log_file, bool use_tls)
{
	int fd, ret;

	criu_init_opts();
	criu_set_service_binary(criu_binary);
	criu_set_pid(victim_pid);
	criu_set_log_file((char *)log_file);
	criu_set_log_level(CRIU_LOG_DEBUG);

	fd = open(images_dir, O_DIRECTORY);
	if (fd < 0) {
		perror("Can't open the images dir");
		return -1;
	}
	criu_set_images_dir_fd(fd);

	if (criu_set_page_server_address_port("127.0.0.1", port)) {
		printf("Can't set the page server address\n");
		close(fd);
		return -1;
	}

	if (use_tls && set_tls_opts()) {
		printf("Can't set the TLS options\n");
		close(fd);
		return -1;
	}

	ret = criu_dump();
	close(fd);
	return ret;
}

/* Check that the page server log reports a failed TLS handshake. */
static int page_server_saw_handshake_failure(const char *log_file)
{
	char path[PATH_MAX], line[512];
	int found = 0;
	FILE *f;

	snprintf(path, sizeof(path), "%s/%s", images_dir, log_file);

	f = fopen(path, "r");
	if (!f) {
		perror("Can't open the page server log");
		return 0;
	}

	while (fgets(line, sizeof(line), f)) {
		if (strstr(line, "TLS handshake failed")) {
			found = 1;
			break;
		}
	}

	fclose(f);
	return found;
}

int main(int argc, char **argv)
{
	int victim_pid, ret;

	if (argc < 3) {
		printf("Usage: %s <criu-binary> <images-dir>\n", argv[0]);
		return 1;
	}

	criu_binary = argv[1];
	images_dir = argv[2];

	if (resolve_pki())
		return 1;

	printf("--- Dump through a TLS page server, TLS configured ---\n");

	if (start_tls_page_server(PS_PORT_OK, "ps-tls.log"))
		return 1;

	if (start_victim(&victim_pid))
		return 1;

	ret = dump_via_page_server(victim_pid, PS_PORT_OK, "dump-tls.log", true);
	if (ret < 0) {
		what_err_ret_mean(ret);
		printf("   `- FAIL: dump with TLS configured did not succeed\n");
		kill(victim_pid, SIGKILL);
		waitpid(victim_pid, NULL, 0);
		return 1;
	}

	printf("   `- Dump succeeded\n");
	kill(victim_pid, SIGKILL);
	waitpid(victim_pid, NULL, 0);

	printf("--- Dump through a TLS page server, TLS not configured ---\n");

	if (start_tls_page_server(PS_PORT_NG, "ps-plain.log"))
		return 1;

	if (start_victim(&victim_pid))
		return 1;

	ret = dump_via_page_server(victim_pid, PS_PORT_NG, "dump-plain.log", false);
	kill(victim_pid, SIGKILL);
	waitpid(victim_pid, NULL, 0);

	if (ret >= 0) {
		printf("   `- FAIL: dump without TLS reached a TLS-only page server\n");
		return 1;
	}

	if (!page_server_saw_handshake_failure("ps-plain.log")) {
		printf("   `- FAIL: page server did not report a TLS handshake failure\n");
		return 1;
	}

	printf("   `- Dump failed on the TLS handshake, as expected\n");
	printf("--- Test passed ---\n");

	return 0;
}
