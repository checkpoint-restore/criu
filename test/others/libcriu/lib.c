#include <stdio.h>
#include <errno.h>
#include <sys/wait.h>

#include "criu.h"

void what_err_ret_mean(int ret)
{
	/* NOTE: errno is set by libcriu */
	switch (ret) {
	case -EBADE:
		perror("RPC has returned fail");
		break;
	case -ECONNREFUSED:
		perror("Unable to connect to CRIU");
		break;
	case -ECOMM:
		perror("Unable to send/recv msg to/from CRIU");
		break;
	case -EINVAL:
		perror("CRIU doesn't support this type of request."
		       "You should probably update CRIU");
		break;
	case -EBADMSG:
		perror("Unexpected response from CRIU."
		       "You should probably update CRIU");
		break;
	default:
		perror("Unknown error type code."
		       "You should probably update CRIU");
	}
}

int chk_exit(int status, int want)
{
	if (WIFEXITED(status)) {
		if (WEXITSTATUS(status) == want)
			return 0;

		printf("   `- FAIL (exit %d)\n", WEXITSTATUS(status));
	} else if (WIFSIGNALED(status))
		printf("   `- FAIL (die %d)\n", WTERMSIG(status));
	else
		printf("   `- FAIL (%#x)\n", status);

	return 1;
}

int get_version()
{
	printf("Using a CRIU binary with version %d\n", criu_get_version());
}
