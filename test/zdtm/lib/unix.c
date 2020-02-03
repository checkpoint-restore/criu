#include <sys/socket.h>
#include <sys/un.h>
#include "zdtmtst.h"
#include "fs.h"

int unix_fill_sock_name(struct sockaddr_un *name, char *relFilename)
{
	char *cwd;

	if (get_cwd_check_perm(&cwd)) {
		pr_err("failed to get current working directory with valid permissions.\n");
		return -1;
	}

	name->sun_family = AF_LOCAL;
	ssprintf(name->sun_path, "%s/%s", cwd, relFilename);
	return 0;
}

