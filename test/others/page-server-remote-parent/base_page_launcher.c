/* The generation oracle assumes base-page dirty tracking granularity. */
#include <stdio.h>
#include <sys/prctl.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: base-page-launcher command [args ...]\n");
		return 2;
	}
	/* Inherited across fork/exec; no system-wide THP setting is changed. */
	if (prctl(PR_SET_THP_DISABLE, 1, 0, 0, 0)) {
		perror("prctl(PR_SET_THP_DISABLE)");
		return 1;
	}
	execvp(argv[1], &argv[1]);
	perror("execvp");
	return 1;
}
