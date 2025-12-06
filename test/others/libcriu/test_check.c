#include <stdio.h>
#include "criu.h"
#include "lib.h"

int main(int argc, char **argv)
{
	int ret;

	printf("--- Start check ---\n");
	criu_init_opts();
	criu_set_service_binary(argv[1]);

	if (criu_check())
		return -1;

	return 0;
}
