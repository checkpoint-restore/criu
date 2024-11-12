/* The mocked version of cuda-checkpoint. */
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
	int c;

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{ "pid", required_argument, 0, 'p' },
			{ "get-state", no_argument, 0, 's' },
			{ "get-restore-tid", no_argument, 0, 'g' },
			{ "action", required_argument, 0, 'a' },
			{ "timeout", required_argument, 0, 't' },
			{ "help", no_argument, 0, 'h' },
			{ 0, 0, 0, 0 }
		};

		c = getopt_long(argc, argv, "p:ga:ht:",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'p':
			printf("%s\n", optarg);
			break;
		case 'g':
		case 'a':
		case 't':
			break;
		case 's':
			printf("running\n");
			break;
		case 'h':
			printf("--action - execute an action");
			break;

		default:
			fprintf(stderr, "getopt returned character code 0%o ??\n", c);
			return 1;
		}
	}

	if (optind < argc) {
		fprintf(stderr, "non-option ARGV-elements: ");
		while (optind < argc)
			fprintf(stderr, "%s ", argv[optind++]);
		fprintf(stderr, "\n");
		return 1;
	}

	return 0;
}
