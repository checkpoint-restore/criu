/* The mocked version of cuda-checkpoint. */
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int record_value(const char *environment, const char *value)
{
	const char *path = getenv(environment);
	FILE *file;

	if (!path)
		return 0;

	file = fopen(path, "a");
	if (!file) {
		perror("Unable to open CUDA CLI value marker");
		return -1;
	}
	fprintf(file, "%s\n", value);
	fclose(file);
	return 0;
}

static const char *read_state(void)
{
	static char state[32];
	const char *path = getenv("CRIU_CUDA_MOCK_STATE_FILE");
	FILE *file;
	size_t length;

	if (!path)
		return "running";

	file = fopen(path, "r");
	if (!file || !fgets(state, sizeof(state), file)) {
		if (file)
			fclose(file);
		return "running";
	}
	fclose(file);
	length = strcspn(state, "\r\n");
	state[length] = '\0';
	return state;
}

static int write_state(const char *state)
{
	const char *path = getenv("CRIU_CUDA_MOCK_STATE_FILE");
	FILE *file;

	if (!path)
		return 0;

	file = fopen(path, "w");
	if (!file) {
		perror("Unable to open CUDA CLI state file");
		return -1;
	}
	fprintf(file, "%s\n", state);
	fclose(file);
	return 0;
}

int main(int argc, char *argv[])
{
	const char *marker;
	const char *action = NULL;
	FILE *marker_file;
	int c;

	marker = getenv("CRIU_CUDA_MOCK_CLI_MARKER");
	if (marker) {
		marker_file = fopen(marker, "a");
		if (!marker_file) {
			perror("Unable to open CUDA CLI marker");
			return 1;
		}
		fputs("invoked\n", marker_file);
		fclose(marker_file);
	}

	if (getenv("CRIU_CUDA_MOCK_CLI_FAIL"))
		return 1;

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{ "pid", required_argument, 0, 'p' },
			{ "get-state", no_argument, 0, 's' },
			{ "get-restore-tid", no_argument, 0, 'g' },
			{ "action", required_argument, 0, 'a' },
			{ "timeout", required_argument, 0, 't' },
			{ "device-map", required_argument, 0, 'm' },
			{ "help", no_argument, 0, 'h' },
			{ 0, 0, 0, 0 }
		};

		c = getopt_long(argc, argv, "p:ga:ht:m:",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'p':
			printf("%s\n", optarg);
			break;
		case 'g':
		case 't':
			break;
		case 'a':
			action = optarg;
			marker = getenv("CRIU_CUDA_MOCK_LOCK_MARKER");
			if (marker && !strcmp(optarg, "lock")) {
				marker_file = fopen(marker, "a");
				if (!marker_file)
					return 1;
				fputs("lock\n", marker_file);
				fclose(marker_file);
			}
			break;
		case 'm':
			if (record_value("CRIU_CUDA_MOCK_DEVICE_MAP_MARKER", optarg))
				return 1;
			break;
		case 's':
			printf("%s\n", read_state());
			break;
		case 'h':
			printf("--action - execute an action\n");
			if (!getenv("CRIU_CUDA_MOCK_NO_DEVICE_MAP"))
				printf("--device-map - remap CUDA GPUs\n");
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

	if (action) {
		if (!strcmp(action, "lock") || !strcmp(action, "restore")) {
			if (write_state("locked"))
				return 1;
		} else if (!strcmp(action, "checkpoint")) {
			if (write_state("checkpointed"))
				return 1;
		} else if (!strcmp(action, "unlock")) {
			if (write_state("running"))
				return 1;
		}
	}

	return 0;
}
