#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <limits.h>

#include "log.h"
#include "crtools.h"

#include "common/xmalloc.h"

extern char **global_conf;
extern char **user_conf;

#define HELP_PASSED			1
#define DEFAULT_CONFIGS_FORBIDDEN	2

static int passed_help_or_defaults_forbidden(int argc, char *argv[])
{
	/*
	 * Check for --help / -h on commandline before parsing, otherwise
	 * the help message won't be displayed if there is an error in
	 * configuration file syntax. Checks are kept in parser in case of
	 * option being put in the configuration file itself.
	 *
	 * Check also whether default configfiles are forbidden to lower
	 * number of argv iterations, but checks for help have higher priority.
	 */
	int i, ret = 0;
	for (i = 0; i < argc; i++) {
		if ((!strcmp(argv[i], "--help")) || (!strcmp(argv[i], "-h")))
			return HELP_PASSED;
		if (!strcmp(argv[i], "--no-default-config"))
			ret = DEFAULT_CONFIGS_FORBIDDEN;
	}
	return ret;
}

static char * specific_config_passed(char *args[], int argc)
{
	int i;
	for (i = 0; i < argc; i++) {
		if (!strcmp(args[i], "--config")) {
			/* getopt takes next string as required argument automatically */
			return args[i + 1];
		} else if (strstr(args[i], "--config=") != NULL) {
			return args[i] + strlen("--config=");
		}
	}
	return NULL;
}

static int count_elements(char **to_count)
{
	int count = 0;
	if (to_count != NULL)
		while (to_count[count] != NULL)
			count++;
	return count;
}

static char ** parse_config(char *filepath)
{
#define DEFAULT_CONFIG_SIZE	10
	FILE* configfile = fopen(filepath, "r");
	int config_size = DEFAULT_CONFIG_SIZE;
	int i = 1, len = 0, offset;
	size_t limit = 0;
	bool was_newline;
	char *tmp_string, *line = NULL, *quoted, *quotedptr;
	char **configuration, **tmp_conf;

	if (!configfile) {
		return NULL;
	}
	configuration = xmalloc(config_size * sizeof(char *));
	if (configuration == NULL) {
		fclose(configfile);
		exit(1);
	}
	/*
	 * Initialize first element, getopt ignores it.
	 */
	configuration[0] = "criu";

	while ((len = getline(&line, &limit, configfile)) != -1) {
		offset = 0;
		was_newline = true;
		if (i >= config_size - 1) {
			config_size *= 2;
			tmp_conf = xrealloc(configuration, config_size * sizeof(char *));
			if (tmp_conf == NULL) {
				fclose(configfile);
				exit(1);
			}
			configuration = tmp_conf;
		}
		while (sscanf(line + offset, "%m[^ \t\n]s", &configuration[i]) == 1) {
			if (configuration[i][0] == '#') {
				if (sscanf(line, "%*[^\n]") != 0) {
					pr_err("Error while reading configuration file %s\n", filepath);
					fclose(configfile);
					exit(1);
				}
				configuration[i] = NULL;
				break;
			}
			if ((configuration[i][0] == '\"') && (strchr(line + offset + 1, '"'))) {
				/*
				 * Handle empty strings which strtok ignores
				 */
				if (!strcmp(configuration[i], "\"\"")) {
					configuration[i] = "";
					offset += strlen("\"\"");
				} else if ((configuration[i] = strtok_r(line + offset, "\"", &quotedptr))) {
					/*
					 * Handle escaping of quotes in quoted string
					 */
					while (configuration[i][strlen(configuration[i]) - 1] == '\\') {
						offset++;
						len = strlen(configuration[i]);
						configuration[i][len - 1] = '"';
						if (*quotedptr == '"') {
							quotedptr++;
							break;
						}
						quoted = strtok_r(NULL, "\"", &quotedptr);
						tmp_string = xmalloc(len + strlen(quoted) + 1);
						if (tmp_string == NULL) {
							fclose(configfile);
							exit(1);
						}
						memmove(tmp_string, configuration[i], len);
						memmove(tmp_string + len, quoted, strlen(quoted) + 1);
						configuration[i] = tmp_string;
					}
					offset += 2;
				}
			}
			offset += strlen(configuration[i]);
			if (was_newline) {
				was_newline = false;
				len = strlen(configuration[i]);
				tmp_string = xrealloc(configuration[i], len + strlen("--") + 1);
				if (tmp_string == NULL) {
					fclose(configfile);
					exit(1);
				}
				memmove(tmp_string + strlen("--"), tmp_string, len + 1);
				memmove(tmp_string, "--", strlen("--"));
				configuration[i] = tmp_string;
			}
			i++;
			while ((isspace(*(line + offset)) && (*(line + offset) != '\n'))) offset++;
		}
		line = NULL;
	}

	fclose(configfile);
	return configuration;
}

static void init_configuration(int argc, char *argv[], int defaults_forbidden)
{
	char *specific_conf = specific_config_passed(argv, argc);
	char local_filepath[PATH_MAX + 1];
	char *home_dir = getenv("HOME");

	if ((specific_conf == NULL) && (!defaults_forbidden)) {
		global_conf = parse_config(GLOBAL_CONFIG_DIR DEFAULT_CONFIG_FILENAME);
		if (!home_dir) {
			pr_info("Unable to get $HOME directory, local configuration file will not be used.");
		} else {
			snprintf(local_filepath, PATH_MAX, "%s/%s%s",
					home_dir, USER_CONFIG_DIR, DEFAULT_CONFIG_FILENAME);
			user_conf = parse_config(local_filepath);
		}
	} else if (specific_conf != NULL) {
		global_conf = parse_config(specific_conf);
		if (global_conf == NULL) {
			pr_err("Can't access configuration file %s.\n", specific_conf);
			exit(1);
		}
	}
}

void init_config(int argc, char **argv, int *first_count, int *second_count)
{
	int help_or_configs;
	bool usage_error;

	help_or_configs = passed_help_or_defaults_forbidden(argc, argv);
	if (help_or_configs == 1) {
		usage_error = false;
		printf("goto usage: %d\n", usage_error);
		return;
	}

	init_configuration(argc, argv, (help_or_configs == DEFAULT_CONFIGS_FORBIDDEN));
	if (global_conf != NULL)
		*first_count = count_elements(global_conf);
	if (user_conf != NULL)
		*second_count = count_elements(user_conf);
}
