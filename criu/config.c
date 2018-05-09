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
		while (1) {
			while ((isspace(*(line + offset)) && (*(line + offset) != '\n'))) offset++;

			if (sscanf(line + offset, "%m[^ \t\n]s", &configuration[i]) != 1) {
				configuration[i] = NULL;
				break;
			}

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
		}
		line = NULL;
	}

	fclose(configfile);
	return configuration;
}

static void init_configuration(int argc, char *argv[], bool no_default_config,
			       char *cfg_file)
{
	char local_filepath[PATH_MAX + 1];
	char *home_dir = getenv("HOME");

	if ((cfg_file == NULL) && (!no_default_config)) {
		global_conf = parse_config(GLOBAL_CONFIG_DIR DEFAULT_CONFIG_FILENAME);
		if (!home_dir) {
			pr_info("Unable to get $HOME directory, local configuration file will not be used.");
		} else {
			snprintf(local_filepath, PATH_MAX, "%s/%s%s",
					home_dir, USER_CONFIG_DIR, DEFAULT_CONFIG_FILENAME);
			user_conf = parse_config(local_filepath);
		}
	} else if (cfg_file != NULL) {
		global_conf = parse_config(cfg_file);
		if (global_conf == NULL) {
			pr_err("Can't access configuration file %s.\n", cfg_file);
			exit(1);
		}
	}
}

int init_config(int argc, char **argv, int *global_cfg_argc, int *user_cfg_argc,
		bool *usage_error)
{
	bool no_default_config = false;
	char *cfg_file = NULL;
	int i;

	/*
	 * We are runnning before getopt(), so we need to pre-parse
	 * the command line.
	 *
	 * Check for --help / -h on commandline before parsing, otherwise
	 * the help message won't be displayed if there is an error in
	 * configuration file syntax. Checks are kept in parser in case of
	 * option being put in the configuration file itself.
	 *
	 * Check also whether default configfiles are forbidden to lower
	 * number of argv iterations, but checks for help have higher priority.
	 */
	for (i = 0; i < argc; i++) {
		if ((!strcmp(argv[i], "--help")) || (!strcmp(argv[i], "-h"))) {
			*usage_error = false;
			return 1;
		} else if (!strcmp(argv[i], "--no-default-config")) {
			no_default_config = true;
		} else if (!strcmp(argv[i], "--config")) {
			/*
			 * getopt takes next string as required
			 * argument automatically, we do the same
			 */
			cfg_file = argv[i + 1];
		} else if (strstr(argv[i], "--config=") != NULL) {
			cfg_file = argv[i] + strlen("--config=");
		}
	}

	init_configuration(argc, argv, no_default_config, cfg_file);
	if (global_conf != NULL)
		*global_cfg_argc = count_elements(global_conf);
	if (user_conf != NULL)
		*user_cfg_argc = count_elements(user_conf);

	return 0;
}
