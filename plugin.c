#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>

#include "cr_options.h"
#include "plugin.h"
#include "log.h"
#include "xmalloc.h"

struct cr_plugin_entry {
	union {
		cr_plugin_fini_t *cr_fini;
	};

	struct cr_plugin_entry *next;
};

struct cr_plugins {
	struct cr_plugin_entry *cr_fini;
};

struct cr_plugins cr_plugins;

static int cr_lib_load(char *path)
{
	struct cr_plugin_entry *ce;
	cr_plugin_init_t *f_init;
	cr_plugin_fini_t *f_fini;
	void *h;

	h = dlopen(path, RTLD_LAZY);
	if (h == NULL) {
		pr_err("Unable to load %s: %s", path, dlerror());
		return -1;
	}

	ce = NULL;
	f_fini = dlsym(h, "cr_plugin_fini");
	if (f_fini) {
		ce = xmalloc(sizeof(struct cr_plugin_entry));
		if (ce == NULL)
			return -1;
		ce->cr_fini = f_fini;
	}

	f_init = dlsym(h, "cr_plugin_init");
	if (f_init && f_init()) {
		xfree(ce);
		return -1;
	}

	if (ce) {
		ce->next = cr_plugins.cr_fini;
		cr_plugins.cr_fini = ce;
	}

	return 0;
}

void cr_plugin_fini(void)
{
	struct cr_plugin_entry *ce;

	while (cr_plugins.cr_fini) {
		ce = cr_plugins.cr_fini;
		cr_plugins.cr_fini = cr_plugins.cr_fini->next;

		ce->cr_fini();
		xfree(ce);
	}
}

int cr_plugin_init(void)
{
	int exit_code = -1;
	char *path;
	DIR *d;

	memset(&cr_plugins, 0, sizeof(cr_plugins));

	if (opts.libdir == NULL) {
		path = getenv("CRIU_LIBS_DIR");
		if (path) {
			opts.libdir = strdup(path);
		} else {
			if (access(CR_PLUGIN_DEFAULT, F_OK))
				return 0;
			opts.libdir = strdup(CR_PLUGIN_DEFAULT);
		}
		if (opts.libdir == NULL) {
			pr_perror("Can't allocate memory");
			return -1;
		}
	}

	d = opendir(opts.libdir);
	if (d == NULL) {
		pr_perror("Unable to open directory %s", opts.libdir);
		return -1;
	}

	while (1) {
		char path[PATH_MAX];
		struct dirent *de;
		int len;

		errno = 0;
		de = readdir(d);
		if (de == NULL) {
			if (errno == 0)
				break;
			pr_perror("Unable to read the libraries directory");
			goto err;
		}

		len = strlen(de->d_name);

		if (len < 3 || strncmp(de->d_name + len - 3, ".so", 3))
			continue;

		snprintf(path, sizeof(path), "%s/%s", opts.libdir, de->d_name);

		if (cr_lib_load(path))
			goto err;
	}

	exit_code = 0;
err:
	closedir(d);

	if (exit_code)
		cr_plugin_fini();

	return exit_code;
}
