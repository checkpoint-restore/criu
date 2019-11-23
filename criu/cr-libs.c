#include <dlfcn.h>
#include <link.h>
#include <linux/limits.h>
#include <stdio.h>
#include <unistd.h>

#include "common/compiler.h"
#include "cr-libs.h"
#include "log.h"

struct so_desc {
	const char	*so_name;
	const char	*warning;

	/*
	 * You have to specify major version to make sure that ABI
	 * version of library is the required.
	 */
	const unsigned	major;
	/* other major versions supported */
	const unsigned	*also_supported;
	const size_t	also_supported_sz;

	/* Set up on load */
	void		*so_handle;
	unsigned	loaded_major;
};
static struct so_desc crlibs[SHARED_LIB_LAST] = {
};

static void *try_load_name_version(const char *so_name, const unsigned major)
{
	char buf[PATH_MAX];
	void *ret;

	snprintf(buf, ARRAY_SIZE(buf), "%s.%u", so_name, major);

	ret = dlopen(buf, RTLD_LAZY);
	if (ret)
		pr_debug("Loaded `%s' succesfully\n", buf);

	return ret;
}

static void try_load_lib(struct so_desc *lib)
{
	size_t i;

	lib->so_handle = try_load_name_version(lib->so_name, lib->major);
	if (lib->so_handle) {
		lib->loaded_major = lib->major;
		return;
	}

	for (i = 0; i < lib->also_supported_sz; i++) {
		unsigned ver = lib->also_supported[i];

		lib->so_handle = try_load_name_version(lib->so_name, ver);
		if (lib->so_handle) {
			lib->loaded_major = ver;
			return;
		}
	}

	print_once(LOG_INFO, "CRIU functionality may be limited\n");
	pr_info("Can't load a shared library %s: %s\n", lib->so_name, dlerror());
	if (lib->warning)
		pr_info("%s: %s\n", lib->so_name, lib->warning);
}

void shared_libs_load(void)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(crlibs); i++)
		try_load_lib(&crlibs[i]);
}

void shared_libs_unload(void)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(crlibs); i++) {
		struct so_desc *lib = &crlibs[i];

		if (lib->so_handle == NULL)
			continue;

		if (dlclose(lib->so_handle))
			pr_warn("Failed to unload `%s': %s\n",
				lib->so_name, dlerror());
		lib->so_handle = NULL;
	}
}

void *shared_libs_lookup(enum shared_libs id, const char *func)
{
	struct so_desc *lib;
	void *ret;

	if (id > SHARED_LIB_LAST) {
		pr_err("BUG: shared library id is too big: %u\n", id);
		return NULL;
	}

	lib = &crlibs[id];
	if (lib->so_handle == NULL)
		return NULL;

	ret = dlsym(lib->so_handle, func);
	if (ret == NULL)
		pr_debug("Can't find `%s' function in %s\n", func, lib->so_name);

	return ret;
}

int shared_libs_major(enum shared_libs id, unsigned *major)
{
	struct so_desc *lib;

	if (id > SHARED_LIB_LAST) {
		pr_err("BUG: shared library id is too big: %u\n", id);
		return -1;
	}

	lib = &crlibs[id];
	if (lib->so_handle == NULL)
		return -1;

	*major = lib->loaded_major;
	return 0;
}
