#include "criu-log.h"
#include "cuda_device_map.h"
#include "cuda_plugin.h"
#include "image.h"
#include "plugin.h"
#include "fault-injection.h"
#include "seize.h"

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif
#define LOG_PREFIX "cuda_plugin: "

#define CUDA_PLUGIN_NAME	      "cuda_plugin"
#define CUDA_PLUGIN_BACKEND_OPTION    CUDA_PLUGIN_NAME ".backend"
#define CUDA_PLUGIN_DEVICE_MAP_OPTION CUDA_PLUGIN_NAME ".device-map"
#define CUDA_PLUGIN_TIMEOUT_OPTION    CUDA_PLUGIN_NAME ".timeout"

unsigned int cuda_plugin_timeout;

static const struct cuda_plugin_backend *active_backend;
static char *device_map_option;
static struct cuda_device_map restore_device_map;
static bool cuda_tasks_handled;

enum cuda_backend_selection {
	CUDA_BACKEND_AUTO,
	CUDA_BACKEND_DRIVER_API,
	CUDA_BACKEND_CHECKPOINT,
};

static enum cuda_backend_selection backend_selection;

enum {
	CUDA_PLUGIN_OPTION_BACKEND = 1000,
	CUDA_PLUGIN_OPTION_DEVICE_MAP,
	CUDA_PLUGIN_OPTION_TIMEOUT,
};

static bool cuda_plugin_option_matches(const char *arg, const char *name,
				       const char *optarg_val, int *err)
{
	size_t len = strlen(name);

	if (strncmp(arg, "--", 2) || strncmp(arg + 2, name, len))
		return false;

	if (arg[len + 2] == '\0') {
		pr_err("%s requires a value\n", arg);
		*err = -EINVAL;
		return false;
	}

	return arg[len + 2] == '=' && optarg_val != NULL;
}

static int parse_cuda_backend_option(const char *value)
{
	if (!strcmp(value, "auto"))
		return 0;
	if (!strcmp(value, "driver-api")) {
		backend_selection = CUDA_BACKEND_DRIVER_API;
		return 0;
	}
	if (!strcmp(value, "cuda-checkpoint")) {
		backend_selection = CUDA_BACKEND_CHECKPOINT;
		return 0;
	}

	pr_err("Invalid cuda_plugin.backend value '%s' (expected auto, driver-api, or cuda-checkpoint)\n",
	       value);
	return -EINVAL;
}

/*
 * Parse this plugin's own "--plugin-option=cuda_plugin.NAME=VALUE" options
 * out of the full, shared option vector returned by
 * criu_plugin_get_options(). Every plugin sees the same argv, so the loop
 * below has to recognize its own options, ignore everyone else's (they show
 * up as getopt_long()'s '?' return, since only *our* long_options[] entries
 * are registered here), and leave getopt's global parsing state exactly as
 * it found it for the caller.
 *
 * The parse is split into two passes on purpose:
 *   1. The getopt_long() loop below only *collects* the raw string value of
 *      each recognized option (backend_value / device_map_value /
 *      timeout_value) and records the first parse error, if any.
 *   2. Once the loop finishes and getopt's globals are restored, each
 *      collected value is validated and applied in a fixed order (backend,
 *      then timeout, then device-map).
 * This keeps getopt_long()'s reentrancy quirks (optind/optarg/opterr/optopt
 * are process-wide globals) isolated to the loop, and lets device-map
 * validation run after backend_selection/cuda_plugin_timeout already hold
 * their final values, without caring which order the options appeared on
 * the command line.
 *
 * "stage" is one of the CR_PLUGIN_STAGE__* values (dump vs restore); it is
 * only used to reject cuda_plugin.device-map outside of restore, since a
 * device map has no meaning while dumping.
 */
static int parse_cuda_plugin_options(int stage)
{
	static const struct option long_options[] = {
		{ CUDA_PLUGIN_BACKEND_OPTION, optional_argument, NULL, CUDA_PLUGIN_OPTION_BACKEND },
		{ CUDA_PLUGIN_DEVICE_MAP_OPTION, optional_argument, NULL, CUDA_PLUGIN_OPTION_DEVICE_MAP },
		{ CUDA_PLUGIN_TIMEOUT_OPTION, optional_argument, NULL, CUDA_PLUGIN_OPTION_TIMEOUT },
		{},
	};
	/* Raw values collected during the getopt_long() pass below; NULL
	 * means "the option was not given" (defaults already apply).
	 */
	const char *backend_value = NULL;
	const char *device_map_value = NULL;
	const char *timeout_value = NULL;
	/* getopt_long()'s parsing state is held in process-wide globals, and
	 * every plugin re-parses the same argv, so we must save and restore
	 * them around our own pass rather than leaving them wherever we
	 * stopped.
	 */
	char *saved_optarg;
	char **argv = NULL;
	int saved_optopt;
	int saved_opterr;
	int saved_optind;
	int argc;
	int option;
	int ret = 0;

	/* Reset to defaults on every call: this plugin is (re-)initialized
	 * once per dump/restore, and a previous invocation's values must not
	 * leak into this one.
	 */
	backend_selection = CUDA_BACKEND_AUTO;
	cuda_plugin_timeout = 300;
	ret = criu_plugin_get_options(&argc, &argv);
	if (ret) {
		pr_err("Unable to read plugin options: %d\n", ret);
		return ret;
	}

	saved_optarg = optarg;
	saved_optopt = optopt;
	saved_opterr = opterr;
	saved_optind = optind;
	/* Suppress getopt_long()'s own "unrecognized option" messages: an
	 * option belonging to another plugin is expected and silently
	 * skipped via the '?' case below, not an error here.
	 */
	opterr = 0;
	optind = 0;
	while ((option = getopt_long(argc, argv, "", long_options, NULL)) != -1) {
		switch (option) {
		case CUDA_PLUGIN_OPTION_BACKEND:
			/* cuda_plugin_option_matches() rejects a bare
			 * "--cuda_plugin.backend" with no "=value" (setting
			 * *ret), which getopt_long() alone cannot express
			 * for an optional_argument option.
			 */
			if (cuda_plugin_option_matches(argv[optind - 1],
						       CUDA_PLUGIN_BACKEND_OPTION,
						       optarg, &ret))
				backend_value = optarg;
			break;
		case CUDA_PLUGIN_OPTION_DEVICE_MAP:
			if (cuda_plugin_option_matches(argv[optind - 1],
						       CUDA_PLUGIN_DEVICE_MAP_OPTION,
						       optarg, &ret))
				device_map_value = optarg;
			break;
		case CUDA_PLUGIN_OPTION_TIMEOUT:
			if (cuda_plugin_option_matches(argv[optind - 1], CUDA_PLUGIN_TIMEOUT_OPTION, optarg, &ret))
				timeout_value = optarg;
			break;
		case '?':
			/* Every plugin receives the same namespaced option list. */
			break;
		default:
			break;
		}
		if (ret)
			break;
	}
	optarg = saved_optarg;
	optopt = saved_optopt;
	opterr = saved_opterr;
	optind = saved_optind;

	if (ret)
		goto out;

	/* Second pass: validate and apply whatever was collected above. */

	if (backend_value) {
		ret = parse_cuda_backend_option(backend_value);
		if (ret)
			goto out;
	}

	if (timeout_value) {
		char *end;
		unsigned long timeout;

		/* strtoul() alone would silently accept a leading '-' or an
		 * empty/garbage string as 0; the extra checks make sure the
		 * whole value was consumed and is a genuine positive integer.
		 */
		errno = 0;
		timeout = strtoul(timeout_value, &end, 10);
		if (errno || timeout_value[0] < '0' || timeout_value[0] > '9' || *end || !timeout || timeout > UINT_MAX) {
			pr_err("Invalid cuda_plugin.timeout value '%s' (expected positive seconds)\n", timeout_value);
			ret = -EINVAL;
			goto out;
		}
		cuda_plugin_timeout = timeout;
	}

	if (device_map_value) {
		if (stage != CR_PLUGIN_STAGE__RESTORE) {
			pr_err("cuda_plugin.device-map is valid only during restore\n");
			ret = -EINVAL;
			goto out;
		}

		ret = cuda_device_map_validate(device_map_value);
		if (ret)
			goto out;

		/* Ownership: device_map_option is a global, consumed later
		 * (once the GPU inventory is available) by
		 * cuda_device_map_resolve(); it outlives this function.
		 */
		device_map_option = strdup(device_map_value);
		if (!device_map_option) {
			pr_err("Unable to allocate CUDA device-map option\n");
			ret = -ENOMEM;
		}
	}

out:
	return ret;
}

static bool is_cuda_device_available(void)
{
	const char *gpu_path = "/proc/driver/nvidia/gpus/";
	struct stat sb;

	if (stat(gpu_path, &sb) != 0)
		return false;

	return S_ISDIR(sb.st_mode);
}

static int select_cuda_backend(void)
{
	int ret;
	const struct cuda_plugin_backend *requested_backend;

	requested_backend = NULL;
	if (backend_selection == CUDA_BACKEND_DRIVER_API)
		requested_backend = &cuda_driver_backend;
	else if (backend_selection == CUDA_BACKEND_CHECKPOINT)
		requested_backend = &cuda_cli_backend;

	if (requested_backend) {
		ret = requested_backend->probe(device_map_option != NULL);
		if (ret) {
			pr_err("Requested %s backend is unavailable: %d\n", requested_backend->name, ret);
			return ret;
		}

		active_backend = requested_backend;
		return 0;
	}

	ret = cuda_driver_backend.probe(device_map_option != NULL);
	if (!ret) {
		active_backend = &cuda_driver_backend;
		return 0;
	}
	if (ret != -ENOTSUP) {
		pr_err("Unable to probe %s backend: %d\n", cuda_driver_backend.name, ret);
		return ret;
	}

	pr_info("%s backend is unsupported; probing %s backend\n",
		cuda_driver_backend.name, cuda_cli_backend.name);

	ret = cuda_cli_backend.probe(device_map_option != NULL);
	if (!ret) {
		active_backend = &cuda_cli_backend;
		return 0;
	}
	if (ret != -ENOTSUP) {
		pr_err("Unable to probe %s backend: %d\n", cuda_cli_backend.name, ret);
		return ret;
	}

	pr_info("No supported CUDA checkpoint backend is available\n");
	return -ENOTSUP;
}

int cuda_plugin_add_inventory(void)
{
	if (!cuda_tasks_handled) {
		if (add_inventory_plugin(CR_PLUGIN_DESC.name)) {
			pr_err("Failed to add CUDA plugin to inventory image\n");
			return -1;
		}
		cuda_tasks_handled = true;
	}

	return 0;
}

static int cuda_plugin_pause_devices(int pid)
{
	if (!active_backend)
		return -ENOTSUP;

	return active_backend->pause_devices(pid);
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__PAUSE_DEVICES, cuda_plugin_pause_devices)

static int cuda_plugin_checkpoint_devices(int pid)
{
	if (!active_backend)
		return -ENOTSUP;

	return active_backend->checkpoint_devices(pid);
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__CHECKPOINT_DEVICES, cuda_plugin_checkpoint_devices);

static int cuda_plugin_resume_devices_late(int pid)
{
	if (!active_backend)
		return -ENOTSUP;

	return active_backend->resume_devices_late(pid, &restore_device_map);
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RESUME_DEVICES_LATE, cuda_plugin_resume_devices_late)

static int cuda_plugin_dump_devices_late(int id)
{
	int ret;

	(void)id;

	if (!active_backend || !cuda_tasks_handled)
		return -ENOTSUP;

	ret = cuda_gpu_inventory_dump();
	if (ret == -ENOTSUP) {
		pr_err("Unable to save required CUDA GPU inventory\n");
		return -EIO;
	}

	return ret;
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__DUMP_DEVICES_LATE, cuda_plugin_dump_devices_late)

static int cuda_plugin_restore_init(void)
{
	int ret;

	if (!active_backend)
		return -ENOTSUP;

	ret = cuda_gpu_inventory_restore_init();
	if (ret)
		goto out;

	ret = cuda_device_map_resolve(device_map_option, &restore_device_map);
out:
	if (ret == -ENOTSUP) {
		pr_err("Unable to prepare required CUDA GPU mapping state\n");
		return -EIO;
	}

	return ret;
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RESTORE_INIT, cuda_plugin_restore_init)

static int cuda_plugin_init(int stage)
{
	bool restore_required = false;
	int ret;

	active_backend = NULL;
	cuda_tasks_handled = false;
	memset(&restore_device_map, 0, sizeof(restore_device_map));
	free(device_map_option);
	device_map_option = NULL;
	ret = parse_cuda_plugin_options(stage);
	if (ret)
		goto error;

	/* CUDA checkpointing is not compatible with pre-dump. */
	if (stage == CR_PLUGIN_STAGE__PRE_DUMP)
		return 0;

	/* Do not touch libcuda or execute cuda-checkpoint for a CPU-only restore. */
	if (stage == CR_PLUGIN_STAGE__RESTORE) {
		restore_required = has_inventory_plugin(CR_PLUGIN_DESC.name);
		if (!restore_required && device_map_option) {
			pr_err("cuda_plugin.device-map was supplied for an image that does not require CUDA restore\n");
			ret = -EINVAL;
			goto error;
		}
		if (!restore_required)
			return 0;
	}

	if (!fault_injected(FI_PLUGIN_CUDA_FORCE_ENABLE) && !is_cuda_device_available()) {
		if (device_map_option) {
			pr_err("cuda_plugin.device-map requires an available CUDA device\n");
			ret = -ENODEV;
			goto error;
		}
		pr_info("No GPU device found; CUDA plugin is disabled\n");
		return 0;
	}

	ret = select_cuda_backend();
	if (ret == -ENOTSUP && backend_selection == CUDA_BACKEND_AUTO && !device_map_option)
		return 0;
	if (ret)
		goto error;

	ret = active_backend->init(stage);
	if (ret) {
		pr_err("Unable to initialize %s backend: %d\n", active_backend->name, ret);
		active_backend->fini(stage, ret);
		active_backend = NULL;
		goto error;
	}

	/* Consume the requirement only after the selected backend is ready. */
	if (restore_required && !check_and_remove_inventory_plugin(CR_PLUGIN_DESC.name)) {
		pr_err("Unable to consume CUDA plugin inventory requirement\n");
		active_backend->fini(stage, -1);
		active_backend = NULL;
		ret = -1;
		goto error;
	}

	pr_info("selected %s backend for stage %d\n", active_backend->name, stage);
	set_compel_interrupt_only_mode();

	return 0;

error:
	free(device_map_option);
	device_map_option = NULL;
	return ret;
}

static int cuda_plugin_dump_finish(int ret)
{
	if (!active_backend)
		return -ENOTSUP;

	return active_backend->dump_finish(ret);
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__DUMP_FINISH, cuda_plugin_dump_finish)

static void cuda_plugin_fini(int stage, int ret)
{
	if (active_backend) {
		pr_info("finished %s backend for stage %d with error %d\n",
			active_backend->name, stage, ret);
		active_backend->fini(stage, ret);
		active_backend = NULL;
	}

	cuda_device_map_fini(&restore_device_map);
	cuda_gpu_inventory_fini();
	free(device_map_option);
	device_map_option = NULL;
	cuda_tasks_handled = false;
}

CR_PLUGIN_REGISTER(CUDA_PLUGIN_NAME, cuda_plugin_init, cuda_plugin_fini)
