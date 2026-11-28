#include "criu-log.h"
#include "cuda_device_map.h"
#include "cuda_inherited.h"
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

#define CUDA_PLUGIN_BACKEND_OPTION    CUDA_PLUGIN_NAME ".backend"
#define CUDA_PLUGIN_DEVICE_MAP_OPTION CUDA_PLUGIN_NAME ".device-map"
#define CUDA_PLUGIN_TIMEOUT_OPTION    CUDA_PLUGIN_NAME ".timeout"

unsigned int cuda_plugin_timeout;

static const struct cuda_plugin_backend *active_backend;
static char *device_map_option;
static struct cuda_device_map restore_device_map;
static bool cuda_tasks_handled;
static bool inherited_scanned;
static bool discard_inherited;
static bool inherited_files_required;

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
	CUDA_PLUGIN_OPTION_FORK,
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

/* All plugins share this option list. Collect values before validation so
 * getopt state is restored before returning an error.
 */
static int parse_cuda_plugin_options(int stage)
{
	static const struct option long_options[] = {
		{ CUDA_PLUGIN_BACKEND_OPTION, optional_argument, NULL, CUDA_PLUGIN_OPTION_BACKEND },
		{ CUDA_PLUGIN_DEVICE_MAP_OPTION, optional_argument, NULL, CUDA_PLUGIN_OPTION_DEVICE_MAP },
		{ CUDA_PLUGIN_FORK_OPTION, optional_argument, NULL, CUDA_PLUGIN_OPTION_FORK },
		{ CUDA_PLUGIN_TIMEOUT_OPTION, optional_argument, NULL, CUDA_PLUGIN_OPTION_TIMEOUT },
		{},
	};
	const char *backend_value = NULL;
	const char *fork_value = NULL;
	const char *device_map_value = NULL;
	const char *timeout_value = NULL;
	char *saved_optarg;
	char **argv = NULL;
	int saved_optopt;
	int saved_opterr;
	int saved_optind;
	int argc;
	int option;
	int ret;

	backend_selection = CUDA_BACKEND_AUTO;
	discard_inherited = false;
	cuda_plugin_timeout = 0;
	ret = criu_plugin_get_options(&argc, &argv);
	if (ret) {
		pr_err("Unable to read plugin options: %d\n", ret);
		return ret;
	}

	saved_optarg = optarg;
	saved_optopt = optopt;
	saved_opterr = opterr;
	saved_optind = optind;
	opterr = 0;
	optind = 0;
	while ((option = getopt_long(argc, argv, "", long_options, NULL)) != -1) {
		switch (option) {
		case CUDA_PLUGIN_OPTION_BACKEND:
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
		case CUDA_PLUGIN_OPTION_FORK:
			if (cuda_plugin_option_matches(argv[optind - 1], CUDA_PLUGIN_FORK_OPTION, optarg, &ret))
				fork_value = optarg;
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
		return ret;

	if (backend_value) {
		ret = parse_cuda_backend_option(backend_value);
		if (ret)
			return ret;
	}

	if (fork_value) {
		if (!strcmp(fork_value, "discard"))
			discard_inherited = true;
		else if (strcmp(fork_value, "reject")) {
			pr_err("Invalid %s value '%s' (expected reject or discard)\n", CUDA_PLUGIN_FORK_OPTION, fork_value);
			return -EINVAL;
		}
	}

	if (timeout_value) {
		char *end;
		unsigned long timeout;

		/* strtoul() accepts signs and leading whitespace; require an initial digit. */
		errno = 0;
		timeout = strtoul(timeout_value, &end, 10);
		if (errno || timeout_value[0] < '0' || timeout_value[0] > '9' || *end || timeout > UINT_MAX) {
			pr_err("Invalid cuda_plugin.timeout value '%s' (expected nonnegative seconds)\n", timeout_value);
			return -EINVAL;
		}
		cuda_plugin_timeout = timeout;
	}

	if (device_map_value) {
		if (stage != CR_PLUGIN_STAGE__RESTORE) {
			pr_err("cuda_plugin.device-map is valid only during restore\n");
			return -EINVAL;
		}

		ret = cuda_device_map_validate(device_map_value);
		if (ret)
			return ret;

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
	if (cuda_tasks_handled)
		return 0;

	if (add_inventory_plugin(CR_PLUGIN_DESC.name)) {
		pr_err("Failed to add CUDA plugin to inventory image\n");
		return -1;
	}
	cuda_tasks_handled = true;

	/* Enumerate GPUs before the first lock. At DUMP_DEVICES_LATE the time
	 * spent initializing CUDA would extend the freeze.
	 */
	return cuda_gpu_inventory_dump();
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

	/*
	 * CRIU calls this for every task once the whole tree is frozen. Before
	 * the first CUDA task releases its GPU state, find the tasks that
	 * inherited it across fork(): they still share it with their parent.
	 */
	if (!inherited_scanned) {
		inherited_scanned = true;
		if (cuda_tasks_handled && cuda_inherited_scan(active_backend->is_cuda_task, discard_inherited))
			return -1;
	}

	return active_backend->checkpoint_devices(pid);
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__CHECKPOINT_DEVICES, cuda_plugin_checkpoint_devices);

static int cuda_plugin_omit_device_vma(int pid, uint64_t start, uint64_t end, const struct stat *st)
{
	return cuda_inherited_omit_vma(pid, start, end, st) ? 1 : -ENOTSUP;
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__OMIT_DEVICE_VMA, cuda_plugin_omit_device_vma)

static int cuda_plugin_dump_file(int fd, int id)
{
	return cuda_inherited_dump_file(fd, id);
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__DUMP_EXT_FILE, cuda_plugin_dump_file)

static int cuda_plugin_dump_devices_late(int pid)
{
	if (!cuda_tasks_handled)
		return -ENOTSUP;

	return cuda_inherited_dump_files() ? -1 : 0;
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__DUMP_DEVICES_LATE, cuda_plugin_dump_devices_late)

static int cuda_plugin_restore_file(int id, bool *retry_needed)
{
	*retry_needed = false;
	return cuda_inherited_restore_file(id);
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RESTORE_EXT_FILE, cuda_plugin_restore_file)

static int cuda_plugin_resume_devices_late(int pid)
{
	if (!active_backend)
		return -ENOTSUP;

	return active_backend->resume_devices_late(pid, &restore_device_map);
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RESUME_DEVICES_LATE, cuda_plugin_resume_devices_late)

static int cuda_plugin_restore_init(void)
{
	int ret;

	if (!active_backend)
		return -ENOTSUP;

	ret = cuda_gpu_inventory_restore_init();
	if (ret)
		goto out;

	if (inherited_files_required) {
		ret = cuda_inherited_restore_init();
		if (ret)
			goto out;
	}

	ret = cuda_device_map_resolve(device_map_option, &restore_device_map);
out:
	if (ret == -ENOTSUP) {
		pr_err("Unable to prepare required CUDA restore state\n");
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
	inherited_scanned = false;
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
	inherited_files_required = restore_required && remove_inventory_plugin(CUDA_PLUGIN_INHERITED_FILES);

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
	cuda_inherited_fini();
	inherited_scanned = false;
	free(device_map_option);
	device_map_option = NULL;
	cuda_tasks_handled = false;
}

CR_PLUGIN_REGISTER(CUDA_PLUGIN_NAME, cuda_plugin_init, cuda_plugin_fini)
