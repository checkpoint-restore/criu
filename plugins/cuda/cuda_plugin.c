#include "criu-log.h"
#include "cuda_plugin.h"
#include "image.h"
#include "plugin.h"
#include "fault-injection.h"
#include "seize.h"

#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif
#define LOG_PREFIX "cuda_plugin: "

#define CUDA_PLUGIN_NAME	       "cuda_plugin"
static const struct cuda_plugin_backend *active_backend;
static bool cuda_tasks_handled;

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
	ret = cuda_driver_backend.probe();
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

	ret = cuda_cli_backend.probe();
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

	return active_backend->resume_devices_late(pid);
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RESUME_DEVICES_LATE, cuda_plugin_resume_devices_late)

static int cuda_plugin_init(int stage)
{
	bool restore_required = false;
	int ret;

	active_backend = NULL;
	cuda_tasks_handled = false;

	/* CUDA checkpointing is not compatible with pre-dump. */
	if (stage == CR_PLUGIN_STAGE__PRE_DUMP)
		return 0;

	/* Do not touch libcuda or execute cuda-checkpoint for a CPU-only restore. */
	if (stage == CR_PLUGIN_STAGE__RESTORE) {
		restore_required = has_inventory_plugin(CR_PLUGIN_DESC.name);
		if (!restore_required)
			return 0;
	}

	if (!fault_injected(FI_PLUGIN_CUDA_FORCE_ENABLE) && !is_cuda_device_available()) {
		pr_info("No GPU device found; CUDA plugin is disabled\n");
		return 0;
	}

	ret = select_cuda_backend();
	if (ret == -ENOTSUP)
		return 0;
	if (ret)
		return ret;

	ret = active_backend->init(stage);
	if (ret) {
		pr_err("Unable to initialize %s backend: %d\n", active_backend->name, ret);
		active_backend->fini(stage, ret);
		active_backend = NULL;
		return ret;
	}

	/* Consume the requirement only after the selected backend is ready. */
	if (restore_required && !check_and_remove_inventory_plugin(CR_PLUGIN_DESC.name)) {
		pr_err("Unable to consume CUDA plugin inventory requirement\n");
		active_backend->fini(stage, -1);
		active_backend = NULL;
		return -1;
	}

	pr_info("selected %s backend for stage %d\n", active_backend->name, stage);
	set_compel_interrupt_only_mode();

	return 0;
}

static void cuda_plugin_fini(int stage, int ret)
{
	if (active_backend) {
		pr_info("finished %s backend for stage %d with error %d\n",
			active_backend->name, stage, ret);
		active_backend->fini(stage, ret);
		active_backend = NULL;
	}

	cuda_tasks_handled = false;
}

CR_PLUGIN_REGISTER(CUDA_PLUGIN_NAME, cuda_plugin_init, cuda_plugin_fini)
