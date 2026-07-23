#include "cuda_plugin.h"
#include "plugin.h"

static int cuda_plugin_pause_devices(int pid)
{
	return cuda_cli_backend.pause_devices(pid);
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__PAUSE_DEVICES, cuda_plugin_pause_devices)

static int cuda_plugin_checkpoint_devices(int pid)
{
	return cuda_cli_backend.checkpoint_devices(pid);
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__CHECKPOINT_DEVICES, cuda_plugin_checkpoint_devices)

static int cuda_plugin_resume_devices_late(int pid)
{
	return cuda_cli_backend.resume_devices_late(pid);
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RESUME_DEVICES_LATE, cuda_plugin_resume_devices_late)

static int cuda_plugin_init(int stage)
{
	return cuda_cli_backend.init(stage);
}

static void cuda_plugin_fini(int stage, int ret)
{
	cuda_cli_backend.fini(stage, ret);
}

CR_PLUGIN_REGISTER("cuda_plugin", cuda_plugin_init, cuda_plugin_fini)
