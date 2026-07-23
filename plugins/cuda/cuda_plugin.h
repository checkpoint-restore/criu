#ifndef CUDA_PLUGIN_H
#define CUDA_PLUGIN_H

struct cuda_plugin_backend {
	const char *name;
	int (*init)(int stage);
	void (*fini)(int stage, int ret);
	int (*pause_devices)(int pid);
	int (*checkpoint_devices)(int pid);
	int (*resume_devices_late)(int pid);
};

extern const struct cuda_plugin_backend cuda_cli_backend;

#endif /* CUDA_PLUGIN_H */
