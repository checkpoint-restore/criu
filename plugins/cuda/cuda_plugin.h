#ifndef CUDA_PLUGIN_H
#define CUDA_PLUGIN_H

/* Register a CUDA task before locking it, while allocation can still fail safely. */
int cuda_plugin_add_inventory(void);

struct cuda_plugin_backend {
	const char *name;
	int (*probe)(void);
	int (*init)(int stage);
	void (*fini)(int stage, int ret);
	int (*pause_devices)(int pid);
	int (*checkpoint_devices)(int pid);
	int (*resume_devices_late)(int pid);
};

extern const struct cuda_plugin_backend cuda_cli_backend;

#endif /* CUDA_PLUGIN_H */
