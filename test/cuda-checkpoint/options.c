/* Exercise the production option parser and backend admission without GPUs. */
#undef NDEBUG
#include <assert.h>
#include <stdarg.h>
#include "../../plugins/cuda/cuda_plugin.c"

enum faults fi_strategy = FI_PLUGIN_CUDA_FORCE_ENABLE;
static char *test_argv[5];
static bool test_inventory = true;
static bool driver_supported = true;
static int probes, initialized;

int criu_plugin_get_options(int *argc, char ***argv)
{
	for (*argc = 0; test_argv[*argc]; (*argc)++)
		;
	*argv = test_argv;
	return 0;
}
void print_on_level(unsigned int level, const char *format, ...)
{
	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
}
int add_inventory_plugin(const char *name) { return 0; }
bool has_inventory_plugin(const char *name) { return test_inventory; }
bool check_and_remove_inventory_plugin(const char *name) { return test_inventory; }
void set_compel_interrupt_only_mode(void) { }
int cuda_device_map_validate(const char *value) { return 0; }
int cuda_device_map_resolve(const char *value, struct cuda_device_map *map) { return 0; }
void cuda_device_map_fini(struct cuda_device_map *map) { }
int cuda_gpu_inventory_dump(void) { return 0; }
int cuda_gpu_inventory_restore_init(void) { return 0; }
void cuda_gpu_inventory_fini(void) { }
static int probe_driver(bool map) { probes++; return driver_supported ? 0 : -ENOTSUP; }
static int probe_cli(bool map) { probes++; return 0; }
static int init_backend(int stage) { initialized++; return 0; }
static void fini_backend(int stage, int ret) { }
const struct cuda_plugin_backend cuda_driver_backend = {
	.name = "fake driver", .probe = probe_driver, .init = init_backend, .fini = fini_backend,
};
const struct cuda_plugin_backend cuda_cli_backend = {
	.name = "fake CLI", .probe = probe_cli, .init = init_backend, .fini = fini_backend,
};

static int check(char *option, char *backend, int stage)
{
	int ret;

	test_argv[0] = "test";
	test_argv[1] = option;
	test_argv[2] = backend;
	test_argv[3] = NULL;
	probes = initialized = 0;
	/* Every plugin shares getopt state; parser must leave it untouched. */
	optind = 7;
	opterr = 1;
	optarg = "sentinel";
	optopt = 89;
	ret = cuda_plugin_init(stage);
	assert(optind == 7 && opterr == 1 && optopt == 89 && !strcmp(optarg, "sentinel"));
	if (!ret)
		cuda_plugin_fini(stage, 0);
	return ret;
}

int main(void)
{
	char *bad[] = {
		"--cuda_plugin.parallel", "--cuda_plugin.parallel=", "--cuda_plugin.parallel=0",
		"--cuda_plugin.parallel=-1", "--cuda_plugin.parallel=+2", "--cuda_plugin.parallel= 2",
		"--cuda_plugin.parallel=2x", "--cuda_plugin.parallel=65",
		"--cuda_plugin.parallel=99999999999999999999999999",
	};
	unsigned int i;

	assert(check(NULL, NULL, CR_PLUGIN_STAGE__RESTORE) == 0 && cuda_plugin_parallel == 1);
	assert(check("--cuda_plugin.parallel=1", NULL, CR_PLUGIN_STAGE__RESTORE) == 0);
	assert(check("--cuda_plugin.parallel=4", NULL, CR_PLUGIN_STAGE__RESTORE) == 0);
	assert(cuda_plugin_parallel == 4 && initialized == 1);
	assert(check("--cuda_plugin.parallel=64", NULL, CR_PLUGIN_STAGE__RESTORE) == 0);
	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		assert(check(bad[i], NULL, CR_PLUGIN_STAGE__RESTORE) != 0);
		assert(!probes && !initialized);
	}
	assert(check("--cuda_plugin.parallel=1", NULL, CR_PLUGIN_STAGE__DUMP) != 0);
	assert(check("--cuda_plugin.parallel=2", NULL, CR_PLUGIN_STAGE__PRE_DUMP) != 0);
	assert(check("--cuda_plugin.parallel=2", "--cuda_plugin.backend=cuda-checkpoint", CR_PLUGIN_STAGE__RESTORE) != 0);
	assert(!probes);
	assert(check("--cuda_plugin.parallel=1", "--cuda_plugin.backend=cuda-checkpoint", CR_PLUGIN_STAGE__RESTORE) == 0);
	driver_supported = false;
	assert(check("--cuda_plugin.parallel=2", NULL, CR_PLUGIN_STAGE__RESTORE) != 0 && initialized == 0);
	test_inventory = false;
	assert(check("--cuda_plugin.parallel=2", NULL, CR_PLUGIN_STAGE__RESTORE) != 0 && probes == 0);
	assert(check(NULL, NULL, CR_PLUGIN_STAGE__RESTORE) == 0 && probes == 0);
	puts("PASS CUDA parallel option bounds, restore-only, default/CLI/CPU admission, getopt isolation");
	return 0;
}
