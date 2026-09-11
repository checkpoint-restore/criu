#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "cr_options.h"
#include "cuda.pb-c.h"
#include "cuda_device_map.h"
#include "image.h"

#define MOCK_GPU_COUNT		    4
#define CUDA_UUID_SIZE		    16
#define CUDA_GPU_INVENTORY_IMAGE    "cuda-gpu-inventory.img"
#define CUDA_GPU_INVENTORY_MAX_SIZE (16 * 1024 * 1024)

struct cr_options opts;

static int image_dir_fd = -1;
static pid_t parent_pid;
static const char uuid_map[] =
	"GPU-00010203-0405-0607-0809-0a0b0c0d0e0f="
	"GPU-50515253-5455-5657-5859-5a5b5c5d5e5f,"
	"GPU-10111213-1415-1617-1819-1a1b1c1d1e1f="
	"GPU-40414243-4445-4647-4849-4a4b4c4d4e4f,"
	"GPU-20212223-2425-2627-2829-2a2b2c2d2e2f="
	"GPU-60616263-6465-6667-6869-6a6b6c6d6e6f,"
	"GPU-30313233-3435-3637-3839-3a3b3c3d3e3f="
	"GPU-70717273-7475-7677-7879-7a7b7c7d7e7f";

void print_on_level(unsigned int loglevel, const char *format, ...)
{
	(void)loglevel;
	(void)format;
}

int criu_get_image_dir(void)
{
	assert(getpid() == parent_pid);
	return image_dir_fd;
}

int img_streamer_open(char *filename, int flags)
{
	int fd;

	assert(getpid() == parent_pid);
	assert(opts.stream);
	assert(!strcmp(filename, CUDA_GPU_INVENTORY_IMAGE));
	assert(flags == O_DUMP || flags == O_RSTR);
	fd = openat(image_dir_fd, filename, flags, 0600);
	return fd < 0 ? -errno : fd;
}

static void write_all(int fd, const void *data, size_t size)
{
	const unsigned char *cursor = data;

	while (size) {
		ssize_t ret = write(fd, cursor, size);

		assert(ret > 0);
		cursor += ret;
		size -= (size_t)ret;
	}
}

static void write_inventory_bytes(const void *header, size_t header_size,
				  const void *data, size_t data_size,
				  const void *trailer, size_t trailer_size)
{
	int fd;

	fd = openat(image_dir_fd, CUDA_GPU_INVENTORY_IMAGE,
		    O_WRONLY | O_CREAT | O_TRUNC, 0600);
	assert(fd >= 0);
	if (header_size)
		write_all(fd, header, header_size);
	if (data_size)
		write_all(fd, data, data_size);
	if (trailer_size)
		write_all(fd, trailer, trailer_size);
	assert(close(fd) == 0);
}

static void write_framed_inventory(const void *data, uint32_t declared_size,
				   size_t data_size, bool add_trailer)
{
	static const unsigned char trailer = 0xa5;

	write_inventory_bytes(&declared_size, sizeof(declared_size), data, data_size,
			      &trailer, add_trailer ? sizeof(trailer) : 0);
}

static void write_test_inventory(uint32_t version, const uint32_t *ordinals,
				 bool duplicate_uuid, bool add_trailer)
{
	CudaGpuInventory inventory = CUDA_GPU_INVENTORY__INIT;
	CudaGpu gpu_values[2];
	CudaGpu *gpus[2];
	unsigned char uuids[2][CUDA_UUID_SIZE];
	unsigned char *data;
	size_t size;
	unsigned int i;

	for (i = 0; i < 2; i++) {
		unsigned int j;

		cuda_gpu__init(&gpu_values[i]);
		for (j = 0; j < CUDA_UUID_SIZE; j++)
			uuids[i][j] = (unsigned char)((duplicate_uuid ? 0 : i * CUDA_UUID_SIZE) + j);
		gpu_values[i].has_ordinal = 1;
		gpu_values[i].ordinal = ordinals[i];
		gpu_values[i].has_uuid = 1;
		gpu_values[i].uuid.data = uuids[i];
		gpu_values[i].uuid.len = CUDA_UUID_SIZE;
		gpus[i] = &gpu_values[i];
	}

	inventory.has_version = 1;
	inventory.version = version;
	inventory.n_gpus = 2;
	inventory.gpus = gpus;
	size = cuda_gpu_inventory__get_packed_size(&inventory);
	assert(size > 0 && size <= UINT32_MAX);
	data = malloc(size);
	assert(data);
	assert(cuda_gpu_inventory__pack(&inventory, data) == size);
	write_framed_inventory(data, (uint32_t)size, size, add_trailer);
	free(data);
}

static void expected_uuid(unsigned char uuid[CUDA_UUID_SIZE], unsigned int device,
			  unsigned int offset)
{
	unsigned int i;

	for (i = 0; i < CUDA_UUID_SIZE; i++)
		uuid[i] = (unsigned char)(offset + device * CUDA_UUID_SIZE + i);
}

static void check_pair(const CUcheckpointGpuPair *pair, unsigned int source,
		       unsigned int destination)
{
	unsigned char source_uuid[CUDA_UUID_SIZE];
	unsigned char destination_uuid[CUDA_UUID_SIZE];

	expected_uuid(source_uuid, source, 0);
	expected_uuid(destination_uuid, destination, 64);
	assert(!memcmp(pair->oldUuid, source_uuid, sizeof(source_uuid)));
	assert(!memcmp(pair->newUuid, destination_uuid, sizeof(destination_uuid)));
}

static void check_dump_framing(void)
{
	struct stat st;
	uint32_t size;
	int fd;

	fd = openat(image_dir_fd, CUDA_GPU_INVENTORY_IMAGE, O_RDONLY);
	assert(fd >= 0);
	assert(fstat(fd, &st) == 0);
	assert(st.st_size > (off_t)sizeof(size));
	assert(read(fd, &size, sizeof(size)) == sizeof(size));
	assert(size == (uint32_t)(st.st_size - (off_t)sizeof(size)));
	assert(close(fd) == 0);
}

static void check_syntax(void)
{
	assert(cuda_device_map_validate(NULL) == 0);
	assert(cuda_device_map_validate("auto") == 0);
	assert(cuda_device_map_validate("0=1,1=0") == 0);
	assert(cuda_device_map_validate(uuid_map) == 0);

	assert(cuda_device_map_validate("") == -EINVAL);
	assert(cuda_device_map_validate("0") == -EINVAL);
	assert(cuda_device_map_validate("=1") == -EINVAL);
	assert(cuda_device_map_validate("0=") == -EINVAL);
	assert(cuda_device_map_validate("0=1,") == -EINVAL);
	assert(cuda_device_map_validate("0=1=2") == -EINVAL);
	assert(cuda_device_map_validate("0 =1") == -EINVAL);
	assert(cuda_device_map_validate("GPU-0011=GPU-2233") == -EINVAL);
}

static void check_no_map(void)
{
	struct cuda_device_map map = {};

	assert(cuda_device_map_resolve(NULL, &map) == 0);
	assert(!map.pairs);
	assert(map.count == 0);
	assert(!map.cli_value);
}

static void check_numeric_map(void)
{
	static const unsigned int destinations[MOCK_GPU_COUNT] = { 1, 0, 2, 3 };
	struct cuda_device_map map = {};
	unsigned int i;

	assert(cuda_device_map_resolve("0=1,1=0,2=2,3=3", &map) == 0);
	assert(map.count == MOCK_GPU_COUNT);
	for (i = 0; i < map.count; i++)
		check_pair(&map.pairs[i], i, destinations[i]);
	assert(map.cli_value);
	assert(!strcmp(map.cli_value, uuid_map));

	cuda_device_map_fini(&map);
}

static void check_automatic_map(void)
{
	struct cuda_device_map map = {};
	unsigned int i;

	assert(cuda_device_map_resolve("auto", &map) == 0);
	assert(map.count == MOCK_GPU_COUNT);
	for (i = 0; i < map.count; i++)
		check_pair(&map.pairs[i], i, i);
	assert(map.cli_value && !strncmp(map.cli_value, "GPU-", 4));

	cuda_device_map_fini(&map);
}

static void check_uuid_map(void)
{
	static const unsigned int destinations[MOCK_GPU_COUNT] = { 1, 0, 2, 3 };
	struct cuda_device_map map = {};
	unsigned int i;

	assert(cuda_device_map_resolve(uuid_map, &map) == 0);
	assert(map.count == MOCK_GPU_COUNT);
	for (i = 0; i < map.count; i++)
		check_pair(&map.pairs[i], i, destinations[i]);
	assert(map.cli_value && !strcmp(map.cli_value, uuid_map));

	cuda_device_map_fini(&map);
}

static void check_invalid_maps(void)
{
	struct cuda_device_map map = {};

	assert(cuda_device_map_resolve("0=1", &map) == -EINVAL);
	assert(cuda_device_map_resolve("0=1,0=0,2=2,3=3", &map) == -EINVAL);
	assert(cuda_device_map_resolve("0=1,1=1,2=2,3=3", &map) == -EINVAL);
	assert(cuda_device_map_resolve("0=4,1=0,2=2,3=3", &map) == -EINVAL);
	assert(cuda_device_map_resolve("4=1,1=0,2=2,3=3", &map) == -EINVAL);
	assert(cuda_device_map_resolve("0=1,1=0,2=2,3", &map) == -EINVAL);
	assert(cuda_device_map_resolve("", &map) == -EINVAL);
}

static void check_without_inventory(void)
{
	struct cuda_device_map map = {};
	const char *destination_ordinal =
		"GPU-00010203-0405-0607-0809-0a0b0c0d0e0f=0";
	const char *duplicate_destination =
		"GPU-00010203-0405-0607-0809-0a0b0c0d0e0f="
		"GPU-50515253-5455-5657-5859-5a5b5c5d5e5f,"
		"GPU-10111213-1415-1617-1819-1a1b1c1d1e1f="
		"GPU-50515253-5455-5657-5859-5a5b5c5d5e5f";

	cuda_gpu_inventory_fini();
	assert(unlinkat(image_dir_fd, CUDA_GPU_INVENTORY_IMAGE, 0) == 0);
	assert(cuda_gpu_inventory_restore_init() == 0);

	assert(cuda_device_map_resolve("0=1,1=0,2=2,3=3", &map) == -EINVAL);
	assert(cuda_device_map_resolve(destination_ordinal, &map) == -EINVAL);
	assert(cuda_device_map_resolve("auto", &map) == -EINVAL);
	assert(cuda_device_map_resolve(duplicate_destination, &map) == -EINVAL);

	assert(cuda_device_map_resolve(uuid_map, &map) == 0);
	assert(map.count == MOCK_GPU_COUNT);
	assert(map.cli_value && !strcmp(map.cli_value, uuid_map));
	cuda_device_map_fini(&map);

	check_no_map();
}

static void check_enumeration_children(const char *marker)
{
	FILE *file = fopen(marker, "r");
	unsigned int count = 0;
	long pid;

	assert(file);
	while (fscanf(file, "%ld", &pid) == 1) {
		assert(pid != (long)parent_pid);
		errno = 0;
		assert(waitpid((pid_t)pid, NULL, WNOHANG) == -1 && errno == ECHILD);
		count++;
	}
	assert(feof(file));
	assert(fclose(file) == 0);
	assert(count > 0);
	assert(unlink(marker) == 0);
}

static void check_signal_mask(const sigset_t *expected)
{
	sigset_t actual;
	int sig;

	assert(sigprocmask(SIG_SETMASK, NULL, &actual) == 0);
	for (sig = 1; sig < NSIG; sig++)
		assert(sigismember(&actual, sig) == sigismember(expected, sig));
}

static void check_enumeration_failures(void)
{
	static const char *failures[] = {
		"CRIU_CUDA_MOCK_INIT_ERROR",
		"CRIU_CUDA_MOCK_INIT_EXIT",
	};
	sigset_t saved_mask, mask;
	unsigned int i, blocked;

	assert(sigprocmask(SIG_SETMASK, NULL, &saved_mask) == 0);
	mask = saved_mask;
	sigaddset(&mask, SIGUSR2);
	for (blocked = 0; blocked < 2; blocked++) {
		if (blocked)
			sigaddset(&mask, SIGCHLD);
		else
			sigdelset(&mask, SIGCHLD);
		assert(sigprocmask(SIG_SETMASK, &mask, NULL) == 0);
		check_automatic_map();
		check_signal_mask(&mask);
		for (i = 0; i < sizeof(failures) / sizeof(failures[0]); i++) {
			struct cuda_device_map map = {};

			assert(setenv(failures[i], "1", 1) == 0);
			assert(cuda_gpu_inventory_dump() == -EIO);
			assert(cuda_device_map_resolve("auto", &map) == -EIO);
			assert(!map.pairs && !map.count && !map.cli_value);
			assert(cuda_device_map_resolve("0=1,1=0,2=2,3=3", &map) == -EIO);
			assert(!map.pairs && !map.count && !map.cli_value);
			assert(unsetenv(failures[i]) == 0);
			check_signal_mask(&mask);
			/* Failed helpers must be reaped before another operation starts. */
			errno = 0;
			assert(waitpid(-1, NULL, WNOHANG) == -1 && errno == ECHILD);
		}
	}
	assert(sigprocmask(SIG_SETMASK, &saved_mask, NULL) == 0);
}

static void check_malformed_inventories(void)
{
	static const uint32_t valid_ordinals[2] = { 0, 1 };
	static const uint32_t duplicate_ordinals[2] = { 0, 0 };
	static const uint32_t out_of_range_ordinals[2] = { 0, 2 };
	uint32_t oversized = CUDA_GPU_INVENTORY_MAX_SIZE + 1;
	uint32_t declared_size = 4;
	uint32_t empty_size = 0;
	uint16_t short_header = 1;
	unsigned char bytes[4] = { 0, 1, 2, 3 };

	write_inventory_bytes(&short_header, sizeof(short_header), NULL, 0, NULL, 0);
	assert(cuda_gpu_inventory_restore_init() == -EIO);

	write_framed_inventory(bytes, declared_size, sizeof(bytes) - 1, false);
	assert(cuda_gpu_inventory_restore_init() == -EIO);

	write_framed_inventory(NULL, oversized, 0, false);
	assert(cuda_gpu_inventory_restore_init() == -EINVAL);

	write_framed_inventory(NULL, empty_size, 0, false);
	assert(cuda_gpu_inventory_restore_init() == -EINVAL);

	write_framed_inventory(bytes, declared_size, sizeof(bytes), false);
	assert(cuda_gpu_inventory_restore_init() == -EINVAL);

	write_test_inventory(2, valid_ordinals, false, false);
	assert(cuda_gpu_inventory_restore_init() == -EINVAL);

	write_test_inventory(1, duplicate_ordinals, false, false);
	assert(cuda_gpu_inventory_restore_init() == -EINVAL);

	write_test_inventory(1, out_of_range_ordinals, false, false);
	assert(cuda_gpu_inventory_restore_init() == -EINVAL);

	write_test_inventory(1, valid_ordinals, true, false);
	assert(cuda_gpu_inventory_restore_init() == -EINVAL);

	write_test_inventory(1, valid_ordinals, false, true);
	assert(cuda_gpu_inventory_restore_init() == -EINVAL);
}

int main(void)
{
	char directory[] = "/tmp/criu-cuda-device-map.XXXXXX";
	char marker[sizeof(directory) + sizeof("/init-pids")];
	const char *visible_devices = "3,2,1,0";
	const char *device_order = "PCI_BUS_ID";

	parent_pid = getpid();
	assert(mkdtemp(directory));
	assert(snprintf(marker, sizeof(marker), "%s/init-pids", directory) > 0);
	assert(setenv("CRIU_CUDA_MOCK_INIT_MARKER", marker, 1) == 0);
	image_dir_fd = open(directory, O_RDONLY | O_DIRECTORY);
	assert(image_dir_fd >= 0);

	check_syntax();

	assert(setenv("CUDA_VISIBLE_DEVICES", visible_devices, 1) == 0);
	assert(setenv("CUDA_DEVICE_ORDER", device_order, 1) == 0);
	assert(setenv("CRIU_CUDA_MOCK_EXPECT_VISIBLE_DEVICES", visible_devices, 1) == 0);
	assert(setenv("CRIU_CUDA_MOCK_EXPECT_DEVICE_ORDER", device_order, 1) == 0);
	assert(setenv("CRIU_CUDA_MOCK_UUID_OFFSET", "0", 1) == 0);
	assert(cuda_gpu_inventory_dump() == 0);
	check_dump_framing();
	check_enumeration_children(marker);
	assert(!strcmp(getenv("CUDA_VISIBLE_DEVICES"), visible_devices));
	assert(!strcmp(getenv("CUDA_DEVICE_ORDER"), device_order));

	/* Exercise the image-streamer open path using only sequential I/O. */
	opts.stream = 1;
	assert(cuda_gpu_inventory_dump() == 0);
	assert(cuda_gpu_inventory_restore_init() == 0);
	opts.stream = 0;
	cuda_gpu_inventory_fini();

	assert(setenv("CRIU_CUDA_MOCK_UUID_OFFSET", "64", 1) == 0);
	assert(cuda_gpu_inventory_restore_init() == 0);

	check_no_map();
	check_numeric_map();
	check_automatic_map();
	check_uuid_map();
	check_invalid_maps();
	check_enumeration_failures();
	check_enumeration_children(marker);
	assert(unsetenv("CRIU_CUDA_MOCK_INIT_MARKER") == 0);
	check_without_inventory();
	check_malformed_inventories();

	cuda_gpu_inventory_fini();
	assert(unlinkat(image_dir_fd, CUDA_GPU_INVENTORY_IMAGE, 0) == 0);
	assert(close(image_dir_fd) == 0);
	assert(rmdir(directory) == 0);

	return 0;
}
