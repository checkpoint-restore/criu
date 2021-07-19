#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <setjmp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "zdtmtst.h"

const char *test_doc = "Create all sorts of maps and compare /proc/pid/maps\n"
		       "before and after migration\n";
const char *test_author = "Pavel Emelianov <xemul@parallels.com>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

const static int map_prots[] = {
	PROT_NONE,
	PROT_READ,
	PROT_READ | PROT_WRITE,
	PROT_READ | PROT_WRITE | PROT_EXEC,
};
#define NUM_MPROTS sizeof(map_prots) / sizeof(int)
#define RW_PROT(x) ((x) & (PROT_READ | PROT_WRITE))
#define X_PROT(x)  ((x)&PROT_EXEC)

int check_prot(int src_prot, int dst_prot)
{
	if (RW_PROT(src_prot) != RW_PROT(dst_prot))
		return 0;
	/* If exec bit will be enabled may depend on NX capability of CPUs of
	 * source and destination nodes. In any case, migrated mapping should
	 * not have less permissions than newly created one
	 **
	 * A is a subset of B iff (A & B) == A
	 */
	return (X_PROT(dst_prot) & X_PROT(src_prot)) == X_PROT(dst_prot);
}

const static int map_flags[] = { MAP_PRIVATE, MAP_SHARED, MAP_PRIVATE | MAP_ANONYMOUS, MAP_SHARED | MAP_ANONYMOUS };
#define NUM_MFLAGS   sizeof(map_flags) / sizeof(int)
#define NUM_MAPS     NUM_MPROTS *NUM_MFLAGS
#define ONE_MAP_SIZE 0x2000

struct map {
	int prot;
	int prot_real;
	int flag;
	char filename[256];
	int fd;
	void *ptr;
};

static void init_map(struct map *map, int prot_no, int flag_no)
{
	map->fd = -1;
	map->prot = map_prots[prot_no];
	map->flag = map_flags[flag_no];
}

static int make_map(struct map *map)
{
	uint32_t crc;
	uint8_t buf[ONE_MAP_SIZE];
	static int i = 0;

	if (!(map->flag & MAP_ANONYMOUS)) {
		/* need file */
		if (snprintf(map->filename, sizeof(map->filename), "%s-%02d", filename, i++) >= sizeof(map->filename)) {
			pr_perror("filename %s is too long", filename);
			return -1;
		}

		map->fd = open(map->filename, O_RDWR | O_CREAT, 0600);
		if (map->fd < 0) {
			pr_perror("can't open %s", map->filename);
			return -1;
		}

		crc = ~0;
		datagen(buf, sizeof(buf), &crc);
		if (write(map->fd, buf, sizeof(buf)) != sizeof(buf)) {
			pr_perror("failed to write %s", map->filename);
			return -1;
		}
	}

	map->ptr = mmap(NULL, ONE_MAP_SIZE, map->prot, map->flag, map->fd, 0);
	if (map->ptr == MAP_FAILED) {
		pr_perror("can't create mapping");
		return -1;
	}

	if ((map->flag & MAP_ANONYMOUS) && (map->prot & PROT_WRITE)) {
		/* can't fill it with data otherwise */
		crc = ~0;
		datagen(map->ptr, ONE_MAP_SIZE, &crc);
	}

	test_msg("map: ptr %p flag %8x prot %8x\n", map->ptr, map->flag, map->prot);

	return 0;
}

static sigjmp_buf segv_ret; /* we need sig*jmp stuff, otherwise SIGSEGV will reset our handler */
static void segfault(int signo)
{
	siglongjmp(segv_ret, 1);
}

/*
 * after test func should be placed check map, because size of test_func
 * is calculated as (check_map-test_func)
 */
int test_func(void)
{
	return 1;
}
static int check_map(struct map *map)
{
	int prot = PROT_WRITE | PROT_READ | PROT_EXEC;

	if (signal(SIGSEGV, segfault) == SIG_ERR) {
		fail("setting SIGSEGV handler failed");
		return -1;
	}
	if (!sigsetjmp(segv_ret, 1)) {
		uint32_t crc = ~0;
		if (datachk(map->ptr, ONE_MAP_SIZE, &crc)) /* perform read access */
			if (!(map->flag & MAP_ANONYMOUS) ||
			    (map->prot & PROT_WRITE)) { /* anon maps could only be filled when r/w */
				fail("CRC mismatch: ptr %p flag %8x prot %8x", map->ptr, map->flag, map->prot);
				return -1;
			}
		/* prot |= PROT_READ//	need barrier before this line,
					because compiler change order commands.
					I finded one method: look at next lines*/
	} else
		prot &= PROT_WRITE | !PROT_READ | PROT_EXEC;

	if (signal(SIGSEGV, segfault) == SIG_ERR) {
		fail("setting SIGSEGV handler failed");
		return -1;
	}

	if (!sigsetjmp(segv_ret, 1)) {
		*(int *)(map->ptr) = 1234; /* perform write access */
	} else
		prot &= !PROT_WRITE | PROT_READ | PROT_EXEC;

	if (signal(SIGSEGV, segfault) == SIG_ERR) {
		fail("restoring SIGSEGV handler failed");
		return -1;
	}

	if (!sigsetjmp(segv_ret, 1)) {
		if (map->prot & PROT_WRITE) {
			memcpy(map->ptr, test_func, getpagesize());
		} else {
			if (!(map->flag & MAP_ANONYMOUS)) {
				uint8_t funlen = (uint8_t *)check_map - (uint8_t *)test_func;
				lseek(map->fd, 0, SEEK_SET);
				if (write(map->fd, test_func, funlen) < funlen) {
					pr_perror("failed to write %s", map->filename);
					return -1;
				}
			}
		}
		if (!(map->flag & MAP_ANONYMOUS) || map->prot & PROT_WRITE)
			/* Function body has been copied into the mapping */
			((int (*)(void))map->ptr)(); /* perform exec access */
		else
			/* No way to copy function body into mapping,
			 * clear exec bit from effective protection
			 */
			prot &= PROT_WRITE | PROT_READ | !PROT_EXEC;
	} else
		prot &= PROT_WRITE | PROT_READ | !PROT_EXEC;

	if (signal(SIGSEGV, SIG_DFL) == SIG_ERR) {
		fail("restoring SIGSEGV handler failed");
		return -1;
	}

	return prot;
}

static void destroy_map(struct map *map)
{
	munmap(map->ptr, ONE_MAP_SIZE);

	if (map->fd >= 0) {
		close(map->fd);
		unlink(map->filename);
	}
}

#define MAPS_LEN 0x10000

int main(int argc, char **argv)
{
	struct map maps[NUM_MAPS] = {}, maps_compare[NUM_MAPS] = {};
	int i, j, k;
	test_init(argc, argv);

	k = 0;
	for (i = 0; i < NUM_MPROTS; i++)
		for (j = 0; j < NUM_MFLAGS; j++)
			init_map(maps + k++, i, j);

	for (i = 0; i < NUM_MAPS; i++)
		if (make_map(maps + i))
			goto err;

	test_daemon();
	test_waitsig();

	for (i = 0; i < NUM_MAPS; i++)
		if ((maps[i].prot_real = check_map(maps + i)) < 0)
			goto err;
	k = 0;
	for (i = 0; i < NUM_MPROTS; i++)
		for (j = 0; j < NUM_MFLAGS; j++)
			init_map(maps_compare + k++, i, j);
	for (i = 0; i < NUM_MAPS; i++)
		if (make_map(maps_compare + i))
			goto err;
	for (i = 0; i < NUM_MAPS; i++)
		if ((maps_compare[i].prot_real = check_map(maps_compare + i)) < 0)
			goto err;
	for (i = 0; i < NUM_MAPS; i++)
		if (!check_prot(maps[i].prot_real, maps_compare[i].prot_real)) {
			fail("protection on %i (flag=%d prot=%d) maps has changed (prot=%d(expected %d))", i,
			     maps[i].flag, maps[i].prot, maps[i].prot_real, maps_compare[i].prot_real);
			goto err;
		}

	pass();

	for (i = 0; i < NUM_MAPS; i++) {
		destroy_map(maps + i);
		destroy_map(maps_compare + i);
	}
	return 0;

err:
	return 1;
}
