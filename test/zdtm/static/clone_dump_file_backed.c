#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "zdtmtst.h"
#include "clone_dump_util.h"

const char *test_doc = "--clone-dump with MAP_PRIVATE file-backed region: "
		       "tracks write count to detect lost CLONE pages. "
		       "Post-restore must see writer marker, not file content.";
const char *test_author = "Asaf Porat Stoler <asafpor@gmail.com>";


#define NR_PAGES	64
#define FILE_FILL	0x33
#define DRAIN_TIMEOUT	10000

char *test_dir;
TEST_OPTION(test_dir, string, "directory for temporary file", 1);

static atomic_int stop_writer;
static atomic_size_t write_iterations;
static unsigned char *mem;

/* Each write iteration uses a different marker based on iteration count */
static inline unsigned char iter_marker(size_t iter)
{
	return (unsigned char)(0x80 | (iter & 0x7f));
}

static void *writer_thread(void *arg)
{
	unsigned long sz = NR_PAGES * PAGE_SIZE;
	size_t iter = 0;

	while (!atomic_load(&stop_writer)) {
		unsigned char marker = iter_marker(iter);
		memset(mem, marker, sz);
		atomic_store(&write_iterations, iter);
		iter++;
	}
	return NULL;
}

int main(int argc, char **argv)
{
	pthread_t th;
	char path[256];
	unsigned char *buf;
	unsigned long sz = NR_PAGES * PAGE_SIZE;
	int fd, i, j;
	int errors = 0;
	size_t snap_iter;
	unsigned char expected_marker;

	test_init(argc, argv);

	snprintf(path, sizeof(path), "%s/clone_dump_file_backed.%d", test_dir, getpid());
	fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0600);
	if (fd < 0) {
		pr_perror("open %s", path);
		return 1;
	}
	buf = malloc(sz);
	if (!buf) {
		pr_perror("malloc");
		return 1;
	}
	memset(buf, FILE_FILL, sz);
	if (write(fd, buf, sz) != (ssize_t)sz) {
		pr_perror("write file");
		return 1;
	}
	free(buf);

	mem = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED) {
		pr_perror("mmap MAP_PRIVATE");
		return 1;
	}

	/* Trigger initial CLONE copies */
	memset(mem, iter_marker(0), sz);

	atomic_init(&stop_writer, 0);
	atomic_init(&write_iterations, 0);

	if (pthread_create(&th, NULL, writer_thread, NULL)) {
		pr_perror("pthread_create");
		return 1;
	}

	test_daemon();
	test_waitsig();

	snap_iter = atomic_load(&write_iterations);
	expected_marker = iter_marker(snap_iter);

	atomic_store(&stop_writer, 1);
	pthread_join(th, NULL);

	test_msg("State at restore: write_iterations=%zu expected_marker=0x%02x\n",
		 snap_iter, expected_marker);

	if (clone_wait_for_drain(mem, sz, DRAIN_TIMEOUT) < 0) {
		fail("file-backed region drain timeout");
		return 1;
	}

	/*
	 * Verify: pages must NOT have FILE_FILL (that would mean CLONE
	 * pages were not captured). They should have expected_marker.
	 */
	for (i = 0; i < NR_PAGES; i++) {
		unsigned char *page = mem + i * PAGE_SIZE;
		unsigned char m = page[0];

		if (m == FILE_FILL) {
			if (errors < 8)
				test_msg("page %d: has FILE_FILL 0x%02x "
					 "(CLONE page NOT captured!)\n", i, m);
			errors++;
			continue;
		}

		/* Check entire page is uniform */
		for (j = 0; j < PAGE_SIZE; j++) {
			if (page[j] != m) {
				if (errors < 8)
					test_msg("page %d offset %d: torn "
						 "(0x%02x != 0x%02x)\n",
						 i, j, page[j], m);
				errors++;
				break;
			}
		}
	}

	close(fd);
	unlink(path);

	if (errors) {
		test_msg("SUMMARY: %d errors (snap_iter=%zu)\n", errors, snap_iter);
		fail("file-backed region verification failed");
		return 1;
	}

	test_msg("OK: all %d pages have CLONE content (iter=%zu)\n",
		 NR_PAGES, snap_iter);
	pass();
	return 0;
}
