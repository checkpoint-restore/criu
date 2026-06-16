#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "zdtmtst.h"
#include "clone_dump_util.h"

const char *test_doc = "--clone-dump multi-threaded process: each thread owns "
		       "a scratch region and TLS cookie. Verifies thread state "
		       "survives restore with no torn writes.";
const char *test_author = "Asaf Porat Stoler <asafpor@gmail.com>";


#define NR_THREADS	8
#define SCRATCH_PAGES	4
#define DRAIN_TIMEOUT	10000

static __thread uint64_t tls_cookie;

struct ctx {
	int id;
	unsigned char *scratch;
	atomic_size_t write_count;
	uint64_t observed_cookie;
};

static atomic_int stop_workers;

/*
 * Each thread writes a unique pattern: 0x80 | id for the first byte,
 * then incrementing from there. This lets us verify:
 * 1. The page belongs to the right thread (first byte encodes id)
 * 2. No torn writes (all bytes follow the pattern)
 */
static void fill_scratch(struct ctx *c)
{
	int j;
	unsigned char base = (unsigned char)(0x80 | c->id);
	for (j = 0; j < SCRATCH_PAGES * PAGE_SIZE; j++)
		c->scratch[j] = (unsigned char)(base + (j % 128));
}

static void *worker(void *arg)
{
	struct ctx *c = arg;
	size_t writes = 0;

	tls_cookie = 0xA5A5000000000000ULL | (uint64_t)c->id;

	while (!atomic_load(&stop_workers)) {
		fill_scratch(c);
		atomic_store(&c->write_count, writes);
		writes++;
		tls_cookie = 0xA5A5000000000000ULL | (uint64_t)c->id;
	}

	c->observed_cookie = tls_cookie;
	return NULL;
}

static int verify_scratch(struct ctx *c)
{
	int j;
	unsigned char first = c->scratch[0];
	int expected_id = first & 0x7f;
	int errors = 0;

	/* Verify first byte encodes the correct thread id */
	if (expected_id != c->id) {
		test_msg("thread %d: first byte 0x%02x encodes id %d (wrong thread!)\n",
			 c->id, first, expected_id);
		return -1;
	}

	/* Verify pattern consistency (no torn writes) */
	for (j = 0; j < SCRATCH_PAGES * PAGE_SIZE; j++) {
		unsigned char expected = (unsigned char)(first + (j % 128));
		if (c->scratch[j] != expected) {
			if (errors < 4)
				test_msg("thread %d offset %d: got 0x%02x expected 0x%02x "
					 "(based on first=0x%02x)\n",
					 c->id, j, c->scratch[j], expected, first);
			errors++;
		}
	}

	return errors ? -1 : 0;
}

int main(int argc, char **argv)
{
	pthread_t threads[NR_THREADS];
	struct ctx ctxs[NR_THREADS];
	int i;
	int errors = 0;
	int tls_errors = 0, content_errors = 0;

	test_init(argc, argv);

	for (i = 0; i < NR_THREADS; i++) {
		ctxs[i].id = i;
		ctxs[i].scratch = mmap(NULL, SCRATCH_PAGES * PAGE_SIZE,
				       PROT_READ | PROT_WRITE,
				       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (ctxs[i].scratch == MAP_FAILED) {
			pr_perror("mmap thread %d scratch", i);
			return 1;
		}
		fill_scratch(&ctxs[i]);
		atomic_init(&ctxs[i].write_count, 0);
	}

	atomic_init(&stop_workers, 0);
	for (i = 0; i < NR_THREADS; i++) {
		if (pthread_create(&threads[i], NULL, worker, &ctxs[i])) {
			pr_perror("pthread_create %d", i);
			return 1;
		}
	}

	test_daemon();
	test_waitsig();

	atomic_store(&stop_workers, 1);
	for (i = 0; i < NR_THREADS; i++)
		pthread_join(threads[i], NULL);

	test_msg("State at restore:\n");
	for (i = 0; i < NR_THREADS; i++)
		test_msg("  thread %d: write_count=%zu cookie=0x%016lx\n",
			 i, (size_t)atomic_load(&ctxs[i].write_count),
			 (unsigned long)ctxs[i].observed_cookie);

	/* Drain all scratch regions */
	for (i = 0; i < NR_THREADS; i++) {
		if (clone_wait_for_drain(ctxs[i].scratch,
					 SCRATCH_PAGES * PAGE_SIZE,
					 DRAIN_TIMEOUT) < 0) {
			fail("thread %d scratch drain timeout", i);
			return 1;
		}
	}

	/* Verify TLS and scratch content */
	for (i = 0; i < NR_THREADS; i++) {
		uint64_t expected_cookie = 0xA5A5000000000000ULL | (uint64_t)i;

		if (ctxs[i].observed_cookie != expected_cookie) {
			test_msg("thread %d: TLS cookie 0x%016lx != 0x%016lx\n",
				 i,
				 (unsigned long)ctxs[i].observed_cookie,
				 (unsigned long)expected_cookie);
			tls_errors++;
			errors++;
		}

		if (verify_scratch(&ctxs[i]) < 0) {
			content_errors++;
			errors++;
		}
	}

	if (errors) {
		test_msg("SUMMARY: %d errors (tls=%d, content=%d)\n",
			 errors, tls_errors, content_errors);
		fail("multi-thread verification failed");
		return 1;
	}

	test_msg("OK: all %d threads verified - TLS correct, no torn writes\n",
		 NR_THREADS);
	pass();
	return 0;
}
