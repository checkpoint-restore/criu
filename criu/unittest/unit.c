#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mman.h>

#include "log.h"
#include "util.h"
#include "criu-log.h"
#include "bfd.h"
#include "compression.h"
#include "page.h"
#include "pagemap.h"

int parse_statement(int i, char *line, char **configuration);

static void test_pagemap_offset_alignment(void)
{
	off_t aligned = (off_t)PAGE_SIZE * 3;

	assert(pagemap_page_align_offset(aligned) == aligned);
	assert(pagemap_page_align_offset(aligned + 1) == aligned + PAGE_SIZE);

	if (sizeof(off_t) > sizeof(uint32_t)) {
		off_t above_4g = ((off_t)1 << 32) + 1;

		assert(pagemap_page_align_offset(above_4g) ==
		       ((off_t)1 << 32) + PAGE_SIZE);
	}
}

static void test_bfd(void)
{
	struct bfd f;
	char *str;
	const int lines = 5;
	char *long_line[lines];
	int size = 1024 * 1024;
	int i, fd;

	fd = memfd_create("criu-bfd-test", 0);
	assert(fd >= 0);

	for (i = 0; i < lines; i++) {
		int j;

		long_line[i] = malloc(size + 2);
		assert(long_line[i]);
		long_line[i][0] = 'A' + (i % 26);
		for (j = 1; j < size; j++)
			long_line[i][j] = 'a' + (j % 26);
		long_line[i][size] = '\n';
		long_line[i][size + 1] = '\0';

		assert(write(fd, long_line[i], size + 1) == size + 1);
	}
	assert(lseek(fd, 0, SEEK_SET) == 0);

	f.fd = fd;
	assert(bfdopenr(&f) == 0);

	for (i = 0; i < lines; i++) {
		str = breadline(&f);
		assert(str);
		assert(strlen(str) == size);
		/* long_line has \n, str hasn't */
		assert(strcmp(str, long_line[i]) != 0);
		str[size] = '\n';
		assert(memcmp(str, long_line[i], size + 1) == 0);
	}

	bclose(&f);
	for (i = 0; i < lines; i++)
		free(long_line[i]);
}

static void test_bwrite(void)
{
	struct bfd f;
	char *buf;
	int size = 1024 * 1024;
	int i;
	int fd;
	char *read_buf;

	fd = memfd_create("criu-bfd-test", 0);
	assert(fd >= 0);

	buf = malloc(size);
	assert(buf);
	for (i = 0; i < size; i++)
		buf[i] = 'z' - (i % 26);

	f.fd = dup(fd);
	assert(f.fd >= 0);
	assert(bfdopenw(&f) == 0);

	assert(bwrite(&f, buf, size) == size);
	bclose(&f);

	assert(lseek(fd, 0, SEEK_SET) == 0);
	read_buf = malloc(size);
	assert(read_buf);
	assert(read(fd, read_buf, size) == size);
	assert(memcmp(buf, read_buf, size) == 0);

	close(fd);
	free(buf);
	free(read_buf);
}

#ifdef CONFIG_LZ4
static void test_compress_roundtrip(const char *page, int acceleration)
{
	char compressed[PAGE_COMPRESSED_SIZE_BOUND];
	char decompressed[PAGE_SIZE];
	int cs;

	cs = compress_data(page, PAGE_SIZE, compressed,
			   PAGE_COMPRESSED_SIZE_BOUND, acceleration);
	assert(cs > 0);
	assert(cs <= PAGE_COMPRESSED_SIZE_BOUND);
	assert(decompress_data(compressed, cs, PAGE_SIZE, decompressed) == 0);
	assert(memcmp(page, decompressed, PAGE_SIZE) == 0);
}

static void test_compression(void)
{
	char cbuf[PAGE_COMPRESSED_SIZE_BOUND];
	char page[PAGE_SIZE];
	const int accels[] = { 1, 4, 100 };

	/* Zero-page detection */
	memset(page, 0, PAGE_SIZE);
	assert(page_is_all_zero(page) == true);
	page[PAGE_SIZE - 1] = 1;
	assert(page_is_all_zero(page) == false);
	page[PAGE_SIZE - 1] = 0;
	page[0] = 0x42;
	assert(page_is_all_zero(page) == false);


	for (int a = 0; a < 3; a++) {
		int accel = accels[a];
		int cs;

		/* Zero-filled page: should compress well */
		memset(cbuf, 0, sizeof(cbuf));
		memset(page, 0, PAGE_SIZE);
		cs = compress_data(page, PAGE_SIZE,
				   cbuf, PAGE_COMPRESSED_SIZE_BOUND, accel);
		assert(cs > 0 && cs < PAGE_SIZE);
		test_compress_roundtrip(page, accel);

		/* Repeating pattern */
		for (int i = 0; i < PAGE_SIZE; i++)
			page[i] = i & 0xff;
		test_compress_roundtrip(page, accel);

		/* Pseudo-random data (incompressible) */
		srand(42);
		for (int i = 0; i < PAGE_SIZE; i++)
			page[i] = rand() & 0xff;
		test_compress_roundtrip(page, accel);

		/* Single non-zero byte */
		memset(cbuf, 0, sizeof(cbuf));
		memset(page, 0, PAGE_SIZE);
		page[0] = 0x42;
		cs = compress_data(page, PAGE_SIZE,
				   cbuf, PAGE_COMPRESSED_SIZE_BOUND, accel);
		assert(cs > 0 && cs < PAGE_SIZE);
		test_compress_roundtrip(page, accel);
	}
}

static unsigned int count_task_threads(void)
{
	struct dirent *entry;
	unsigned int nr_threads = 0;
	DIR *dir;

	dir = opendir("/proc/self/task");
	assert(dir);
	while ((entry = readdir(dir))) {
		if (entry->d_name[0] != '.')
			nr_threads++;
	}
	closedir(dir);
	return nr_threads;
}

static void wait_for_task_threads(unsigned int expected)
{
	unsigned int attempt;

	for (attempt = 0; attempt < 100; attempt++) {
		if (count_task_threads() == expected)
			return;
		usleep(1000);
	}
	assert(count_task_threads() == expected);
}

static void record_decompression_overlap(void *arg)
{
	unsigned int *calls = arg;

	(*calls)++;
}

static void test_parallel_decompression(void)
{
	struct decompression_shared_budget budget;
	const unsigned int pages_per_job = (512UL << 10) / PAGE_SIZE;
	const size_t nr_jobs = 8;
	const size_t job_bytes = (size_t)pages_per_job * PAGE_SIZE;
	const size_t src_size = nr_jobs * job_bytes;
	const size_t compressed_stride = REGION_COMPRESSED_SIZE_BOUND(pages_per_job);
	struct decompress_job *jobs;
	char *compressed;
	char *decompressed;
	char *src;
	struct decompression_pool *pool = NULL;
	unsigned int available_threads;
	unsigned int baseline_threads;
	unsigned int expected_threads;
	unsigned int overlap_calls = 0;
	size_t job;

	assert(decompression_thread_limit(0, 64) == 64);
	assert(decompression_thread_limit(1, 64) == 1);
	assert(decompression_thread_limit(8, 64) == 8);
	assert(decompression_thread_limit(100, 64) == 64);
	assert(decompression_thread_limit(0, 0) == 1);

	decompression_shared_budget_init(&budget, 1);
	available_threads = futex_get(&budget.threads);
	assert(available_threads >= 1);
	{
		cpu_set_t affinity;

		CPU_ZERO(&affinity);
		if (sched_getaffinity(0, sizeof(affinity), &affinity) == 0)
			assert(available_threads == (unsigned int)CPU_COUNT(&affinity));
	}
	decompression_shared_budget_init(&budget, 4);
	assert(futex_get(&budget.threads) == min(available_threads, 4U));
	assert(futex_get(&budget.batches) == 2);
	/* Automatic and serial calls both leave CPUs available to sibling calls. */
	decompression_shared_budget_init(&budget, 0);
	assert(futex_get(&budget.threads) == available_threads);
	decompression_use_shared_budget(&budget);
	assert(decompression_batch_try_acquire());
	assert(decompression_batch_try_acquire());
	assert(!decompression_batch_try_acquire());
	decompression_batch_release();
	assert(decompression_batch_try_acquire());
	decompression_batch_release();
	decompression_batch_release();
	assert(futex_get(&budget.batches) == 2);
	budget.thread_capacity = 1;
	assert(!compressed_restore_has_parallel_capacity(0));
	budget.thread_capacity = available_threads;
	assert(!compressed_restore_has_parallel_capacity(1));
	assert(compressed_restore_has_parallel_capacity(0) == (available_threads > 1));

	src = malloc(src_size);
	compressed = malloc(nr_jobs * compressed_stride);
	decompressed = malloc(src_size);
	jobs = malloc(nr_jobs * sizeof(*jobs));
	assert(src && compressed && decompressed && jobs);

	for (job = 0; job < nr_jobs; job++) {
		char *job_src = src + job * job_bytes;
		char *job_compressed = compressed + job * compressed_stride;
		int cs;
		size_t byte;

		for (byte = 0; byte < job_bytes; byte++)
			job_src[byte] = (char)(job + byte);
		cs = compress_region(job_src, pages_per_job, job_compressed, compressed_stride, 1);
		assert(cs > 0 && (size_t)cs < job_bytes);

		jobs[job].src = job_compressed;
		jobs[job].dst = decompressed + job * job_bytes;
		jobs[job].compressed_size = cs;
		jobs[job].pages = pages_per_job;
		jobs[job].block_index = job;
	}

	baseline_threads = count_task_threads();
	assert(decompress_jobs_parallel_pool_with_caller_work(
		       &pool, jobs, 1, job_bytes, 1,
		       record_decompression_overlap, &overlap_calls) == 0);
	assert(memcmp(src, decompressed, job_bytes) == 0);
	assert(overlap_calls == 0);
	assert(pool == NULL);
	assert(count_task_threads() == baseline_threads);
	assert(futex_get(&budget.threads) == available_threads);

	/* A 1 MiB batch creates one worker when at least two CPUs are available. */
	memset(decompressed, 0, src_size);
	assert(decompress_jobs_parallel_pool_with_caller_work(
		       &pool, jobs, 2, 2 * job_bytes, 0,
		       record_decompression_overlap, &overlap_calls) == 0);
	assert(memcmp(src, decompressed, 2 * job_bytes) == 0);
	expected_threads = min(available_threads, 2U);
	assert(overlap_calls == (expected_threads > 1));
	wait_for_task_threads(baseline_threads + expected_threads - 1);
	assert((pool != NULL) == (expected_threads > 1));
	assert(futex_get(&budget.threads) == available_threads);

	/* More work replaces the small pool with one sized to the useful width. */
	memset(decompressed, 0, src_size);
	assert(decompress_jobs_parallel_pool(&pool, jobs, nr_jobs, src_size, 0) == 0);
	assert(memcmp(src, decompressed, src_size) == 0);
	expected_threads = min(available_threads, (unsigned int)nr_jobs);
	wait_for_task_threads(baseline_threads + expected_threads - 1);
	assert((pool != NULL) == (expected_threads > 1));
	assert(futex_get(&budget.threads) == available_threads);

	/* Zero jobs use the same serial fallback and persistent worker pool. */
	memset(decompressed, 0xa5, src_size);
	for (job = 0; job < nr_jobs; job++) {
		jobs[job].src = NULL;
		jobs[job].compressed_size = 0;
	}
	assert(decompress_jobs_parallel_pool(&pool, jobs, 1, job_bytes, 1) == 0);
	for (job = 0; job < job_bytes; job++)
		assert(decompressed[job] == 0);

	memset(decompressed, 0xa5, src_size);
	assert(decompress_jobs_parallel_pool(&pool, jobs, nr_jobs, src_size, 0) == 0);
	for (job = 0; job < src_size; job++)
		assert(decompressed[job] == 0);

	decompression_pool_destroy(pool);
	decompression_use_shared_budget(NULL);
	wait_for_task_threads(baseline_threads);

	free(jobs);
	free(decompressed);
	free(compressed);
	free(src);
}

static void test_region_roundtrip(const char *src, unsigned int n_pages,
				  int acceleration)
{
	size_t region_bytes = (size_t)n_pages * PAGE_SIZE;
	size_t cap = REGION_COMPRESSED_SIZE_BOUND(n_pages);
	char *cbuf = malloc(cap);
	char *dec = malloc(region_bytes);
	int cs;

	assert(cbuf && dec);
	cs = compress_region(src, n_pages, cbuf, cap, acceleration);
	assert(cs >= 0);
	assert((size_t)cs <= region_bytes);
	assert(decompress_region(cbuf, cs, n_pages, dec) == 0);
	assert(memcmp(src, dec, region_bytes) == 0);

	free(cbuf);
	free(dec);
}

static void test_region_compression(void)
{
	unsigned int sizes[] = { 1, DEFAULT_REGION_PAGES, MAX_REGION_PAGES };
	const int accels[] = { 1, 4, 32 };
	unsigned int s, a;

	for (s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
		unsigned int n_pages = sizes[s];
		size_t region_bytes = (size_t)n_pages * PAGE_SIZE;
		char *src = malloc(region_bytes);
		size_t cap = REGION_COMPRESSED_SIZE_BOUND(n_pages);
		char *cbuf = malloc(cap);
		size_t i;

		assert(src && cbuf);

		for (a = 0; a < sizeof(accels) / sizeof(accels[0]); a++) {
			int accel = accels[a];
			int cs;
			uint32_t state;

			/* All-zero region: must short-circuit to 0 bytes. */
			memset(src, 0, region_bytes);
			cs = compress_region(src, n_pages, cbuf, cap, accel);
			assert(cs == 0);
			test_region_roundtrip(src, n_pages, accel);

			/* Repeating pattern: should compress well. */
			for (i = 0; i < region_bytes; i++)
				src[i] = (char)(i & 0xff);
			cs = compress_region(src, n_pages, cbuf, cap, accel);
			assert(cs > 0);
			assert((size_t)cs < region_bytes);
			test_region_roundtrip(src, n_pages, accel);

			/* Deterministic high-entropy bytes must use the raw fallback. */
			state = 0x9e3779b9U ^ (a + 1) ^ n_pages;

			for (i = 0; i < region_bytes; i++) {
				state ^= state << 13;
				state ^= state >> 17;
				state ^= state << 5;
				src[i] = (char)(state >> 24);
			}
			cs = compress_region(src, n_pages, cbuf, cap, accel);
			assert((size_t)cs == region_bytes);
			test_region_roundtrip(src, n_pages, accel);

			/* Mostly zeros with one non-zero island. */
			memset(src, 0, region_bytes);
			memset(src + (n_pages / 2) * PAGE_SIZE, 0xab, PAGE_SIZE);
			cs = compress_region(src, n_pages, cbuf, cap, accel);
			assert(cs > 0);
			assert((size_t)cs < region_bytes);
			test_region_roundtrip(src, n_pages, accel);
		}

		free(src);
		free(cbuf);
	}
}

#endif

int main(int argc, char *argv[], char *envp[])
{
	char **configuration;
	int i;

	configuration = malloc(10 * sizeof(char *));
	log_init(NULL);

	test_bfd();
	test_bwrite();
	test_pagemap_offset_alignment();

	i = parse_statement(0, "", configuration);
	assert(i == 0);

	i = parse_statement(0, "\n", configuration);
	assert(i == 0);

	i = parse_statement(0, "# comment\n", configuration);
	assert(i == 0);

	i = parse_statement(0, "#comment\n", configuration);
	assert(i == 0);

	i = parse_statement(0, "tcp-close #comment\n", configuration);
	assert(i == 1);
	assert(!strcmp(configuration[0], "--tcp-close"));

	i = parse_statement(0, " tcp-close #comment\n", configuration);
	assert(i == 1);
	assert(!strcmp(configuration[0], "--tcp-close"));

	i = parse_statement(0, "test \"test\"\n", configuration);
	assert(i == 2);
	assert(!strcmp(configuration[0], "--test"));
	assert(!strcmp(configuration[1], "test"));

	i = parse_statement(0, "dsfa \"aaaaa \\\"bbbbbb\\\"\"\n", configuration);
	assert(i == 2);
	assert(!strcmp(configuration[0], "--dsfa"));
	assert(!strcmp(configuration[1], "aaaaa \"bbbbbb\""));

	i = parse_statement(0, "verbosity 4\n", configuration);
	assert(i == 2);
	assert(!strcmp(configuration[0], "--verbosity"));
	assert(!strcmp(configuration[1], "4"));

	i = parse_statement(0, "verbosity \"\n", configuration);
	assert(i == -1);

	i = parse_statement(0, "verbosity 4#comment\n", configuration);
	assert(i == 2);
	assert(!strcmp(configuration[0], "--verbosity"));
	assert(!strcmp(configuration[1], "4"));

	i = parse_statement(0, "verbosity 4 #comment\n", configuration);
	assert(i == 2);
	assert(!strcmp(configuration[0], "--verbosity"));
	assert(!strcmp(configuration[1], "4"));

	i = parse_statement(0, "verbosity 4  #comment\n", configuration);
	assert(i == 2);
	assert(!strcmp(configuration[0], "--verbosity"));
	assert(!strcmp(configuration[1], "4"));

	i = parse_statement(0, "verbosity 4 no-comment\n", configuration);
	assert(i == -1);

	i = parse_statement(0, "lsm-profile \"\" # more comments\n", configuration);
	assert(i == 2);
	assert(!strcmp(configuration[0], "--lsm-profile"));
	assert(!strcmp(configuration[1], ""));

	i = parse_statement(0, "lsm-profile \"something\"# comment\n", configuration);
	assert(i == 2);
	assert(!strcmp(configuration[0], "--lsm-profile"));
	assert(!strcmp(configuration[1], "something"));

	i = parse_statement(0, "#\n", configuration);
	assert(i == 0);

	i = parse_statement(0, "lsm-profile \"selinux:something\\\"with\\\"quotes\"\n", configuration);
	assert(i == 2);
	assert(!strcmp(configuration[0], "--lsm-profile"));
	assert(!strcmp(configuration[1], "selinux:something\"with\"quotes"));

	i = parse_statement(0, "work-dir \"/tmp with spaces\" no-comment\n", configuration);
	assert(i == -1);

	i = parse_statement(0, "work-dir \"/tmp with spaces\"\n", configuration);
	assert(i == 2);
	assert(!strcmp(configuration[0], "--work-dir"));
	assert(!strcmp(configuration[1], "/tmp with spaces"));

	i = parse_statement(0, "a b c d e f g h i\n", configuration);
	assert(i == -1);

	/* get_relative_path */
	/* different kinds of representation of "/" */
	assert(!strcmp(get_relative_path("/", "/"), ""));
	assert(!strcmp(get_relative_path("/", ""), ""));
	assert(!strcmp(get_relative_path("", "/"), ""));
	assert(!strcmp(get_relative_path(".", "/"), ""));
	assert(!strcmp(get_relative_path("/", "."), ""));
	assert(!strcmp(get_relative_path("/", "./"), ""));
	assert(!strcmp(get_relative_path("./", "/"), ""));
	assert(!strcmp(get_relative_path("/.", "./"), ""));
	assert(!strcmp(get_relative_path("./", "/."), ""));
	assert(!strcmp(get_relative_path(".//////.", ""), ""));
	assert(!strcmp(get_relative_path("/./", ""), ""));

	/* all relative paths given are assumed relative to "/" */
	assert(!strcmp(get_relative_path("/a/b/c", "a/b/c"), ""));

	/* multiple slashes are ignored, only directory names matter */
	assert(!strcmp(get_relative_path("///alfa///beta///gamma///", "//alfa//beta//gamma//"), ""));

	/* returned path is always relative */
	assert(!strcmp(get_relative_path("/a/b/c", "/"), "a/b/c"));
	assert(!strcmp(get_relative_path("/a/b/c", "/a/b"), "c"));

	/* single dots supported */
	assert(!strcmp(get_relative_path("./a/b", "a/"), "b"));

	/* double dots are partially supported */
	assert(!strcmp(get_relative_path("a/../b", "a"), "../b"));
	assert(!strcmp(get_relative_path("a/../b", "a/.."), "b"));
	assert(!get_relative_path("a/../b/c", "b"));

	/* if second path is not subpath - NULL returned */
	assert(!get_relative_path("/a/b/c", "/a/b/d"));
	assert(!get_relative_path("/a/b", "/a/b/c"));
	assert(!get_relative_path("/a/b/c/d", "b/c/d"));

	assert(!strcmp(get_relative_path("./a////.///./b//././c", "///./a/b"), "c"));

	/* leaves punctuation in returned string as is */
	assert(!strcmp(get_relative_path("./a////.///./b//././c", "a"), "b//././c"));

#ifdef CONFIG_LZ4
	test_compression();
	test_parallel_decompression();
	test_region_compression();
#endif

	pr_msg("OK\n");
	return 0;
}
