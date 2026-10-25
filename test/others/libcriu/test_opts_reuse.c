#define _GNU_SOURCE
#include "criu.h"

#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The libcriu test jobs run without a sanitizer, so this test counts
 * outstanding allocations through interposed libc calls instead. */

static void *(*real_malloc)(size_t);
static void *(*real_calloc)(size_t, size_t);
static char *(*real_strdup)(const char *);
static void *(*real_realloc)(void *, size_t);
static void (*real_free)(void *);

static long outstanding;

/* Record the allocations of one set call (track), and refuse to release
 * them while a failed replacement runs (guard), so a failed set that
 * touches the previous value fails loudly instead of only changing the
 * allocation count.
 */
#define MAX_TRACKED 8
static void *tracked[MAX_TRACKED];
static int tracked_n;
static int track;
static int guard;

/* real strdup() may allocate through the interposed malloc(); do not
 * count that nested allocation twice.
 */
static int in_strdup;

/* dlsym() may itself allocate while resolving, so serve nested calls
 * from a scratch buffer to break the recursion.
 */
static char scratch[65536];
static size_t scratch_used;
static int resolving;

static void *scratch_alloc(size_t size)
{
	void *p = scratch + scratch_used;

	scratch_used += (size + 15) & ~15UL;
	if (scratch_used > sizeof(scratch))
		return NULL;
	return p;
}

static int in_scratch(const void *p)
{
	return p >= (void *)scratch && p < (void *)(scratch + sizeof(scratch));
}

static void resolve_real(void)
{
	if (resolving)
		return;
	resolving = 1;
	real_malloc = dlsym(RTLD_NEXT, "malloc");
	real_calloc = dlsym(RTLD_NEXT, "calloc");
	real_strdup = dlsym(RTLD_NEXT, "strdup");
	real_realloc = dlsym(RTLD_NEXT, "realloc");
	real_free = dlsym(RTLD_NEXT, "free");
	resolving = 0;
}

/* when non-negative, fail the (malloc_fail_at + 1)-th malloc from now */
static int malloc_fail_at = -1;

/* when non-negative, fail the (strdup_fail_at + 1)-th strdup from now */
static int strdup_fail_at = -1;

void *malloc(size_t size)
{
	void *p;

	if (malloc_fail_at >= 0 && malloc_fail_at-- == 0) {
		errno = ENOMEM;
		return NULL;
	}
	if (!real_malloc) {
		resolve_real();
		if (!real_malloc)
			return scratch_alloc(size);
	}
	p = real_malloc(size);
	if (p && !in_strdup)
		outstanding++;
	if (track && p && !in_strdup) {
		if (tracked_n == MAX_TRACKED) {
			fprintf(stderr, "FAIL: tracked allocations overflow\n");
			exit(1);
		}
		tracked[tracked_n++] = p;
	}
	return p;
}

void *calloc(size_t nmemb, size_t size)
{
	void *p;

	if (!real_calloc) {
		resolve_real();
		if (!real_calloc) {
			p = scratch_alloc(nmemb * size);
			memset(p, 0, nmemb * size);
			return p;
		}
	}
	p = real_calloc(nmemb, size);
	if (p)
		outstanding++;
	return p;
}

char *strdup(const char *s)
{
	char *p;

	if (strdup_fail_at >= 0 && strdup_fail_at-- == 0) {
		errno = ENOMEM;
		return NULL;
	}
	if (!real_strdup) {
		resolve_real();
		if (!real_strdup) {
			p = scratch_alloc(strlen(s) + 1);
			strcpy(p, s);
			return p;
		}
	}
	in_strdup = 1;
	p = real_strdup(s);
	in_strdup = 0;
	if (p)
		outstanding++;
	if (track && p) {
		if (tracked_n == MAX_TRACKED) {
			fprintf(stderr, "FAIL: tracked allocations overflow\n");
			exit(1);
		}
		tracked[tracked_n++] = p;
	}
	return p;
}

void *realloc(void *p, size_t size)
{
	void *np;

	if (!real_realloc) {
		resolve_real();
		if (!real_realloc)
			return NULL;
	}
	if (!p)
		return malloc(size);
	if (in_scratch(p)) {
		/* the old scratch size is unknown; copy at most to its end */
		size_t avail = scratch + scratch_used - (char *)p;

		np = malloc(size);
		if (np)
			memcpy(np, p, avail < size ? avail : size);
		return np;
	}
	return real_realloc(p, size);
}

void free(void *p)
{
	int i;

	if (!p || in_scratch(p))
		return;
	if (guard) {
		for (i = 0; i < tracked_n; i++)
			if (tracked[i] == p) {
				fprintf(stderr, "FAIL: failed set released the previous value\n");
				exit(1);
			}
	}
	if (!real_free) {
		resolve_real();
		if (!real_free)
			return;
	}
	outstanding--;
	real_free(p);
}

static char *argv1[] = { "first", "command" };
static char *argv2[] = { "second" };
static char *argv_dup[] = { "same", "same" };
static char *argv_many[64];
static char *alias_argv[2];

static int set_options_twice(criu_opts *opts)
{
	if (criu_local_set_exec_cmd(opts, 2, argv1) ||
	    criu_local_set_exec_cmd(opts, 1, argv2) ||
	    criu_local_set_page_server_address_port(opts, "127.0.0.1", 1111) ||
	    criu_local_set_page_server_address_port(opts, "127.0.0.2", 2222)) {
		fprintf(stderr, "option setter failed\n");
		return -1;
	}

	return 0;
}

static int check_leaks(long before, const char *what)
{
	if (outstanding != before) {
		fprintf(stderr, "FAIL: %ld allocations leaked %s\n",
			outstanding - before, what);
		return 1;
	}
	return 0;
}

int main(void)
{
	criu_opts *opts = NULL;
	long before;
	int i;

	/* absorb one-time library allocations before taking the count */
	if (criu_local_init_opts(&opts) || set_options_twice(opts))
		return 1;
	criu_local_free_opts(opts);

	before = outstanding;

	for (i = 0; i < 64; i++)
		argv_many[i] = "arg";

	for (i = 0; i < 100; i++) {
		opts = NULL;
		if (criu_local_init_opts(&opts) ||
		    criu_local_set_exec_cmd(opts, 2, argv1) ||
		    criu_local_set_exec_cmd(opts, 1, argv2))
			return 1;
		criu_local_free_opts(opts);
	}
	if (check_leaks(before, "over 100 exec_cmd reuse iterations"))
		return 1;

	for (i = 0; i < 100; i++) {
		opts = NULL;
		if (criu_local_init_opts(&opts) ||
		    criu_local_set_page_server_address_port(opts, "127.0.0.1", 1111) ||
		    criu_local_set_page_server_address_port(opts, "127.0.0.2", 2222))
			return 1;
		criu_local_free_opts(opts);
	}
	if (check_leaks(before, "over 100 page-server reuse iterations"))
		return 1;

	for (i = 0; i < 100; i++) {
		opts = NULL;
		if (criu_local_init_opts(&opts) || set_options_twice(opts))
			return 1;
		criu_local_free_opts(opts);
	}
	if (check_leaks(before, "over 100 combined reuse iterations"))
		return 1;

	/* fail the second strdup of a repeated set: the partial cleanup
	 * must free everything the call already copied, and the call must
	 * report -ENOMEM.
	 */
	opts = NULL;
	if (criu_local_init_opts(&opts) || criu_local_set_exec_cmd(opts, 2, argv1))
		return 1;
	strdup_fail_at = 1;
	if (criu_local_set_exec_cmd(opts, 2, argv1) != -ENOMEM) {
		fprintf(stderr, "FAIL: injected strdup failure not reported\n");
		return 1;
	}
	if (criu_local_set_exec_cmd(opts, 1, argv2)) {
		fprintf(stderr, "FAIL: set after failure did not succeed\n");
		return 1;
	}
	criu_local_free_opts(opts);
	if (check_leaks(before, "on the strdup failure path"))
		return 1;

	/* fail the array allocation of a repeated set: the call must
	 * report -ENOMEM, and a later set must succeed.
	 */
	opts = NULL;
	if (criu_local_init_opts(&opts) || criu_local_set_exec_cmd(opts, 2, argv1))
		return 1;
	malloc_fail_at = 0;
	if (criu_local_set_exec_cmd(opts, 2, argv1) != -ENOMEM) {
		fprintf(stderr, "FAIL: injected malloc failure not reported\n");
		return 1;
	}
	if (criu_local_set_exec_cmd(opts, 1, argv2)) {
		fprintf(stderr, "FAIL: set after failure did not succeed\n");
		return 1;
	}
	criu_local_free_opts(opts);
	if (check_leaks(before, "on the exec_cmd malloc failure path"))
		return 1;

	/* a failed repeated set must keep the previous value: track the
	 * first set's allocations, guard them during both failure paths,
	 * then check the array slots and the strings behind them.
	 */
	opts = NULL;
	if (criu_local_init_opts(&opts))
		return 1;
	tracked_n = 0;
	track = 1;
	if (criu_local_set_exec_cmd(opts, 2, argv1))
		return 1;
	track = 0;
	if (tracked_n != 3) {
		fprintf(stderr, "FAIL: tracked %d allocations for one exec_cmd set\n", tracked_n);
		return 1;
	}
	guard = 1;
	strdup_fail_at = 1;
	if (criu_local_set_exec_cmd(opts, 2, argv1) != -ENOMEM) {
		fprintf(stderr, "FAIL: injected strdup failure not reported\n");
		return 1;
	}
	malloc_fail_at = 0;
	if (criu_local_set_exec_cmd(opts, 2, argv1) != -ENOMEM) {
		fprintf(stderr, "FAIL: injected malloc failure not reported\n");
		return 1;
	}
	if (criu_local_set_exec_cmd(opts, -1, argv1) != -ENOMEM) {
		fprintf(stderr, "FAIL: negative argc not rejected\n");
		return 1;
	}
	guard = 0;
	{
		char **arr = tracked[0];

		if (arr[0] != tracked[1] || arr[1] != tracked[2] ||
		    strcmp(tracked[1], argv1[0]) || strcmp(tracked[2], argv1[1])) {
			fprintf(stderr, "FAIL: failed set changed the previous exec_cmd value\n");
			return 1;
		}
	}
	if (criu_local_set_exec_cmd(opts, 1, argv2)) {
		fprintf(stderr, "FAIL: set after failure did not succeed\n");
		return 1;
	}
	criu_local_free_opts(opts);
	if (check_leaks(before, "after the preserved failed sets"))
		return 1;

	/* zero, duplicate and many arguments, then a set whose argv
	 * aliases the stored value: the arguments must be copied before
	 * the replaced value is released.
	 */
	opts = NULL;
	if (criu_local_init_opts(&opts) ||
	    criu_local_set_exec_cmd(opts, 0, argv1) ||
	    criu_local_set_exec_cmd(opts, 2, argv_dup) ||
	    criu_local_set_exec_cmd(opts, 64, argv_many))
		return 1;
	tracked_n = 0;
	track = 1;
	if (criu_local_set_exec_cmd(opts, 2, argv1))
		return 1;
	track = 0;
	alias_argv[0] = tracked[1];
	alias_argv[1] = "extra";
	tracked_n = 0;
	track = 1;
	if (criu_local_set_exec_cmd(opts, 2, alias_argv))
		return 1;
	track = 0;
	if (strcmp(tracked[1], "first") || strcmp(tracked[2], "extra")) {
		fprintf(stderr, "FAIL: aliased set did not copy before releasing\n");
		return 1;
	}
	criu_local_free_opts(opts);
	if (check_leaks(before, "on the boundary sets"))
		return 1;

	/* same for the page-server struct allocation */
	opts = NULL;
	if (criu_local_init_opts(&opts) ||
	    criu_local_set_page_server_address_port(opts, "127.0.0.1", 1111))
		return 1;
	malloc_fail_at = 0;
	if (criu_local_set_page_server_address_port(opts, "127.0.0.2", 2222) != -ENOMEM) {
		fprintf(stderr, "FAIL: injected malloc failure not reported\n");
		return 1;
	}
	if (criu_local_set_page_server_address_port(opts, "127.0.0.2", 2222)) {
		fprintf(stderr, "FAIL: set after failure did not succeed\n");
		return 1;
	}
	criu_local_free_opts(opts);
	if (check_leaks(before, "on the page-server malloc failure path"))
		return 1;

	/* and for the page-server address string */
	opts = NULL;
	if (criu_local_init_opts(&opts) ||
	    criu_local_set_page_server_address_port(opts, "127.0.0.1", 1111))
		return 1;
	strdup_fail_at = 0;
	if (criu_local_set_page_server_address_port(opts, "127.0.0.2", 2222) != -ENOMEM) {
		fprintf(stderr, "FAIL: injected strdup failure not reported\n");
		return 1;
	}
	if (criu_local_set_page_server_address_port(opts, "127.0.0.2", 2222)) {
		fprintf(stderr, "FAIL: set after failure did not succeed\n");
		return 1;
	}
	criu_local_free_opts(opts);
	if (check_leaks(before, "on the page-server strdup failure path"))
		return 1;

	printf("PASS: option setter reuse and failure paths leak nothing\n");
	return 0;
}
