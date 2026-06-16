CRIU_ROOT := ../../..
CRIU_SRC := $(CRIU_ROOT)/criu
CRIU_INC := $(CRIU_SRC)/include
COMMON_INC := $(CRIU_ROOT)/include

CC ?= gcc
CFLAGS := -Wall -Wextra -g -O2 -pthread -std=gnu11 \
	  -iquote shims -iquote $(CRIU_INC) -iquote $(COMMON_INC) -iquote .

LDFLAGS := -pthread

# Header-only tests (portable, work on macOS + Linux)
TESTS_PORTABLE := test_batch_bitmap test_spsc_queue test_mpsc_queue \
		  test_spmc_queue test_atomic_bitmap test_stress \
		  test_remove_range_leak

# Tests linking real CLONE .c files (Linux-only: need pthread_spinlock_t, mmap alignment)
TESTS_LINUX := test_unmapped_tracker test_page_pool test_page_state_tracker \
	       test_hung_page_tracker

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
TESTS := $(TESTS_PORTABLE) $(TESTS_LINUX)
else
TESTS := $(TESTS_PORTABLE)
endif

all: $(TESTS)

# Header-only tests
test_batch_bitmap: test_batch_bitmap.c test_harness.h shims/page.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_spsc_queue: test_spsc_queue.c test_harness.h shims/page.h shims/criu-log.h shims/xmalloc.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_mpsc_queue: test_mpsc_queue.c test_harness.h shims/page.h shims/criu-log.h shims/xmalloc.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_spmc_queue: test_spmc_queue.c test_harness.h shims/page.h shims/criu-log.h shims/xmalloc.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_remove_range_leak: test_remove_range_leak.c test_harness.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_atomic_bitmap: test_atomic_bitmap.c test_harness.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_stress: test_stress.c test_harness.h shims/page.h shims/criu-log.h shims/xmalloc.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Tests linking against CLONE source files (Linux-only)
test_unmapped_tracker: test_unmapped_tracker.c $(CRIU_SRC)/clone/unmapped-tracker.c \
		       test_harness.h shims/page.h shims/int.h shims/criu-log.h shims/xmalloc.h
	$(CC) $(CFLAGS) -o $@ test_unmapped_tracker.c $(CRIU_SRC)/clone/unmapped-tracker.c $(LDFLAGS)

test_page_pool: test_page_pool.c $(CRIU_SRC)/clone/page-pool.c \
		test_harness.h shims/page.h shims/criu-log.h
	$(CC) $(CFLAGS) -o $@ test_page_pool.c $(CRIU_SRC)/clone/page-pool.c $(LDFLAGS)

test_page_state_tracker: test_page_state_tracker.c $(CRIU_SRC)/clone/page-state-tracker.c \
			 test_harness.h shims/page.h shims/int.h shims/criu-log.h shims/xmalloc.h shims/util.h
	$(CC) $(CFLAGS) -DCONFIG_PAGE_STATE_TRACKER -o $@ \
		test_page_state_tracker.c $(CRIU_SRC)/clone/page-state-tracker.c $(LDFLAGS)

test_hung_page_tracker: test_hung_page_tracker.c $(CRIU_SRC)/clone/hung-page-tracker.c \
			test_harness.h shims/page.h shims/int.h shims/criu-log.h shims/xmalloc.h
	$(CC) $(CFLAGS) -DCONFIG_HUNG_PAGE_TRACKER -o $@ \
		test_hung_page_tracker.c $(CRIU_SRC)/clone/hung-page-tracker.c $(LDFLAGS)

check: all
	@echo "=== CLONE Unit Tests ==="; \
	failures=0; \
	total_passed=0; \
	total_failed=0; \
	for t in $(TESTS); do \
		echo ""; \
		echo "--- $$t ---"; \
		output=$$(./$$t 2>&1); \
		rc=$$?; \
		echo "$$output"; \
		if [ $$rc -ne 0 ]; then failures=$$((failures + 1)); fi; \
		p=$$(echo "$$output" | sed -n 's/^ *\([0-9]*\) passed.*/\1/p' | tail -1); \
		f=$$(echo "$$output" | sed -n 's/^.*passed, *\([0-9]*\) failed.*/\1/p' | tail -1); \
		total_passed=$$((total_passed + $${p:-0})); \
		total_failed=$$((total_failed + $${f:-0})); \
	done; \
	echo ""; \
	echo "=================="; \
	echo "TOTAL: $$total_passed passed, $$total_failed failed ($$failures suite(s) failed)"; \
	if [ $$failures -eq 0 ]; then \
		echo "ALL TESTS PASSED"; \
	else \
		exit 1; \
	fi

clean:
	rm -f $(TESTS_PORTABLE) $(TESTS_LINUX)

.PHONY: all check clean
