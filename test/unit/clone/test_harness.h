#ifndef __TEST_HARNESS_H__
#define __TEST_HARNESS_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int __test_failures = 0;
static int __test_passes = 0;

#define TEST_ASSERT(cond, msg) do { \
	if (!(cond)) { \
		fprintf(stderr, "  FAIL [%s:%d]: %s\n", __FILE__, __LINE__, msg); \
		__test_failures++; \
	} else { \
		__test_passes++; \
	} \
} while (0)

#define TEST_ASSERT_EQ(a, b, msg) do { \
	long _a = (long)(a); \
	long _b = (long)(b); \
	if (_a != _b) { \
		fprintf(stderr, "  FAIL [%s:%d]: %s (got %ld, expected %ld)\n", \
			__FILE__, __LINE__, msg, _a, _b); \
		__test_failures++; \
	} else { \
		__test_passes++; \
	} \
} while (0)

#define TEST_SUMMARY() do { \
	printf("\n  %d passed, %d failed\n", __test_passes, __test_failures); \
	return __test_failures > 0 ? 1 : 0; \
} while (0)

#define RUN_TEST(fn) do { \
	printf("  %-40s", #fn); \
	int _before = __test_failures; \
	fn(); \
	if (__test_failures == _before) \
		printf("OK\n"); \
	else \
		printf("FAILED\n"); \
} while (0)

#endif /* __TEST_HARNESS_H__ */
