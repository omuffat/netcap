/*
 * test_harness.h — minimal test harness for netcap unit tests.
 *
 * Usage:
 *   - Define test functions with signature: static void test_foo(void)
 *   - Use EXPECT(condition) to assert conditions; failures are counted but do
 *     not abort the test function.
 *   - In main(), call RUN_TEST(test_foo) for each test function, then return
 *     TEST_RESULT() to exit with 0 on success or 1 on failure.
 */

#ifndef CN_TEST_HARNESS_H
#define CN_TEST_HARNESS_H

#include <stdio.h>

/* Global counters — reset between RUN_TEST() calls. */
static int cn_test_failures = 0;  /* Failures across all tests. */
static int cn_test_total    = 0;  /* Total tests run. */
static int cn_test_fn_fail  = 0;  /* Failures in the current test function. */

/*
 * EXPECT(cond) — check a condition within a test function.
 * Prints file and line number on failure; increments failure counters.
 */
#define EXPECT(cond) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            cn_test_fn_fail++; \
            cn_test_failures++; \
        } \
    } while (0)

/*
 * EXPECT_EQ(a, b) — check integer equality; prints both values on failure.
 */
#define EXPECT_EQ(a, b) \
    do { \
        long long _a = (long long)(a); \
        long long _b = (long long)(b); \
        if (_a != _b) { \
            fprintf(stderr, "  FAIL %s:%d: %s == %s  (%lld != %lld)\n", \
                    __FILE__, __LINE__, #a, #b, _a, _b); \
            cn_test_fn_fail++; \
            cn_test_failures++; \
        } \
    } while (0)

/*
 * RUN_TEST(fn) — call test function fn(), report PASS or FAIL.
 */
#define RUN_TEST(fn) \
    do { \
        cn_test_fn_fail = 0; \
        cn_test_total++; \
        (fn)(); \
        if (cn_test_fn_fail == 0) { \
            printf("  PASS  " #fn "\n"); \
        } else { \
            printf("  FAIL  " #fn " (%d assertion(s) failed)\n", \
                   cn_test_fn_fail); \
        } \
    } while (0)

/*
 * TEST_RESULT() — returns 0 if all tests passed, 1 otherwise.
 * Print a summary line before returning.
 */
#define TEST_RESULT() \
    ( \
        printf("%s: %d/%d passed\n", \
               cn_test_failures == 0 ? "PASS" : "FAIL", \
               cn_test_total - cn_test_failures, cn_test_total), \
        cn_test_failures > 0 ? 1 : 0 \
    )

#endif /* CN_TEST_HARNESS_H */
