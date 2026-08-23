/*
 * test_harness.h - Lightweight C test framework
 *
 * Provides simple assertion macros and test runner infrastructure.
 * No external dependencies - just include this header.
 *
 * Usage:
 *   TEST(test_name) {
 *       ASSERT(condition);
 *       ASSERT_STR_EQ(actual, expected);
 *       ASSERT_INT_EQ(actual, expected);
 *   }
 *
 *   int main(void) {
 *       RUN_TEST(test_name);
 *       TEST_REPORT();
 *       return TEST_EXIT_CODE();
 *   }
 */

#ifndef TEST_HARNESS_H
#define TEST_HARNESS_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Counters */
static int _tests_run = 0;
static int _tests_passed = 0;
static int _tests_failed = 0;
static int _current_test_failed = 0;

/* Colors for terminal output */
#define COLOR_RED     "\033[1;31m"
#define COLOR_GREEN   "\033[1;32m"
#define COLOR_YELLOW  "\033[1;33m"
#define COLOR_RESET   "\033[0m"

/* Define a test function */
#define TEST(name) static void name(void)

/* Run a test */
#define RUN_TEST(name) do { \
    _current_test_failed = 0; \
    _tests_run++; \
    printf("  %-50s ", #name); \
    name(); \
    if (_current_test_failed) { \
        _tests_failed++; \
        printf(COLOR_RED "FAIL" COLOR_RESET "\n"); \
    } else { \
        _tests_passed++; \
        printf(COLOR_GREEN "PASS" COLOR_RESET "\n"); \
    } \
} while(0)

/* Basic assertion */
#define ASSERT(condition) do { \
    if (!(condition)) { \
        printf("\n    " COLOR_RED "ASSERT FAILED" COLOR_RESET ": %s (line %d)\n", \
               #condition, __LINE__); \
        _current_test_failed = 1; \
        return; \
    } \
} while(0)

/* Assert two strings are equal */
#define ASSERT_STR_EQ(actual, expected) do { \
    const char *_a = (actual); \
    const char *_e = (expected); \
    if (_a == NULL || _e == NULL || strcmp(_a, _e) != 0) { \
        printf("\n    " COLOR_RED "ASSERT_STR_EQ FAILED" COLOR_RESET \
               " (line %d):\n      expected: \"%s\"\n      actual:   \"%s\"\n", \
               __LINE__, _e ? _e : "(null)", _a ? _a : "(null)"); \
        _current_test_failed = 1; \
        return; \
    } \
} while(0)

/* Assert string contains substring */
#define ASSERT_STR_CONTAINS(haystack, needle) do { \
    const char *_h = (haystack); \
    const char *_n = (needle); \
    if (_h == NULL || _n == NULL || strstr(_h, _n) == NULL) { \
        printf("\n    " COLOR_RED "ASSERT_STR_CONTAINS FAILED" COLOR_RESET \
               " (line %d):\n      string:   \"%s\"\n      expected: contains \"%s\"\n", \
               __LINE__, _h ? _h : "(null)", _n ? _n : "(null)"); \
        _current_test_failed = 1; \
        return; \
    } \
} while(0)

/* Assert two integers are equal */
#define ASSERT_INT_EQ(actual, expected) do { \
    int _a = (actual); \
    int _e = (expected); \
    if (_a != _e) { \
        printf("\n    " COLOR_RED "ASSERT_INT_EQ FAILED" COLOR_RESET \
               " (line %d):\n      expected: %d\n      actual:   %d\n", \
               __LINE__, _e, _a); \
        _current_test_failed = 1; \
        return; \
    } \
} while(0)

/* Assert value is not zero / not NULL */
#define ASSERT_NOT_NULL(ptr) do { \
    if ((ptr) == NULL) { \
        printf("\n    " COLOR_RED "ASSERT_NOT_NULL FAILED" COLOR_RESET \
               " (line %d): " #ptr " is NULL\n", __LINE__); \
        _current_test_failed = 1; \
        return; \
    } \
} while(0)

/* Assert value is zero / NULL */
#define ASSERT_NULL(ptr) do { \
    if ((ptr) != NULL) { \
        printf("\n    " COLOR_RED "ASSERT_NULL FAILED" COLOR_RESET \
               " (line %d): " #ptr " is not NULL\n", __LINE__); \
        _current_test_failed = 1; \
        return; \
    } \
} while(0)

/* Print test report */
#define TEST_REPORT() do { \
    printf("\n----------------------------------------\n"); \
    printf("Tests: %d total, " COLOR_GREEN "%d passed" COLOR_RESET, \
           _tests_run, _tests_passed); \
    if (_tests_failed > 0) \
        printf(", " COLOR_RED "%d failed" COLOR_RESET, _tests_failed); \
    printf("\n"); \
    if (_tests_failed == 0) \
        printf(COLOR_GREEN "ALL TESTS PASSED" COLOR_RESET "\n"); \
    else \
        printf(COLOR_RED "SOME TESTS FAILED" COLOR_RESET "\n"); \
    printf("----------------------------------------\n"); \
} while(0)

/* Return exit code based on test results */
#define TEST_EXIT_CODE() (_tests_failed > 0 ? 1 : 0)

#endif /* TEST_HARNESS_H */
