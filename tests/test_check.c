/*
 * test_check.c - Integration tests for the hashed check.exe
 *
 * Tests that check.exe correctly grants/denies access based on
 * hashed password comparison.
 */

#include "test_harness.h"
#include <stdio.h>
#include <string.h>

/* Test 1: Correct password grants access */
void correct_password_grants_access(void) {
    FILE *fp = _popen("echo s3cr3t | ..\\build\\check.exe", "r");
    ASSERT_NOT_NULL(fp);

    char output[2048] = {0};
    char line[256];
    while (fgets(line, sizeof(line), fp) != NULL) {
        strncat(output, line, sizeof(output) - strlen(output) - 1);
    }
    _pclose(fp);

    ASSERT_STR_CONTAINS(output, "Access Granted");
}

/* Test 2: Wrong password denies access */
void wrong_password_denies_access(void) {
    FILE *fp = _popen("echo wrongpassword | ..\\build\\check.exe", "r");
    ASSERT_NOT_NULL(fp);

    char output[2048] = {0};
    char line[256];
    while (fgets(line, sizeof(line), fp) != NULL) {
        strncat(output, line, sizeof(output) - strlen(output) - 1);
    }
    _pclose(fp);

    ASSERT_STR_CONTAINS(output, "Access Denied");
}

/* Test 3: Plaintext password string is NOT in memory
 * (verify that searching for "s3cr3t" in the binary yields no result) */
void plaintext_not_in_binary(void) {
    FILE *fp = fopen("..\\build\\check.exe", "rb");
    ASSERT_NOT_NULL(fp);

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *data = (char *)malloc(size);
    fread(data, 1, size, fp);
    fclose(fp);

    /* Search for "s3cr3t" in the binary - should NOT be found */
    int found = 0;
    for (long i = 0; i <= size - 6; i++) {
        if (memcmp(data + i, "s3cr3t", 6) == 0) {
            found = 1;
            break;
        }
    }
    free(data);

    ASSERT(found == 0);  /* Password must NOT appear in binary */
}

int main(void) {
    printf("\n=== check.exe (Hashed) Integration Tests ===\n\n");

    RUN_TEST(correct_password_grants_access);
    RUN_TEST(wrong_password_denies_access);
    RUN_TEST(plaintext_not_in_binary);

    TEST_REPORT();
    return TEST_EXIT_CODE();
}
