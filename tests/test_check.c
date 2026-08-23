/*
 * test_check.c - Integration tests for check.exe
 *
 * Tests the check program through its CLI interface (stdin/stdout)
 * by launching it as a subprocess.
 */

#include "test_harness.h"
#include <stdio.h>
#include <string.h>

/*
 * Helper: run check.exe with a given password input and capture stdout.
 * Returns the output as a static buffer (not thread-safe, fine for tests).
 */
static char* run_check_with_input(const char *password) {
    static char output[1024];
    memset(output, 0, sizeof(output));

    /*
     * Use _popen to launch check.exe with the password piped to stdin.
     * The 'echo' command sends the password followed by a newline,
     * then we pipe it into check.exe. We only read the first response.
     */
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "echo %s | .\\check.exe", password);

    FILE *fp = _popen(cmd, "r");
    if (fp == NULL) {
        strcpy(output, "ERROR: failed to run check.exe");
        return output;
    }

    /* Read all output lines */
    char line[256];
    output[0] = '\0';
    while (fgets(line, sizeof(line), fp) != NULL) {
        strncat(output, line, sizeof(output) - strlen(output) - 1);
    }
    _pclose(fp);
    return output;
}

/* ============================
 *  Cycle 1: Correct password
 * ============================ */
TEST(correct_password_grants_access) {
    char *result = run_check_with_input("123");
    ASSERT_STR_CONTAINS(result, "Access Granted");
}

/* ============================
 *  Cycle 2: Wrong password
 * ============================ */
TEST(wrong_password_denies_access) {
    char *result = run_check_with_input("wrongpassword");
    ASSERT_STR_CONTAINS(result, "Access Denied");
}

int main(void) {
    printf("\n=== check.exe Integration Tests ===\n\n");

    RUN_TEST(correct_password_grants_access);
    RUN_TEST(wrong_password_denies_access);

    TEST_REPORT();
    return TEST_EXIT_CODE();
}
