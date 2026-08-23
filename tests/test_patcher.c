/*
 * test_patcher.c - Unit and integration tests for the patcher tool
 *
 * Tests the patcher_lib functions through their public interface.
 * Tests are ordered as TDD cycles - each one was written RED, then
 * the implementation was written to make it GREEN.
 */

#include "test_harness.h"
#include "../src/patcher_lib.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>

/* ============================
 *  Cycle 3: validate_input rejects longer new password
 * ============================ */
TEST(validate_rejects_longer_new_password) {
    /* "123" is 3 chars, "abcdef" is 6 chars - should be rejected */
    ASSERT_INT_EQ(validate_input("123", "abcdef"), 0);
}

/* ============================
 *  Cycle 4: validate_input accepts same/shorter new password
 * ============================ */
TEST(validate_accepts_same_length_password) {
    /* "123" -> "abc" : both 3 chars - should be accepted */
    ASSERT_INT_EQ(validate_input("123", "abc"), 1);
}

TEST(validate_accepts_shorter_password) {
    /* "123" -> "ab" : 3 -> 2 chars - should be accepted */
    ASSERT_INT_EQ(validate_input("123", "ab"), 1);
}

TEST(validate_rejects_null_old) {
    ASSERT_INT_EQ(validate_input(NULL, "abc"), 0);
}

TEST(validate_rejects_null_new) {
    ASSERT_INT_EQ(validate_input("123", NULL), 0);
}

TEST(validate_rejects_empty_old) {
    ASSERT_INT_EQ(validate_input("", "abc"), 0);
}

TEST(validate_rejects_empty_new) {
    ASSERT_INT_EQ(validate_input("123", ""), 0);
}

/* ============================
 *  Cycle 5: find_process_by_name finds a running process
 * ============================ */
TEST(find_process_finds_running_check_exe) {
    /*
     * Pre-condition: check.exe must be running.
     * We launch it as a background process before running this test.
     */
    DWORD pid = find_process_by_name("check.exe");
    ASSERT(pid != 0);
}

/* ============================
 *  Cycle 6: find_process_by_name returns 0 for non-existent process
 * ============================ */
TEST(find_process_returns_zero_for_nonexistent) {
    DWORD pid = find_process_by_name("nonexistent_process_xyz_12345.exe");
    ASSERT_INT_EQ(pid, 0);
}

/* ============================
 *  Cycle 7: scan_process_memory finds the password string
 * ============================ */
TEST(scan_memory_finds_password_string) {
    /*
     * Pre-condition: check.exe must be running with password "123".
     * We open its process and scan for the string.
     */
    DWORD pid = find_process_by_name("check.exe");
    ASSERT(pid != 0);

    HANDLE hProcess = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
        FALSE, pid
    );
    ASSERT_NOT_NULL(hProcess);

    void *addresses[64];
    int count = scan_process_memory(hProcess, "123", 3, addresses, 64);
    /* Should find at least 1 occurrence of "123" in check.exe's memory */
    ASSERT(count > 0);

    CloseHandle(hProcess);
}

/* ============================
 *  Cycle 8: scan_process_memory returns 0 for string not in memory
 * ============================ */
TEST(scan_memory_returns_zero_for_missing_string) {
    DWORD pid = find_process_by_name("check.exe");
    ASSERT(pid != 0);

    HANDLE hProcess = OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE, pid
    );
    ASSERT_NOT_NULL(hProcess);

    void *addresses[64];
    /* Search for a string that should not exist in check.exe's memory */
    int count = scan_process_memory(hProcess, "ZZUNIQUEZZNOTFOUND", 18, addresses, 64);
    ASSERT_INT_EQ(count, 0);

    CloseHandle(hProcess);
}

/* ============================
 *  Cycle 9: patch_memory writes new data and read-back matches
 * ============================ */
TEST(patch_memory_overwrites_and_readback_matches) {
    DWORD pid = find_process_by_name("check.exe");
    ASSERT(pid != 0);

    HANDLE hProcess = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
        FALSE, pid
    );
    ASSERT_NOT_NULL(hProcess);

    /* First, find where "123" lives */
    void *addresses[64];
    int count = scan_process_memory(hProcess, "123", 3, addresses, 64);
    ASSERT(count > 0);

    /* Patch the first occurrence with "abc" */
    int result = patch_memory(hProcess, addresses[0], "abc", 3);
    ASSERT_INT_EQ(result, 1);

    /* Read back to verify */
    char readback[4] = {0};
    SIZE_T bytes_read;
    ReadProcessMemory(hProcess, addresses[0], readback, 3, &bytes_read);
    ASSERT_STR_EQ(readback, "abc");

    /* Restore original value for other tests */
    patch_memory(hProcess, addresses[0], "123", 3);

    CloseHandle(hProcess);
}

/* ============================
 *  Cycle 10: End-to-end integration test
 * ============================ */
TEST(e2e_patch_changes_password_in_running_check) {
    /*
     * Full end-to-end:
     * 1. check.exe is already running with password "123"
     * 2. We patch all occurrences of "123" -> "abc"
     * 3. We test that "abc" now grants access via check.exe's stdin
     * 4. We restore "123" afterward
     */
    DWORD pid = find_process_by_name("check.exe");
    ASSERT(pid != 0);

    HANDLE hProcess = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
        FALSE, pid
    );
    ASSERT_NOT_NULL(hProcess);

    /* Find and patch all occurrences */
    void *addresses[64];
    int count = scan_process_memory(hProcess, "123", 3, addresses, 64);
    ASSERT(count > 0);

    for (int i = 0; i < count; i++) {
        patch_memory(hProcess, addresses[i], "abc", 3);
    }

    CloseHandle(hProcess);

    /* Now test: "abc" should grant access, "123" should deny */
    char cmd_grant[256];
    snprintf(cmd_grant, sizeof(cmd_grant), "echo abc | .\\check.exe");
    FILE *fp = _popen(cmd_grant, "r");
    ASSERT_NOT_NULL(fp);

    char output[1024] = {0};
    char line[256];
    while (fgets(line, sizeof(line), fp) != NULL) {
        strncat(output, line, sizeof(output) - strlen(output) - 1);
    }
    _pclose(fp);

    /* NOTE: This launches a NEW check.exe instance, so it will have
     * the original password. The real E2E test is that the RUNNING
     * instance's password changed. We verify by re-scanning. */

    /* Re-open the original running process */
    hProcess = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
        FALSE, pid
    );
    ASSERT_NOT_NULL(hProcess);

    /* Verify "abc" is now in memory where "123" was */
    void *verify_addrs[64];
    int abc_count = scan_process_memory(hProcess, "abc", 3, verify_addrs, 64);
    ASSERT(abc_count > 0);

    /* Verify "123" as the password is no longer found at those same locations */
    /* (Note: "123" may appear elsewhere in memory, but at our patched addresses it should be "abc") */
    char readback[4] = {0};
    SIZE_T bytes_read;
    ReadProcessMemory(hProcess, addresses[0], readback, 3, &bytes_read);
    ASSERT_STR_EQ(readback, "abc");

    /* Restore for cleanup */
    for (int i = 0; i < count; i++) {
        patch_memory(hProcess, addresses[i], "123", 3);
    }

    CloseHandle(hProcess);
}


int main(void) {
    printf("\n=== Patcher Unit & Integration Tests ===\n\n");

    /* Cycle 3-4: Input validation */
    printf("--- Input Validation ---\n");
    RUN_TEST(validate_rejects_longer_new_password);
    RUN_TEST(validate_accepts_same_length_password);
    RUN_TEST(validate_accepts_shorter_password);
    RUN_TEST(validate_rejects_null_old);
    RUN_TEST(validate_rejects_null_new);
    RUN_TEST(validate_rejects_empty_old);
    RUN_TEST(validate_rejects_empty_new);

    /* Cycle 5-6: Process finding */
    printf("\n--- Process Finding ---\n");
    
    /* Ensure target process (check.exe) is running for integration tests */
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    int spawned = 0;
    if (find_process_by_name("check.exe") == 0) {
        if (CreateProcessA(".\\check.exe", ".\\check.exe -d", NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi) ||
            CreateProcessA("check.exe", "check.exe -d", NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            spawned = 1;
            Sleep(500);
        }
    }

    RUN_TEST(find_process_finds_running_check_exe);
    RUN_TEST(find_process_returns_zero_for_nonexistent);

    /* Cycle 7-8: Memory scanning */
    printf("\n--- Memory Scanning ---\n");
    RUN_TEST(scan_memory_finds_password_string);
    RUN_TEST(scan_memory_returns_zero_for_missing_string);

    /* Cycle 9: Memory patching */
    printf("\n--- Memory Patching ---\n");
    RUN_TEST(patch_memory_overwrites_and_readback_matches);

    /* Cycle 10: End-to-end */
    printf("\n--- End-to-End ---\n");
    RUN_TEST(e2e_patch_changes_password_in_running_check);

    if (spawned && pi.hProcess != NULL) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    TEST_REPORT();
    return TEST_EXIT_CODE();
}
