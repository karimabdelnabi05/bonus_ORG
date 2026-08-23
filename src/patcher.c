/*
 * patcher.c - CLI entry point for the runtime memory patcher
 *
 * Usage: patcher.exe <process_name> <old_password> <new_password>
 * Example: patcher.exe check.exe 123 abc
 *
 * This program:
 *   1. Validates inputs (new_pw length <= old_pw length)
 *   2. Finds the target process by name
 *   3. Scans all readable memory for the old password string
 *   4. Overwrites every occurrence with the new password
 *   5. Reports results
 *
 * Compile: gcc -o patcher.exe src/patcher.c src/patcher_lib.c
 */

#include <stdio.h>
#include <string.h>
#include "patcher_lib.h"

#define MAX_RESULTS 256

int main(int argc, char *argv[]) {
    printf("=== Runtime Memory Patcher ===\n\n");

    /* Parse command-line arguments */
    if (argc != 4) {
        printf("Usage: %s <process_name> <old_password> <new_password>\n", argv[0]);
        printf("Example: %s check.exe 123 abc\n", argv[0]);
        return 1;
    }

    const char *process_name = argv[1];
    const char *old_pw = argv[2];
    const char *new_pw = argv[3];

    /* Step 1: Validate inputs */
    printf("[1/4] Validating inputs...\n");
    if (!validate_input(old_pw, new_pw)) {
        printf("  ERROR: Invalid inputs.\n");
        printf("  - Both passwords must be non-empty\n");
        printf("  - New password (%zu chars) must be <= old password (%zu chars)\n",
               strlen(new_pw), strlen(old_pw));
        return 1;
    }
    printf("  OK: \"%s\" (%zu chars) -> \"%s\" (%zu chars)\n",
           old_pw, strlen(old_pw), new_pw, strlen(new_pw));

    /* Step 2: Find the target process */
    printf("[2/4] Finding process \"%s\"...\n", process_name);
    DWORD pid = find_process_by_name(process_name);
    if (pid == 0) {
        printf("  ERROR: Process \"%s\" not found. Is it running?\n", process_name);
        return 1;
    }
    printf("  OK: Found PID %lu\n", (unsigned long)pid);

    /* Step 3: Open the process and scan memory */
    printf("[3/4] Scanning process memory for \"%s\"...\n", old_pw);
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
        FALSE, pid
    );
    if (hProcess == NULL) {
        printf("  ERROR: Could not open process (error %lu). Try running as Administrator.\n",
               GetLastError());
        return 1;
    }

    void *addresses[MAX_RESULTS];
    int count = scan_process_memory(hProcess, old_pw, strlen(old_pw),
                                     addresses, MAX_RESULTS);
    if (count == 0) {
        printf("  ERROR: String \"%s\" not found in process memory.\n", old_pw);
        CloseHandle(hProcess);
        return 1;
    }
    printf("  OK: Found %d occurrence(s)\n", count);

    /* Step 4: Patch all occurrences */
    printf("[4/4] Patching memory...\n");
    int patched = 0;
    int failed = 0;

    /*
     * When the new password is shorter, we null-terminate it properly
     * by writing the new password + null bytes to fill the old length.
     */
    size_t old_len = strlen(old_pw);
    size_t new_len = strlen(new_pw);
    char *patch_data = (char *)calloc(old_len + 1, 1); /* zero-filled */
    memcpy(patch_data, new_pw, new_len);

    for (int i = 0; i < count && i < MAX_RESULTS; i++) {
        printf("  [%d] Address: 0x%p -> ", i + 1, addresses[i]);
        if (patch_memory(hProcess, addresses[i], patch_data, old_len)) {
            printf("PATCHED\n");
            patched++;
        } else {
            printf("FAILED\n");
            failed++;
        }
    }

    free(patch_data);
    CloseHandle(hProcess);

    /* Summary */
    printf("\n--- Results ---\n");
    printf("Occurrences found:   %d\n", count);
    printf("Successfully patched: %d\n", patched);
    if (failed > 0) {
        printf("Failed:              %d\n", failed);
    }
    printf("\nThe password in \"%s\" has been changed from \"%s\" to \"%s\".\n",
           process_name, old_pw, new_pw);
    printf("Try it - the new password should now work!\n");

    return (patched > 0) ? 0 : 1;
}
