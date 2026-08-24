/*
 * debug_patcher.c - Fully Automated Runtime Password Patcher for Hashed Passwords
 *
 * How it works:
 *   1. Finds the running check.exe process by name using Win32 Toolhelp32 API.
 *   2. Opens check.exe memory with Read/Write access.
 *   3. Computes the target hash for <new_password> locally (djb2 hash).
 *   4. Scans check.exe's memory for the stored hash value (401824839).
 *   5. Overwrites the stored hash with the new password hash via WriteProcessMemory.
 *   6. Password is changed instantly (<10ms) without restarting check.exe!
 *
 * Usage:
 *   .\build\debug_patcher.exe check.exe <new_password>
 *
 * Compile: gcc -o debug_patcher.exe src/debug_patcher.c
 */

#undef UNICODE
#undef _UNICODE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>

/* Target stored hash value in check.c: hash("s3cr3t") = 401824839 */
#define INITIAL_STORED_HASH 401824839UL

/* djb2 hash function matching check.c */
static unsigned long hash_password(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

/* Find PID of a running process by executable name */
static DWORD find_process_by_name(const char *name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snap, &entry)) {
        do {
            if (_stricmp(entry.szExeFile, name) == 0) {
                DWORD pid = entry.th32ProcessID;
                CloseHandle(snap);
                return pid;
            }
        } while (Process32Next(snap, &entry));
    }
    CloseHandle(snap);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <process_name> <new_password>\n", argv[0]);
        printf("Example: %s check.exe pass\n", argv[0]);
        return 1;
    }

    const char *process_name = argv[1];
    const char *new_password = argv[2];
    unsigned long new_hash = hash_password(new_password);

    printf("=== Automated Runtime Memory Patcher ===\n\n");
    printf("[1/4] Validating inputs...\n");
    printf("  Target password: \"%s\" (hash = %lu)\n\n", new_password, new_hash);

    /* Step 1: Find process */
    printf("[2/4] Finding process \"%s\"...\n", process_name);
    DWORD pid = find_process_by_name(process_name);
    if (pid == 0) {
        printf("  ERROR: Process \"%s\" is not running.\n", process_name);
        printf("  Please start %s in another window first.\n", process_name);
        return 1;
    }
    printf("  OK: Found PID %lu\n\n", (unsigned long)pid);

    /* Step 2: Open process memory */
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
        FALSE, pid
    );
    if (!hProcess) {
        printf("  ERROR: Cannot open process memory (error %lu).\n", GetLastError());
        return 1;
    }

    /* Step 3: Scan memory for stored_hash */
    printf("[3/4] Scanning process memory for stored hash (%lu)...\n", INITIAL_STORED_HASH);

    MEMORY_BASIC_INFORMATION mbi;
    unsigned char *scan_addr = NULL;
    int patched_count = 0;

    while (VirtualQueryEx(hProcess, scan_addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY | PAGE_READONLY | PAGE_EXECUTE_READ)) &&
            !(mbi.Protect & PAGE_GUARD) &&
            !(mbi.Protect & PAGE_NOACCESS) &&
            mbi.RegionSize < 10 * 1024 * 1024) {

            unsigned char *buf = (unsigned char *)malloc(mbi.RegionSize);
            SIZE_T br = 0;

            if (ReadProcessMemory(hProcess, mbi.BaseAddress, buf, mbi.RegionSize, &br) && br >= sizeof(unsigned long)) {
                for (SIZE_T off = 0; off + sizeof(unsigned long) <= br; off += 4) {
                    unsigned long *val_ptr = (unsigned long *)(buf + off);

                    if (*val_ptr == INITIAL_STORED_HASH || *val_ptr == new_hash) {
                        void *target_addr = (unsigned char *)mbi.BaseAddress + off;

                        /* Temporarily make page executable read/write */
                        DWORD old_protect;
                        if (VirtualProtectEx(hProcess, target_addr, sizeof(unsigned long), PAGE_EXECUTE_READWRITE, &old_protect)) {
                            SIZE_T written = 0;
                            if (WriteProcessMemory(hProcess, target_addr, &new_hash, sizeof(unsigned long), &written) && written == sizeof(unsigned long)) {
                                printf("  PATCHED @ %p (hash updated to %lu)\n", target_addr, new_hash);
                                patched_count++;
                            }
                            VirtualProtectEx(hProcess, target_addr, sizeof(unsigned long), old_protect, &old_protect);
                        }
                    }
                }
            }
            free(buf);
        }

        scan_addr = (unsigned char *)mbi.BaseAddress + mbi.RegionSize;
        if ((ULONG_PTR)scan_addr < (ULONG_PTR)mbi.BaseAddress) break;
    }

    CloseHandle(hProcess);

    printf("\n[4/4] Results:\n");
    if (patched_count > 0) {
        printf("  SUCCESS: Patched %d memory location(s).\n", patched_count);
        printf("\nPassword in \"%s\" changed to: \"%s\"\n", process_name, new_password);
        printf("Go to your %s window and type '%s' to confirm Access Granted!\n", process_name, new_password);
        return 0;
    } else {
        printf("  FAILED: Could not find stored hash in memory.\n");
        printf("  Make sure %s is running.\n", process_name);
        return 1;
    }
}
