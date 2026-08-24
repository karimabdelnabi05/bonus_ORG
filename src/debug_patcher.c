/*
 * debug_patcher.c - Runtime Password Patcher for Hashed Passwords
 *
 * Supports TWO operational modes:
 *
 *   MODE 1: Direct Value Search (Default - Instant <10ms)
 *     - Usage:  .\build\debug_patcher.exe check.exe pass
 *     - Scans RAM for the known initial stored hash (401824839) in check.exe's .data section.
 *
 *   MODE 2: Zero-Knowledge Differential Search (--diff flag)
 *     - Usage:  .\build\debug_patcher.exe check.exe pass --diff
 *     - Takes 2 RAM snapshots after different inputs ("aaaa" vs "bbbb").
 *     - Finds the stored_hash address automatically without knowing initial hash value (401824839).
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

/* Patch a single unsigned long at a target address */
static int patch_value(HANDLE hProcess, void *target_addr, unsigned long new_value) {
    DWORD old_protect;
    if (!VirtualProtectEx(hProcess, target_addr, sizeof(unsigned long), PAGE_EXECUTE_READWRITE, &old_protect)) {
        return 0;
    }

    SIZE_T bytes_written = 0;
    BOOL ok = WriteProcessMemory(hProcess, target_addr, &new_value, sizeof(unsigned long), &bytes_written);

    VirtualProtectEx(hProcess, target_addr, sizeof(unsigned long), old_protect, &old_protect);
    return ok && (bytes_written == sizeof(unsigned long));
}

typedef struct {
    void *base;
    SIZE_T size;
    unsigned char *data;
    DWORD protect;
    DWORD type;
} MemRegion;

/* Read all committed memory regions */
static int snapshot_memory(HANDLE hProcess, MemRegion **regions, int *count) {
    *count = 0;
    int capacity = 256;
    *regions = (MemRegion *)malloc(capacity * sizeof(MemRegion));

    MEMORY_BASIC_INFORMATION mbi;
    unsigned char *scan_addr = NULL;

    while (VirtualQueryEx(hProcess, scan_addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY | PAGE_READONLY | PAGE_EXECUTE_READ)) &&
            !(mbi.Protect & PAGE_GUARD) &&
            !(mbi.Protect & PAGE_NOACCESS) &&
            mbi.RegionSize < 10 * 1024 * 1024) {

            unsigned char *buf = (unsigned char *)malloc(mbi.RegionSize);
            SIZE_T br = 0;
            if (ReadProcessMemory(hProcess, mbi.BaseAddress, buf, mbi.RegionSize, &br) && br > 0) {
                if (*count >= capacity) {
                    capacity *= 2;
                    *regions = (MemRegion *)realloc(*regions, capacity * sizeof(MemRegion));
                }
                (*regions)[*count].base = mbi.BaseAddress;
                (*regions)[*count].size = br;
                (*regions)[*count].data = buf;
                (*regions)[*count].protect = mbi.Protect;
                (*regions)[*count].type = mbi.Type;
                (*count)++;
            } else {
                free(buf);
            }
        }
        scan_addr = (unsigned char *)mbi.BaseAddress + mbi.RegionSize;
        if ((ULONG_PTR)scan_addr < (ULONG_PTR)mbi.BaseAddress) break;
    }
    return *count;
}

static void free_snapshot(MemRegion *regions, int count) {
    for (int i = 0; i < count; i++) {
        free(regions[i].data);
    }
    free(regions);
}

/* Mode 1: Direct Value Search */
static int run_mode_1_direct(HANDLE hProcess, const char *process_name, const char *new_password, unsigned long new_hash) {
    printf("[MODE 1: Direct Search]\n");
    printf("Scanning process memory for initial hash (%lu)...\n", INITIAL_STORED_HASH);

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

                    if (*val_ptr == INITIAL_STORED_HASH) {
                        void *target_addr = (unsigned char *)mbi.BaseAddress + off;
                        if (patch_value(hProcess, target_addr, new_hash)) {
                            printf("  PATCHED @ %p (stored_hash updated to %lu)\n", target_addr, new_hash);
                            patched_count++;
                        }
                    }
                }
            }
            free(buf);
        }
        scan_addr = (unsigned char *)mbi.BaseAddress + mbi.RegionSize;
        if ((ULONG_PTR)scan_addr < (ULONG_PTR)mbi.BaseAddress) break;
    }

    if (patched_count > 0) {
        printf("\nSUCCESS: Password in \"%s\" changed to \"%s\"!\n", process_name, new_password);
        return 0;
    } else {
        printf("\nFAILED: Could not locate stored hash in memory.\n");
        return 1;
    }
}

/* Mode 2: Zero-Knowledge Differential Snapshot Search */
static int run_mode_2_diff(HANDLE hProcess, const char *process_name, const char *new_password, unsigned long new_hash) {
    printf("[MODE 2: Zero-Knowledge Differential Search]\n\n");

    printf("Step 1: Type a WRONG password (e.g. 'aaaa') into %s\n", process_name);
    printf("  >> After typing 'aaaa' and pressing Enter in %s, press Enter here...", process_name);
    fflush(stdout);
    getchar();

    MemRegion *snapA = NULL;
    int countA = 0;
    snapshot_memory(hProcess, &snapA, &countA);
    printf("  OK: Captured Snapshot A (%d regions).\n\n", countA);

    printf("Step 2: Type a DIFFERENT wrong password (e.g. 'bbbb') into %s\n", process_name);
    printf("  >> After typing 'bbbb' and pressing Enter in %s, press Enter here...", process_name);
    fflush(stdout);
    getchar();

    MemRegion *snapB = NULL;
    int countB = 0;
    snapshot_memory(hProcess, &snapB, &countB);
    printf("  OK: Captured Snapshot B (%d regions).\n\n", countB);

    printf("Analyzing RAM differences to locate stored_hash in .data section...\n");
    void *stored_hash_addr = NULL;
    unsigned long old_val = 0;

    for (int i = 0; i < countA && i < countB && !stored_hash_addr; i++) {
        if (snapA[i].base != snapB[i].base) continue;
        if (snapA[i].type != MEM_IMAGE) continue;
        if (!(snapA[i].protect & (PAGE_READWRITE | PAGE_WRITECOPY))) continue;

        SIZE_T sz = snapA[i].size;
        for (SIZE_T off = 0; off + sizeof(unsigned long) <= sz; off += sizeof(unsigned long)) {
            unsigned long valA = *(unsigned long *)(snapA[i].data + off);
            unsigned long valB = *(unsigned long *)(snapB[i].data + off);

            if (valA == valB && valA != 0 && valA != new_hash) {
                stored_hash_addr = (unsigned char *)snapA[i].base + off;
                old_val = valA;
                break;
            }
        }
    }

    free_snapshot(snapA, countA);
    free_snapshot(snapB, countB);

    if (stored_hash_addr) {
        printf("  FOUND stored_hash @ %p (old hash value = %lu)\n", stored_hash_addr, old_val);
        if (patch_value(hProcess, stored_hash_addr, new_hash)) {
            printf("\nSUCCESS: Password in \"%s\" changed to \"%s\"!\n", process_name, new_password);
            return 0;
        }
    }

    printf("\nFAILED: Could not isolate stored hash in RAM.\n");
    return 1;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage:\n");
        printf("  Mode 1 (Instant): %s <process_name> <new_password>\n", argv[0]);
        printf("  Mode 2 (Zero-Knowledge Diff): %s <process_name> <new_password> --diff\n", argv[0]);
        return 1;
    }

    const char *process_name = argv[1];
    const char *new_password = argv[2];
    int use_diff = (argc >= 4 && strcmp(argv[3], "--diff") == 0);
    unsigned long new_hash = hash_password(new_password);

    printf("=== Runtime Memory Patcher ===\n\n");

    DWORD pid = find_process_by_name(process_name);
    if (pid == 0) {
        printf("ERROR: Process \"%s\" is not running.\n", process_name);
        return 1;
    }
    printf("Found PID %lu for \"%s\"\n\n", (unsigned long)pid, process_name);

    HANDLE hProcess = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
        FALSE, pid
    );
    if (!hProcess) {
        printf("ERROR: Cannot open process memory (error %lu).\n", GetLastError());
        return 1;
    }

    int result = 0;
    if (use_diff) {
        result = run_mode_2_diff(hProcess, process_name, new_password, new_hash);
    } else {
        result = run_mode_1_direct(hProcess, process_name, new_password, new_hash);
    }

    CloseHandle(hProcess);
    return result;
}
