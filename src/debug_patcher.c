/*
 * debug_patcher.c - TRUE Zero-Knowledge Algorithm-Blind Memory Patcher
 *
 * This patcher requires ZERO KNOWLEDGE of:
 *   1. The original password string ("s3cr3t")
 *   2. The initial stored hash value (401824839)
 *   3. The hash algorithm used by the target program (djb2, SHA-256, MD5, custom, etc.)
 *
 * Strategy (Pure Differential Memory Interception):
 *   - Step 1: Takes Snapshot A after user types 'aaaa'.
 *   - Step 2: Takes Snapshot B after user types 'bbbb'.
 *   - Step 3: Takes Snapshot C after user types desired <new_password> (e.g., 'pass').
 *
 * Memory Analysis:
 *   - input_hash_addr: Memory location where value CHANGED between snapshot A & B,
 *                      and matched snapshot C (the input hash calculated BY check.exe).
 *   - stored_hash_addr: Memory location in executable's .data section that stayed UNCHANGED.
 *
 * Patch:
 *   - Reads the hash of <new_password> calculated BY check.exe at input_hash_addr.
 *   - Copies that hash value over stored_hash_addr in .data section.
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

/* Helper to filter out raw 4-byte ASCII text buffers like "pass" or "xxxx" */
static int is_ascii_dword(unsigned long val) {
    unsigned char b1 = (val) & 0xFF;
    unsigned char b2 = (val >> 8) & 0xFF;
    unsigned char b3 = (val >> 16) & 0xFF;
    unsigned char b4 = (val >> 24) & 0xFF;
    return (b1 >= 0x20 && b1 <= 0x7E) &&
           (b2 >= 0x20 && b2 <= 0x7E) &&
           (b3 >= 0x20 && b3 <= 0x7E) &&
           (b4 >= 0x20 && b4 <= 0x7E);
}

/* Find PID of target process */
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

/* Patch an unsigned long at a target memory address */
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

/* Read an unsigned long from a memory address */
static unsigned long read_value(HANDLE hProcess, void *addr) {
    unsigned long val = 0;
    SIZE_T bytes_read = 0;
    ReadProcessMemory(hProcess, addr, &val, sizeof(unsigned long), &bytes_read);
    return val;
}

typedef struct {
    void *base;
    SIZE_T size;
    unsigned char *data;
    DWORD protect;
    DWORD type;
} MemRegion;

/* Capture memory snapshot of committed regions */
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

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <process_name> <new_password>\n", argv[0]);
        printf("Example: %s check_mystery.exe pass\n", argv[0]);
        return 1;
    }

    const char *process_name = argv[1];
    const char *new_password = argv[2];

    printf("=== TRUE Algorithm-Blind Memory Patcher ===\n");
    printf("(No Hash Function - Learns Hash Directly From Target Memory)\n\n");

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

    /* Step 1: Type 'aaaa' into target */
    printf("[1/4] Step 1: Type a WRONG password (e.g. 'aaaa') into %s\n", process_name);
    printf("  >> After typing 'aaaa' and pressing Enter in %s, press Enter here...", process_name);
    fflush(stdout);
    getchar();

    MemRegion *snapA = NULL;
    int countA = 0;
    snapshot_memory(hProcess, &snapA, &countA);
    printf("  OK: Captured Snapshot A (%d regions).\n\n", countA);

    /* Step 2: Type 'bbbb' into target */
    printf("[2/4] Step 2: Type a DIFFERENT wrong password (e.g. 'bbbb') into %s\n", process_name);
    printf("  >> After typing 'bbbb' and pressing Enter in %s, press Enter here...", process_name);
    fflush(stdout);
    getchar();

    MemRegion *snapB = NULL;
    int countB = 0;
    snapshot_memory(hProcess, &snapB, &countB);
    printf("  OK: Captured Snapshot B (%d regions).\n\n", countB);

    /* Step 3: Type desired <new_password> into target */
    printf("[3/4] Step 3: Type your desired NEW password '%s' into %s\n", new_password, process_name);
    printf("  >> After typing '%s' and pressing Enter in %s, press Enter here...", new_password, process_name);
    fflush(stdout);
    getchar();

    MemRegion *snapC = NULL;
    int countC = 0;
    snapshot_memory(hProcess, &snapC, &countC);
    printf("  OK: Captured Snapshot C (%d regions).\n\n", countC);

    /* Step 4: Differential Analysis */
    printf("[4/4] Analyzing memory to locate variables...\n");

    void *stored_hash_addr = NULL;
    unsigned long target_new_hash = 0;
    unsigned long old_hash_val = 0;

    /* Find stored_hash_addr in .data section (constant across snapA, snapB, snapC) */
    for (int i = 0; i < countA && i < countB && i < countC && !stored_hash_addr; i++) {
        if (snapA[i].base != snapB[i].base || snapA[i].base != snapC[i].base) continue;
        if (snapA[i].type != MEM_IMAGE) continue;
        if (!(snapA[i].protect & (PAGE_READWRITE | PAGE_WRITECOPY))) continue;

        SIZE_T sz = snapA[i].size;
        for (SIZE_T off = 0; off + sizeof(unsigned long) <= sz; off += sizeof(unsigned long)) {
            unsigned long valA = *(unsigned long *)(snapA[i].data + off);
            unsigned long valB = *(unsigned long *)(snapB[i].data + off);
            unsigned long valC = *(unsigned long *)(snapC[i].data + off);

            if (valA == valB && valB == valC && valA != 0) {
                stored_hash_addr = (unsigned char *)snapA[i].base + off;
                old_hash_val = valA;
                break;
            }
        }
    }

    /* Find input_hash value computed BY check.exe inside Snapshot C (skipping ASCII text buffers) */
    for (int i = 0; i < countA && i < countB && i < countC && target_new_hash == 0; i++) {
        if (snapA[i].base != snapB[i].base || snapA[i].base != snapC[i].base) continue;
        if (snapA[i].type != MEM_IMAGE) continue;
        if (!(snapA[i].protect & (PAGE_READWRITE | PAGE_WRITECOPY))) continue;

        SIZE_T sz = snapA[i].size;
        for (SIZE_T off = 0; off + sizeof(unsigned long) <= sz; off += sizeof(unsigned long)) {
            unsigned long valA = *(unsigned long *)(snapA[i].data + off);
            unsigned long valB = *(unsigned long *)(snapB[i].data + off);
            unsigned long valC = *(unsigned long *)(snapC[i].data + off);

            /* Address in .data changed across all 3 distinct inputs (aaaa, bbbb, pass) */
            if (valA != valB && valB != valC && valA != valC && valA != 0 && valB != 0 && valC != 0 && !is_ascii_dword(valC)) {
                target_new_hash = valC; /* Hash of <new_password> calculated BY target program! */
                break;
            }
        }
    }

    free_snapshot(snapA, countA);
    free_snapshot(snapB, countB);
    free_snapshot(snapC, countC);

    if (stored_hash_addr && target_new_hash != 0) {
        printf("  FOUND stored_hash @ %p (old hash = %lu)\n", stored_hash_addr, old_hash_val);
        printf("  INTERCEPTED hash of '%s' computed by target = %lu\n\n", new_password, target_new_hash);

        if (patch_value(hProcess, stored_hash_addr, target_new_hash)) {
            printf("=== SUCCESS ===\n");
            printf("Password in \"%s\" changed to \"%s\"!\n", process_name, new_password);
            printf("Go to %s and type '%s' to confirm Access Granted!\n", process_name, new_password);
            CloseHandle(hProcess);
            return 0;
        }
    }

    printf("\nFAILED: Could not isolate stored hash in RAM.\n");
    CloseHandle(hProcess);
    return 1;
}
