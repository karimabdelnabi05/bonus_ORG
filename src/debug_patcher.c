/*
 * debug_patcher.c - Runtime password patcher for hashed passwords
 *
 * Works even when:
 *   1. The original password is unknown
 *   2. The stored hash value is unknown
 *
 * Strategy (Safe & Precise Differential Analysis):
 *   - Takes two memory snapshots after different user inputs ("aaaa" and "bbbb").
 *   - Locates the stored_hash variable in check.exe's .data section (the memory address
 *     that remains constant across snapshots in the image data section).
 *   - Computes the hash of <new_password> and writes it to stored_hash_addr.
 *   - Password is now changed! Old password is denied, new password is granted.
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

/* Hash algorithm (djb2) */
static unsigned long hash_password(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
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

/* Read an unsigned long from target address */
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

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <process_name> <new_password>\n", argv[0]);
        printf("Example: %s check.exe pass\n", argv[0]);
        return 1;
    }

    const char *process_name = argv[1];
    const char *new_password = argv[2];
    unsigned long target_new_hash = hash_password(new_password);

    printf("=== Debug Patcher (Hash-Blind Differential Analysis) ===\n\n");
    printf("Target new password: \"%s\" (computed hash = %lu)\n\n", new_password, target_new_hash);

    /* Step 1: Find target process */
    printf("[1/4] Finding process \"%s\"...\n", process_name);
    DWORD pid = find_process_by_name(process_name);
    if (pid == 0) {
        printf("  ERROR: Process not found. Is %s running?\n", process_name);
        return 1;
    }
    printf("  OK: Found PID %lu\n\n", (unsigned long)pid);

    HANDLE hProcess = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
        FALSE, pid
    );
    if (!hProcess) {
        printf("  ERROR: Cannot open process (run as Administrator?)\n");
        return 1;
    }

    /* Step 2: Prompt for first wrong password */
    printf("[2/4] Step 1: Type a WRONG password (e.g. 'aaaa') into %s\n", process_name);
    printf("  >> After typing 'aaaa' and pressing Enter in %s, press Enter here...", process_name);
    fflush(stdout);
    getchar();

    MemRegion *snapA = NULL;
    int countA = 0;
    snapshot_memory(hProcess, &snapA, &countA);
    printf("  OK: Captured snapshot A (%d regions).\n\n", countA);

    /* Step 3: Prompt for second wrong password */
    printf("[3/4] Step 2: Type a DIFFERENT wrong password (e.g. 'bbbb') into %s\n", process_name);
    printf("  >> After typing 'bbbb' and pressing Enter in %s, press Enter here...", process_name);
    fflush(stdout);
    getchar();

    MemRegion *snapB = NULL;
    int countB = 0;
    snapshot_memory(hProcess, &snapB, &countB);
    printf("  OK: Captured snapshot B (%d regions).\n\n", countB);

    /* Step 4: Differential Analysis to locate stored_hash_addr in .data section */
    printf("[4/4] Analyzing memory to locate stored_hash in .data section...\n");

    void *stored_hash_addr = NULL;
    unsigned long old_hash_val = 0;

    /* Search for stored_hash in MEM_IMAGE writable section (.data) */
    for (int i = 0; i < countA && i < countB && !stored_hash_addr; i++) {
        if (snapA[i].base != snapB[i].base) continue;
        if (snapA[i].type != MEM_IMAGE) continue;
        if (!(snapA[i].protect & (PAGE_READWRITE | PAGE_WRITECOPY))) continue;

        SIZE_T sz = snapA[i].size;
        for (SIZE_T off = 0; off + sizeof(unsigned long) <= sz; off += sizeof(unsigned long)) {
            unsigned long valA = *(unsigned long *)(snapA[i].data + off);
            unsigned long valB = *(unsigned long *)(snapB[i].data + off);

            /* stored_hash stays constant across snapshots and is non-zero */
            if (valA == valB && valA != 0 && valA != target_new_hash) {
                stored_hash_addr = (unsigned char *)snapA[i].base + off;
                old_hash_val = valA;
                break;
            }
        }
    }

    if (!stored_hash_addr) {
        printf("  ERROR: Could not locate stored_hash address in .data section.\n");
        free_snapshot(snapA, countA);
        free_snapshot(snapB, countB);
        CloseHandle(hProcess);
        return 1;
    }

    printf("  FOUND stored_hash @ %p (old hash value = %lu)\n\n", stored_hash_addr, old_hash_val);

    /* Patch stored_hash_addr with target_new_hash */
    printf("Patching stored_hash @ %p with hash(%s) = %lu...\n",
           stored_hash_addr, new_password, target_new_hash);

    if (patch_value(hProcess, stored_hash_addr, target_new_hash)) {
        unsigned long verify = read_value(hProcess, stored_hash_addr);
        if (verify == target_new_hash) {
            printf("\n=== SUCCESS ===\n");
            printf("Password successfully changed to \"%s\"!\n", new_password);
            printf("Go to %s and type '%s' to confirm Access Granted!\n", process_name, new_password);
        } else {
            printf("FAILED: Readback verification mismatch.\n");
        }
    } else {
        printf("FAILED: WriteProcessMemory error %lu\n", GetLastError());
    }

    free_snapshot(snapA, countA);
    free_snapshot(snapB, countB);
    CloseHandle(hProcess);

    return 0;
}
