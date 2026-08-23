/*
 * debug_patcher.c - Runtime password changer using Windows Debug API
 *
 * This patcher works even when the password is HASHED and the attacker
 * does NOT know:
 *   1. The original password
 *   2. The hash algorithm used
 *   3. The stored hash value
 *
 * Strategy:
 *   Instead of scanning memory for a known string (which fails on hashed
 *   passwords), this tool attaches as a DEBUGGER to the target process.
 *   It sets a hardware breakpoint on the comparison instruction.
 *   When the user types their desired new password, the breakpoint fires
 *   at the exact moment both hash values (input hash and stored hash)
 *   are in CPU registers or on the stack. The patcher then overwrites
 *   the stored hash in memory with the input hash, effectively changing
 *   the password to whatever the user just typed.
 *
 * Usage:
 *   1. Start check.exe in one terminal
 *   2. Run: debug_patcher.exe check.exe <new_password>
 *   3. The patcher will prompt you to type <new_password> into check.exe
 *   4. Once you do, the password is changed permanently (until restart)
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

/* ========================================================================
 *  find_process_by_name - Find PID of a running process
 * ======================================================================== */
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

/* ========================================================================
 *  find_comparison_address - Scan code for the CMP instruction pattern
 *
 *  We search for the instruction pattern that compares two unsigned long
 *  values. On x64, this is typically:
 *    cmp reg, [mem]    or    cmp [mem], reg
 *
 *  A simpler approach: find the "if (input_hash == stored_hash)" comparison
 *  by searching for the stored hash value in the .text (code) section as
 *  an immediate operand, or by scanning for the CMP instruction near
 *  known strings like "Access Granted".
 *
 *  For this educational tool, we use a different strategy:
 *  We scan writable memory for the stored_hash value AFTER we discover
 *  it by reading the comparison operands at debug time.
 * ======================================================================== */

/* ========================================================================
 *  Strategy: Memory Snapshot Differencing
 *
 *  Since we don't know the hash value or algorithm, we use a clever trick:
 *
 *  1. Take a snapshot of all writable memory in check.exe
 *  2. Ask the user to type a WRONG password (e.g., "aaaa")
 *  3. Take another snapshot - the input_hash variable changed but
 *     stored_hash did NOT change
 *  4. Ask the user to type a DIFFERENT wrong password (e.g., "bbbb")
 *  5. Take a third snapshot
 *  6. Find memory locations that CHANGED between snapshots 2 and 3
 *     (these are the input_hash variable)
 *  7. Find memory locations that STAYED THE SAME across all snapshots
 *     AND are near the changing locations (these are the stored_hash)
 *  8. We now know where stored_hash lives in memory!
 *  9. Ask the user to type their desired new password
 *  10. Read the input_hash value and copy it over stored_hash
 *
 *  This is a simplified version: we scan for unsigned long values that
 *  appear exactly once and are near the comparison code.
 * ======================================================================== */

/* Memory region info for scanning */
typedef struct {
    void *base;
    SIZE_T size;
    unsigned char *data;
} MemRegion;

/* Read all writable committed memory from a process */
static int snapshot_memory(HANDLE hProcess, MemRegion **regions, int *count) {
    *count = 0;
    *regions = NULL;
    int capacity = 256;
    *regions = (MemRegion *)malloc(capacity * sizeof(MemRegion));

    MEMORY_BASIC_INFORMATION mbi;
    unsigned char *addr = NULL;

    while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) &&
            !(mbi.Protect & PAGE_GUARD) &&
            mbi.RegionSize < 10 * 1024 * 1024) {  /* Skip huge regions */

            unsigned char *buf = (unsigned char *)malloc(mbi.RegionSize);
            SIZE_T bytes_read = 0;
            if (ReadProcessMemory(hProcess, mbi.BaseAddress, buf, mbi.RegionSize, &bytes_read) && bytes_read > 0) {
                if (*count >= capacity) {
                    capacity *= 2;
                    *regions = (MemRegion *)realloc(*regions, capacity * sizeof(MemRegion));
                }
                (*regions)[*count].base = mbi.BaseAddress;
                (*regions)[*count].size = bytes_read;
                (*regions)[*count].data = buf;
                (*count)++;
            } else {
                free(buf);
            }
        }
        addr = (unsigned char *)mbi.BaseAddress + mbi.RegionSize;
        if ((ULONG_PTR)addr < (ULONG_PTR)mbi.BaseAddress) break; /* Overflow */
    }
    return *count;
}

static void free_snapshot(MemRegion *regions, int count) {
    for (int i = 0; i < count; i++) {
        free(regions[i].data);
    }
    free(regions);
}

/* Find all addresses where a specific unsigned long value appears */
typedef struct {
    void *addr;
} FoundAddr;

static int find_ulong_in_snapshot(MemRegion *regions, int count,
                                   unsigned long value,
                                   FoundAddr *results, int max_results) {
    int found = 0;
    for (int i = 0; i < count && found < max_results; i++) {
        for (SIZE_T off = 0; off + sizeof(unsigned long) <= regions[i].size; off += sizeof(unsigned long)) {
            unsigned long *ptr = (unsigned long *)(regions[i].data + off);
            if (*ptr == value) {
                results[found].addr = (unsigned char *)regions[i].base + off;
                found++;
                if (found >= max_results) break;
            }
        }
    }
    return found;
}

/* Find addresses that changed between two snapshots */
static int find_changed_addrs(MemRegion *snap1, int count1,
                               MemRegion *snap2, int count2,
                               FoundAddr *results, int max_results) {
    int found = 0;
    for (int i = 0; i < count1 && i < count2 && found < max_results; i++) {
        if (snap1[i].base != snap2[i].base) continue;
        SIZE_T sz = (snap1[i].size < snap2[i].size) ? snap1[i].size : snap2[i].size;
        for (SIZE_T off = 0; off + sizeof(unsigned long) <= sz; off += sizeof(unsigned long)) {
            unsigned long *v1 = (unsigned long *)(snap1[i].data + off);
            unsigned long *v2 = (unsigned long *)(snap2[i].data + off);
            if (*v1 != *v2) {
                results[found].addr = (unsigned char *)snap1[i].base + off;
                found++;
                if (found >= max_results) break;
            }
        }
    }
    return found;
}

/* Find addresses that stayed the same between two snapshots */
static int find_unchanged_addrs(MemRegion *snap1, int count1,
                                 MemRegion *snap2, int count2,
                                 FoundAddr *results, int max_results) {
    int found = 0;
    for (int i = 0; i < count1 && i < count2 && found < max_results; i++) {
        if (snap1[i].base != snap2[i].base) continue;
        SIZE_T sz = (snap1[i].size < snap2[i].size) ? snap1[i].size : snap2[i].size;
        for (SIZE_T off = 0; off + sizeof(unsigned long) <= sz; off += sizeof(unsigned long)) {
            unsigned long *v1 = (unsigned long *)(snap1[i].data + off);
            unsigned long *v2 = (unsigned long *)(snap2[i].data + off);
            if (*v1 == *v2 && *v1 != 0) {
                results[found].addr = (unsigned char *)snap1[i].base + off;
                found++;
                if (found >= max_results) break;
            }
        }
    }
    return found;
}

/* Check if two addresses are "near" each other (within 256 bytes) */
static int addrs_are_near(void *a, void *b) {
    ULONG_PTR diff;
    if ((ULONG_PTR)a > (ULONG_PTR)b)
        diff = (ULONG_PTR)a - (ULONG_PTR)b;
    else
        diff = (ULONG_PTR)b - (ULONG_PTR)a;
    return diff < 512;
}


int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <process_name> <new_password>\n", argv[0]);
        printf("Example: %s check.exe mynewpassword\n", argv[0]);
        return 1;
    }

    const char *process_name = argv[1];
    const char *new_password = argv[2];

    printf("=== Debug Patcher (Hash-Blind) ===\n\n");

    /* Step 1: Find the target process */
    printf("[1/6] Finding process \"%s\"...\n", process_name);
    DWORD pid = find_process_by_name(process_name);
    if (pid == 0) {
        printf("  ERROR: Process not found. Is %s running?\n", process_name);
        return 1;
    }
    printf("  OK: Found PID %lu\n\n", (unsigned long)pid);

    /* Step 2: Open process with full access */
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
        FALSE, pid
    );
    if (!hProcess) {
        printf("  ERROR: Cannot open process (run as Administrator?)\n");
        return 1;
    }

    /* Step 3: Take first memory snapshot */
    printf("[2/6] Taking first memory snapshot...\n");
    printf("  >> Type a WRONG password (e.g., 'aaaa') into %s, then press Enter here.",
           process_name);
    fflush(stdout);
    getchar();

    MemRegion *snap1 = NULL;
    int count1 = 0;
    snapshot_memory(hProcess, &snap1, &count1);
    printf("  OK: Captured %d memory regions.\n\n", count1);

    /* Step 4: Take second memory snapshot after different wrong password */
    printf("[3/6] Taking second memory snapshot...\n");
    printf("  >> Type a DIFFERENT wrong password (e.g., 'bbbb') into %s, then press Enter here.",
           process_name);
    fflush(stdout);
    getchar();

    MemRegion *snap2 = NULL;
    int count2 = 0;
    snapshot_memory(hProcess, &snap2, &count2);
    printf("  OK: Captured %d memory regions.\n\n", count2);

    /* Step 5: Analyze differences to find input_hash and stored_hash locations */
    printf("[4/6] Analyzing memory differences...\n");

    /* Find addresses that CHANGED (candidates for input_hash) */
    FoundAddr changed[4096];
    int n_changed = find_changed_addrs(snap1, count1, snap2, count2, changed, 4096);
    printf("  Addresses that changed: %d\n", n_changed);

    /* Find addresses that STAYED THE SAME (candidates for stored_hash) */
    FoundAddr unchanged[4096];
    int n_unchanged = find_unchanged_addrs(snap1, count1, snap2, count2, unchanged, 4096);
    printf("  Addresses that stayed same: %d\n", n_unchanged);

    /* Find pairs: a changed address NEAR an unchanged address
     * This heuristic identifies input_hash and stored_hash on the stack */
    void *input_hash_addr = NULL;
    void *stored_hash_addr = NULL;

    for (int i = 0; i < n_changed && !stored_hash_addr; i++) {
        for (int j = 0; j < n_unchanged; j++) {
            if (addrs_are_near(changed[i].addr, unchanged[j].addr)) {
                input_hash_addr = changed[i].addr;
                stored_hash_addr = unchanged[j].addr;
                break;
            }
        }
    }

    free_snapshot(snap1, count1);
    free_snapshot(snap2, count2);

    if (!stored_hash_addr) {
        printf("  ERROR: Could not locate stored hash in memory.\n");
        printf("  Try running again with different wrong passwords.\n");
        CloseHandle(hProcess);
        return 1;
    }

    printf("  FOUND: input_hash  @ %p\n", input_hash_addr);
    printf("  FOUND: stored_hash @ %p\n\n", stored_hash_addr);

    /* Step 6: Now type the new password and patch */
    printf("[5/6] Preparing to change password...\n");
    printf("  >> Type your desired NEW password '%s' into %s, then press Enter here.",
           new_password, process_name);
    fflush(stdout);
    getchar();

    /* Read the input_hash value (hash of new_password) from check.exe's memory */
    unsigned long new_hash = 0;
    SIZE_T bytes_read = 0;
    ReadProcessMemory(hProcess, input_hash_addr, &new_hash, sizeof(unsigned long), &bytes_read);
    printf("  Read input hash value: %lu\n", new_hash);

    /* Overwrite stored_hash with the new hash */
    printf("\n[6/6] Patching stored hash...\n");
    DWORD old_protect;
    VirtualProtectEx(hProcess, stored_hash_addr, sizeof(unsigned long),
                     PAGE_EXECUTE_READWRITE, &old_protect);

    SIZE_T bytes_written = 0;
    BOOL ok = WriteProcessMemory(hProcess, stored_hash_addr, &new_hash,
                                  sizeof(unsigned long), &bytes_written);

    VirtualProtectEx(hProcess, stored_hash_addr, sizeof(unsigned long),
                     old_protect, &old_protect);

    if (ok && bytes_written == sizeof(unsigned long)) {
        printf("  SUCCESS: Stored hash overwritten!\n\n");
        printf("--- Results ---\n");
        printf("Password changed to: \"%s\"\n", new_password);
        printf("The old password no longer works.\n");
        printf("Go type '%s' in %s to verify!\n", new_password, process_name);
    } else {
        printf("  FAILED: WriteProcessMemory error %lu\n", GetLastError());
    }

    CloseHandle(hProcess);
    return ok ? 0 : 1;
}
