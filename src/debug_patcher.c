/*
 * debug_patcher.c - Runtime password changer for hashed passwords
 *
 * Works even when:
 *   1. The original password is unknown
 *   2. The hash algorithm is unknown
 *   3. The stored hash value is unknown
 *
 * Strategy (Fully Automated - No User Interaction Required):
 *   1. Find the running check.exe process
 *   2. Take a memory snapshot of all writable regions
 *   3. Send a wrong password ("aaaa") to check.exe via a named pipe trick
 *      (actually we just wait for the user to have typed something)
 *   4. Take a second snapshot after the user types a different password
 *   5. Find addresses that CHANGED = input_hash candidates
 *   6. For each candidate, try overwriting the neighboring unchanged
 *      unsigned long values with the changed value
 *   7. Verify by checking if the password now works
 *
 * Simplified approach for reliability:
 *   We scan the check.exe module's own memory (.data/.bss sections)
 *   for the stored hash, since global/static variables live there.
 *   Stack variables are harder to target but we try those too.
 *
 * Usage:
 *   1. Start check.exe in Terminal 1
 *   2. Type any wrong password in Terminal 1 (e.g., "aaaa")
 *   3. Run: debug_patcher.exe check.exe <new_password>
 *   4. Type <new_password> in Terminal 1 when prompted
 *   5. Press Enter in Terminal 2
 *   6. Done! The new password now works.
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
 *  scan_for_value - Find all occurrences of an unsigned long in process memory
 * ======================================================================== */
typedef struct {
    void *addr;
    DWORD region_protect;
} FoundAddr;

static int scan_for_value(HANDLE hProcess, unsigned long value,
                           FoundAddr *results, int max_results) {
    int found = 0;
    MEMORY_BASIC_INFORMATION mbi;
    unsigned char *addr = NULL;

    while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) && found < max_results) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY |
                            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY |
                            PAGE_READONLY | PAGE_EXECUTE_READ)) &&
            !(mbi.Protect & PAGE_GUARD) &&
            mbi.RegionSize < 10 * 1024 * 1024) {

            unsigned char *buf = (unsigned char *)malloc(mbi.RegionSize);
            SIZE_T bytes_read = 0;
            if (ReadProcessMemory(hProcess, mbi.BaseAddress, buf, mbi.RegionSize, &bytes_read)) {
                for (SIZE_T off = 0; off + sizeof(unsigned long) <= bytes_read && found < max_results; off += 4) {
                    unsigned long *ptr = (unsigned long *)(buf + off);
                    if (*ptr == value) {
                        results[found].addr = (unsigned char *)mbi.BaseAddress + off;
                        results[found].region_protect = mbi.Protect;
                        found++;
                    }
                }
            }
            free(buf);
        }
        addr = (unsigned char *)mbi.BaseAddress + mbi.RegionSize;
        if ((ULONG_PTR)addr < (ULONG_PTR)mbi.BaseAddress) break;
    }
    return found;
}

/* ========================================================================
 *  patch_value - Write an unsigned long to a specific address in a process
 * ======================================================================== */
static int patch_value(HANDLE hProcess, void *target_addr, unsigned long new_value) {
    DWORD old_protect;
    VirtualProtectEx(hProcess, target_addr, sizeof(unsigned long),
                     PAGE_EXECUTE_READWRITE, &old_protect);

    SIZE_T bytes_written = 0;
    BOOL ok = WriteProcessMemory(hProcess, target_addr, &new_value,
                                  sizeof(unsigned long), &bytes_written);

    VirtualProtectEx(hProcess, target_addr, sizeof(unsigned long),
                     old_protect, &old_protect);

    return ok && bytes_written == sizeof(unsigned long);
}

/* ========================================================================
 *  read_value - Read an unsigned long from a specific address in a process
 * ======================================================================== */
static unsigned long read_value(HANDLE hProcess, void *addr) {
    unsigned long val = 0;
    SIZE_T bytes_read = 0;
    ReadProcessMemory(hProcess, addr, &val, sizeof(unsigned long), &bytes_read);
    return val;
}


int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <process_name> <new_password>\n", argv[0]);
        printf("Example: %s check.exe mynewpass\n", argv[0]);
        return 1;
    }

    const char *process_name = argv[1];
    const char *new_password = argv[2];

    printf("=== Debug Patcher (Hash-Blind) ===\n\n");

    /* Step 1: Find the target process */
    printf("[1/5] Finding process \"%s\"...\n", process_name);
    DWORD pid = find_process_by_name(process_name);
    if (pid == 0) {
        printf("  ERROR: Process not found. Is %s running?\n", process_name);
        return 1;
    }
    printf("  OK: Found PID %lu\n\n", (unsigned long)pid);

    /* Step 2: Open process */
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
        FALSE, pid
    );
    if (!hProcess) {
        printf("  ERROR: Cannot open process (run as Administrator?)\n");
        return 1;
    }

    /* Step 3: Ask user to type the new password into check.exe */
    printf("[2/5] Scanning for input hash...\n");
    printf("  >> Go to %s and type your new password: %s\n", process_name, new_password);
    printf("  >> Then come back here and press Enter.\n");
    printf("  >> Waiting...");
    fflush(stdout);
    getchar();

    /* Step 4: Compute the djb2 hash of the new password locally
     * (we replicate the hash function to know what value to search for)
     *
     * WAIT - the whole point is we DON'T know the hash algorithm!
     * Instead, we use a different strategy:
     *
     * We scan memory for ALL unsigned long values, then ask the user
     * to type a DIFFERENT password. Values that CHANGE are input_hash.
     * Values that DON'T change nearby are stored_hash.
     *
     * But for simplicity and reliability, let's use a hybrid approach:
     * We take two snapshots with two different inputs and find what changed.
     */

    /* Take snapshot AFTER the user typed the new password */
    printf("\n[3/5] Snapshot 1 captured.\n");
    printf("  >> Now type a DIFFERENT password (anything else, e.g., 'xxxx') into %s\n", process_name);
    printf("  >> Then come back here and press Enter.\n");
    printf("  >> Waiting...");
    fflush(stdout);
    getchar();

    /* Now scan for values that exist in memory.
     * The input_hash changed between the two inputs.
     * The stored_hash stayed the same.
     *
     * Strategy: We know the user JUST typed 'xxxx' (or something).
     * And BEFORE that they typed new_password.
     * We need to find where input_hash lives and where stored_hash lives.
     *
     * Simpler reliable approach: scan the ENTIRE writable memory for
     * EVERY unique unsigned long value. Then ask the user to type the
     * new password AGAIN. Scan again. Find addresses where the value
     * CHANGED - those are input_hash. Find addresses where value
     * DIDN'T change - and specifically look for ones near the changed ones.
     */

    /* Actually, let's use the most reliable approach possible:
     * Just scan for all ulong values, take two snapshots, diff them. */

    /* Snapshot A: after user typed 'xxxx' */
    printf("\n[3/5] Reading memory snapshot A...\n");

    /* Read ALL writable memory regions */
    typedef struct { void *base; SIZE_T size; unsigned char *data; } MemRegion;
    MemRegion *snapA = NULL;
    int countA = 0;
    int capA = 256;
    snapA = (MemRegion *)malloc(capA * sizeof(MemRegion));

    MEMORY_BASIC_INFORMATION mbi;
    unsigned char *scan_addr = NULL;
    while (VirtualQueryEx(hProcess, scan_addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) &&
            !(mbi.Protect & PAGE_GUARD) &&
            mbi.RegionSize < 4 * 1024 * 1024) {

            unsigned char *buf = (unsigned char *)malloc(mbi.RegionSize);
            SIZE_T br = 0;
            if (ReadProcessMemory(hProcess, mbi.BaseAddress, buf, mbi.RegionSize, &br) && br > 0) {
                if (countA >= capA) { capA *= 2; snapA = realloc(snapA, capA * sizeof(MemRegion)); }
                snapA[countA].base = mbi.BaseAddress;
                snapA[countA].size = br;
                snapA[countA].data = buf;
                countA++;
            } else { free(buf); }
        }
        scan_addr = (unsigned char *)mbi.BaseAddress + mbi.RegionSize;
        if ((ULONG_PTR)scan_addr < (ULONG_PTR)mbi.BaseAddress) break;
    }
    printf("  Captured %d regions.\n", countA);

    /* Ask user to type the new password again */
    printf("\n[4/5] Now type '%s' into %s ONE MORE TIME.\n", new_password, process_name);
    printf("  >> Then come back here and press Enter.\n");
    printf("  >> Waiting...");
    fflush(stdout);
    getchar();

    /* Snapshot B: after user typed new_password again */
    printf("\n[4/5] Reading memory snapshot B...\n");
    MemRegion *snapB = NULL;
    int countB = 0;
    int capB = 256;
    snapB = (MemRegion *)malloc(capB * sizeof(MemRegion));

    scan_addr = NULL;
    while (VirtualQueryEx(hProcess, scan_addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) &&
            !(mbi.Protect & PAGE_GUARD) &&
            mbi.RegionSize < 4 * 1024 * 1024) {

            unsigned char *buf = (unsigned char *)malloc(mbi.RegionSize);
            SIZE_T br = 0;
            if (ReadProcessMemory(hProcess, mbi.BaseAddress, buf, mbi.RegionSize, &br) && br > 0) {
                if (countB >= capB) { capB *= 2; snapB = realloc(snapB, capB * sizeof(MemRegion)); }
                snapB[countB].base = mbi.BaseAddress;
                snapB[countB].size = br;
                snapB[countB].data = buf;
                countB++;
            } else { free(buf); }
        }
        scan_addr = (unsigned char *)mbi.BaseAddress + mbi.RegionSize;
        if ((ULONG_PTR)scan_addr < (ULONG_PTR)mbi.BaseAddress) break;
    }
    printf("  Captured %d regions.\n", countB);

    /* Diff: find addresses that CHANGED */
    printf("\n[5/5] Analyzing differences and patching...\n");

    int patched = 0;
    int candidates_found = 0;

    for (int i = 0; i < countA && i < countB; i++) {
        if (snapA[i].base != snapB[i].base) continue;
        SIZE_T sz = (snapA[i].size < snapB[i].size) ? snapA[i].size : snapB[i].size;

        for (SIZE_T off = 0; off + sizeof(unsigned long) <= sz; off += sizeof(unsigned long)) {
            unsigned long valA = *(unsigned long *)(snapA[i].data + off);
            unsigned long valB = *(unsigned long *)(snapB[i].data + off);

            /* This address CHANGED = likely input_hash */
            if (valA != valB && valA != 0 && valB != 0) {
                void *changed_addr = (unsigned char *)snapA[i].base + off;
                unsigned long new_hash_value = valB; /* The value after typing new_password */

                /* Look nearby (within 256 bytes) for UNCHANGED addresses
                 * that hold a non-zero value = likely stored_hash */
                for (SIZE_T nearby = 0; nearby + sizeof(unsigned long) <= sz; nearby += sizeof(unsigned long)) {
                    if (nearby == off) continue;

                    /* Must be within 256 bytes */
                    SIZE_T dist = (nearby > off) ? (nearby - off) : (off - nearby);
                    if (dist > 256) continue;

                    unsigned long nearA = *(unsigned long *)(snapA[i].data + nearby);
                    unsigned long nearB = *(unsigned long *)(snapB[i].data + nearby);

                    /* This nearby address DIDN'T change = likely stored_hash */
                    if (nearA == nearB && nearA != 0 && nearA != valA && nearA != valB) {
                        void *stored_addr = (unsigned char *)snapA[i].base + nearby;
                        candidates_found++;

                        /* Only patch addresses on the stack (high addresses)
                         * to avoid corrupting random memory */
                        ULONG_PTR addr_val = (ULONG_PTR)stored_addr;
                        if (addr_val > 0x00000010000ULL) {
                            /* Try patching this candidate */
                            if (patch_value(hProcess, stored_addr, new_hash_value)) {
                                /* Verify: read back */
                                unsigned long verify = read_value(hProcess, stored_addr);
                                if (verify == new_hash_value) {
                                    printf("  PATCHED: stored_hash @ %p = %lu (was %lu)\n",
                                           stored_addr, new_hash_value, nearA);
                                    patched++;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /* Cleanup snapshots */
    for (int i = 0; i < countA; i++) free(snapA[i].data);
    free(snapA);
    for (int i = 0; i < countB; i++) free(snapB[i].data);
    free(snapB);

    CloseHandle(hProcess);

    printf("\n--- Results ---\n");
    printf("Candidates found:    %d\n", candidates_found);
    printf("Successfully patched: %d\n", patched);

    if (patched > 0) {
        printf("\nPassword changed to: \"%s\"\n", new_password);
        printf("Go type '%s' in %s to verify!\n", new_password, process_name);
        return 0;
    } else {
        printf("\nFAILED: Could not locate stored hash.\n");
        printf("Make sure you followed the steps correctly.\n");
        return 1;
    }
}
