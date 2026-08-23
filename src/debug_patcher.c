/*
 * debug_patcher.c - Runtime password patcher for hashed passwords
 *
 * Works even when:
 *   1. The original password is unknown
 *   2. The hash algorithm is unknown
 *   3. The stored hash value is unknown
 *
 * Strategy (Safe & Precise Memory Differencing):
 *   - Captures two memory snapshots after different user inputs.
 *   - Identifies the user input hash location (which changes).
 *   - Identifies the stored hash location in the static data section (.data)
 *     which stays constant across all inputs.
 *   - Overwrites ONLY the stored_hash variable in .data section with the new input hash.
 *   - Never corrupts stack frames, return addresses, or loop counters.
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
            (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) &&
            !(mbi.Protect & PAGE_GUARD) &&
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

    printf("=== Debug Patcher (Safe & Precise) ===\n\n");

    /* Step 1: Find target process */
    printf("[1/5] Finding process \"%s\"...\n", process_name);
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

    /* Step 2: Prompt for first password */
    printf("[2/5] Step 1: Type '%s' into %s\n", new_password, process_name);
    printf("  >> After typing '%s' and pressing Enter in %s, press Enter here...", new_password, process_name);
    fflush(stdout);
    getchar();

    MemRegion *snapA = NULL;
    int countA = 0;
    snapshot_memory(hProcess, &snapA, &countA);
    printf("  OK: Captured snapshot A (%d regions).\n\n", countA);

    /* Step 3: Prompt for second password */
    printf("[3/5] Step 2: Type a DIFFERENT password (e.g. 'xxxx') into %s\n", process_name);
    printf("  >> After typing 'xxxx' and pressing Enter in %s, press Enter here...", process_name);
    fflush(stdout);
    getchar();

    MemRegion *snapB = NULL;
    int countB = 0;
    snapshot_memory(hProcess, &snapB, &countB);
    printf("  OK: Captured snapshot B (%d regions).\n\n", countB);

    /* Step 4: Prompt for new password one more time to capture final state */
    printf("[4/5] Step 3: Type '%s' ONE MORE TIME into %s\n", new_password, process_name);
    printf("  >> After typing '%s' and pressing Enter in %s, press Enter here...", new_password, process_name);
    fflush(stdout);
    getchar();

    MemRegion *snapC = NULL;
    int countC = 0;
    snapshot_memory(hProcess, &snapC, &countC);
    printf("  OK: Captured snapshot C (%d regions).\n\n", countC);

    /* Analyze snapshots:
     * Snapshot A: User typed 'new_password'  -> input_hash = hash(new_password)
     * Snapshot B: User typed 'xxxx'          -> input_hash = hash(xxxx)
     * Snapshot C: User typed 'new_password'  -> input_hash = hash(new_password)
     *
     * We look for:
     * 1. input_hash_addr: Address where valA == valC AND valA != valB AND valA != 0
     * 2. stored_hash_addr: Address in image/data region where valA == valB == valC AND valA != 0
     */
    printf("[5/5] Analyzing memory to locate hash variables...\n");

    unsigned long target_new_hash = 0;
    void *input_hash_addr = NULL;
    void *stored_hash_addr = NULL;

    /* Search for input_hash address */
    for (int i = 0; i < countA && i < countB && i < countC; i++) {
        if (snapA[i].base != snapB[i].base || snapA[i].base != snapC[i].base) continue;
        SIZE_T sz = snapA[i].size;

        for (SIZE_T off = 0; off + sizeof(unsigned long) <= sz; off += sizeof(unsigned long)) {
            unsigned long valA = *(unsigned long *)(snapA[i].data + off);
            unsigned long valB = *(unsigned long *)(snapB[i].data + off);
            unsigned long valC = *(unsigned long *)(snapC[i].data + off);

            /* Check if this address matches input_hash behavior */
            if (valA == valC && valA != valB && valA != 0 && valB != 0) {
                input_hash_addr = (unsigned char *)snapA[i].base + off;
                target_new_hash = valC;  /* This is hash(new_password) */
                break;
            }
        }
        if (input_hash_addr) break;
    }

    if (!input_hash_addr || target_new_hash == 0) {
        printf("  ERROR: Could not isolate input_hash in memory.\n");
        free_snapshot(snapA, countA);
        free_snapshot(snapB, countB);
        free_snapshot(snapC, countC);
        CloseHandle(hProcess);
        return 1;
    }

    printf("  FOUND input_hash  @ %p (hash value = %lu)\n", input_hash_addr, target_new_hash);

    /* Now find stored_hash address:
     * We search for unchanged candidates. If static, it resides in an image section (MEM_IMAGE) or data region.
     */
    for (int i = 0; i < countA && i < countB && i < countC; i++) {
        if (snapA[i].base != snapB[i].base || snapA[i].base != snapC[i].base) continue;
        SIZE_T sz = snapA[i].size;

        /* Prefer MEM_IMAGE regions (where global/static variables live) */
        for (SIZE_T off = 0; off + sizeof(unsigned long) <= sz; off += sizeof(unsigned long)) {
            unsigned long valA = *(unsigned long *)(snapA[i].data + off);
            unsigned long valB = *(unsigned long *)(snapB[i].data + off);
            unsigned long valC = *(unsigned long *)(snapC[i].data + off);

            /* Check if this is stored_hash: unchanged across all 3 snapshots */
            if (valA == valB && valB == valC && valA != 0 && valA != target_new_hash) {
                void *cand_addr = (unsigned char *)snapA[i].base + off;

                /* If in MEM_IMAGE (PE data section), it's static stored_hash! */
                if (snapA[i].type == MEM_IMAGE) {
                    stored_hash_addr = cand_addr;
                    break;
                }

                /* Or if near input_hash address */
                ULONG_PTR diff = ((ULONG_PTR)cand_addr > (ULONG_PTR)input_hash_addr) ?
                                 ((ULONG_PTR)cand_addr - (ULONG_PTR)input_hash_addr) :
                                 ((ULONG_PTR)input_hash_addr - (ULONG_PTR)cand_addr);
                if (diff < 512 && !stored_hash_addr) {
                    stored_hash_addr = cand_addr;
                }
            }
        }
        if (stored_hash_addr && snapA[i].type == MEM_IMAGE) break;
    }

    if (!stored_hash_addr) {
        printf("  ERROR: Could not locate stored_hash address safely.\n");
        free_snapshot(snapA, countA);
        free_snapshot(snapB, countB);
        free_snapshot(snapC, countC);
        CloseHandle(hProcess);
        return 1;
    }

    printf("  FOUND stored_hash @ %p (old hash value = %lu)\n\n",
           stored_hash_addr, read_value(hProcess, stored_hash_addr));

    /* Patch ONLY stored_hash_addr! */
    printf("Patching stored_hash @ %p with new hash %lu...\n", stored_hash_addr, target_new_hash);

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
    free_snapshot(snapC, countC);
    CloseHandle(hProcess);

    return 0;
}
