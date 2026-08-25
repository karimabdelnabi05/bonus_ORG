/*
 * live_patcher.c - Dynamic Runtime Memory Patcher
 *
 * Patches check.exe in live RAM while it is actively running.
 *
 * How it works:
 *   1. Finds the Process ID (PID) of the running check.exe process.
 *   2. Opens the process using OpenProcess().
 *   3. Scans check.exe's writable memory regions (.data section in RAM).
 *   4. Locates the old stored hash (287671138).
 *   5. Overwrites it in RAM with the XOR hash of the new password using WriteProcessMemory().
 *   6. check.exe now accepts your new password live, without restarting!
 *
 * Usage: live_patcher.exe <new_password>
 * Example: live_patcher.exe mypass
 *
 * Compile: gcc -o live_patcher.exe src/live_patcher.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>

/* Simple XOR hash function identified from check.exe disassembly */
static unsigned long xor_hash(const char *str) {
    unsigned long hash = 0x5A;
    int c;
    while ((c = *str++))
        hash = (hash * 31) ^ (unsigned char)c;
    return hash;
}

/* Find PID of running process by name */
static DWORD find_pid(const char *process_name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    DWORD pid = 0;
    if (Process32First(snap, &entry)) {
        do {
            if (_stricmp(entry.szExeFile, process_name) == 0) {
                pid = entry.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &entry));
    }

    CloseHandle(snap);
    return pid;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <new_password>\n", argv[0]);
        printf("Example: %s mypass\n", argv[0]);
        return 1;
    }

    const char *new_password = argv[1];
    unsigned long old_hash = 287671138UL;
    unsigned long new_hash = xor_hash(new_password);

    printf("=== Dynamic Runtime Memory Patcher (XOR Hash) ===\n\n");
    printf("Target Process: check.exe\n");
    printf("Old Hash:       %lu (0x%08lX)\n", old_hash, old_hash);
    printf("New Password:   \"%s\"\n", new_password);
    printf("New Hash:       %lu (0x%08lX)\n\n", new_hash, new_hash);

    /* Step 1: Find running process */
    DWORD pid = find_pid("check.exe");
    if (pid == 0) {
        printf("ERROR: check.exe is not running!\n");
        printf("Please start check.exe in another terminal window first.\n");
        return 1;
    }
    printf("[1] Found running check.exe (PID %lu)\n", pid);

    /* Step 2: Open target process with read/write permissions */
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
        FALSE, pid
    );
    if (!hProcess) {
        printf("ERROR: Cannot open process (Error %lu)\n", GetLastError());
        return 1;
    }

    /* Step 3: Scan committed writable memory regions for old hash */
    MEMORY_BASIC_INFORMATION mbi;
    unsigned char *scan_addr = NULL;
    int patched = 0;

    while (VirtualQueryEx(hProcess, scan_addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY)) &&
            !(mbi.Protect & PAGE_GUARD)) {

            unsigned char buf[4096];
            SIZE_T bytes_read;

            for (SIZE_T offset = 0; offset < mbi.RegionSize; offset += sizeof(buf)) {
                SIZE_T to_read = (mbi.RegionSize - offset < sizeof(buf)) ? (mbi.RegionSize - offset) : sizeof(buf);

                if (ReadProcessMemory(hProcess, (unsigned char *)mbi.BaseAddress + offset, buf, to_read, &bytes_read)) {
                    for (SIZE_T j = 0; j <= bytes_read - 4; j += 4) {
                        if (*(unsigned long *)(buf + j) == old_hash) {
                            void *target_addr = (unsigned char *)mbi.BaseAddress + offset + j;

                            /* Step 4: Overwrite old hash with new hash in live RAM */
                            if (WriteProcessMemory(hProcess, target_addr, &new_hash, sizeof(unsigned long), NULL)) {
                                printf("[2] Located stored_hash in RAM @ %p\n", target_addr);
                                printf("[3] Overwrote RAM: %lu -> %lu\n\n", old_hash, new_hash);
                                patched = 1;
                                break;
                            }
                        }
                    }
                }
                if (patched) break;
            }
        }
        if (patched) break;
        scan_addr = (unsigned char *)mbi.BaseAddress + mbi.RegionSize;
    }

    CloseHandle(hProcess);

    if (patched) {
        printf("=== SUCCESS ===\n");
        printf("check.exe (PID %lu) patched live in RAM!\n", pid);
        printf("Type '%s' in the check.exe window now to get Access Granted!\n", new_password);
        return 0;
    } else {
        printf("ERROR: Stored hash %lu not found in process memory.\n", old_hash);
        return 1;
    }
}
