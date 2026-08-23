/*
 * patcher_lib.c - Implementation of the runtime memory patcher library
 *
 * Provides functions to:
 *   1. Validate patcher inputs
 *   2. Find a process by name using Windows Toolhelp32
 *   3. Scan process memory for a byte pattern
 *   4. Patch (overwrite) memory in a running process
 *
 * All functions use the Windows API. Must link with -lpsapi (if needed).
 */

/* Force ANSI (narrow char) versions of Windows API functions.
 * Without this, MinGW may default to Unicode (wide char) variants,
 * which would make PROCESSENTRY32.szExeFile a wchar_t array. */
#undef UNICODE
#undef _UNICODE

#include "patcher_lib.h"
#include <stdio.h>
#include <string.h>
#include <tlhelp32.h>

/* ========================================================================
 *  validate_input - Check that old/new passwords are acceptable
 * ======================================================================== */
int validate_input(const char *old_pw, const char *new_pw) {
    /* Both must be non-NULL */
    if (old_pw == NULL || new_pw == NULL) {
        return 0;
    }

    size_t old_len = strlen(old_pw);
    size_t new_len = strlen(new_pw);

    /* Both must be non-empty */
    if (old_len == 0 || new_len == 0) {
        return 0;
    }

    /* New password must not be longer than old (prevents buffer overflow) */
    if (new_len > old_len) {
        return 0;
    }

    return 1;
}

/* ========================================================================
 *  find_process_by_name - Locate a running process by its .exe name
 * ======================================================================== */
DWORD find_process_by_name(const char *process_name) {
    if (process_name == NULL) {
        return 0;
    }

    /*
     * Take a snapshot of all running processes using the Toolhelp32 API.
     * This is the standard way to enumerate processes on Windows.
     */
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    /* Iterate through all processes in the snapshot */
    if (Process32First(snapshot, &entry)) {
        do {
            /*
             * Compare the executable name (case-insensitive).
             * entry.szExeFile contains just the filename, e.g. "check.exe"
             */
            if (_stricmp(entry.szExeFile, process_name) == 0) {
                DWORD pid = entry.th32ProcessID;
                CloseHandle(snapshot);
                return pid;
            }
        } while (Process32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return 0;
}

/* ========================================================================
 *  scan_process_memory - Search all readable memory regions for a pattern
 * ======================================================================== */
int scan_process_memory(HANDLE hProcess, const char *pattern, size_t pattern_len,
                        void **addresses, int max_results) {
    if (hProcess == NULL || pattern == NULL || pattern_len == 0 ||
        addresses == NULL || max_results <= 0) {
        return 0;
    }

    int found = 0;
    MEMORY_BASIC_INFORMATION mbi;
    unsigned char *addr = NULL;

    /*
     * Walk through the entire virtual address space of the target process.
     * VirtualQueryEx tells us about each memory region - its base address,
     * size, protection flags, and state.
     */
    while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        /*
         * Only scan regions that are:
         *   - Committed (MEM_COMMIT) - actually backed by physical memory
         *   - Readable - have PAGE_READWRITE, PAGE_READONLY, PAGE_EXECUTE_READ, etc.
         *
         * Skip guard pages, no-access pages, and free/reserved regions.
         */
        if (mbi.State == MEM_COMMIT &&
            !(mbi.Protect & PAGE_GUARD) &&
            !(mbi.Protect & PAGE_NOACCESS) &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY |
                            PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                            PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY))) {

            /* Allocate a buffer to read this entire region */
            SIZE_T region_size = mbi.RegionSize;
            unsigned char *buffer = (unsigned char *)malloc(region_size);

            if (buffer != NULL) {
                SIZE_T bytes_read = 0;

                if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer,
                                      region_size, &bytes_read)) {
                    /*
                     * Search the buffer for all occurrences of the pattern.
                     * Simple byte-by-byte scan - not the fastest algorithm,
                     * but clear and correct for educational purposes.
                     */
                    for (SIZE_T i = 0; i <= bytes_read - pattern_len; i++) {
                        if (memcmp(buffer + i, pattern, pattern_len) == 0) {
                            if (found < max_results) {
                                addresses[found] =
                                    (void *)((unsigned char *)mbi.BaseAddress + i);
                            }
                            found++;
                        }
                    }
                }

                free(buffer);
            }
        }

        /* Move to the next memory region */
        addr = (unsigned char *)mbi.BaseAddress + mbi.RegionSize;

        /* Stop if we've found enough results */
        if (found >= max_results) {
            break;
        }
    }

    return found;
}

/* ========================================================================
 *  patch_memory - Overwrite bytes at a specific address in the target
 * ======================================================================== */
int patch_memory(HANDLE hProcess, void *address, const char *new_data, size_t len) {
    if (hProcess == NULL || address == NULL || new_data == NULL || len == 0) {
        return 0;
    }

    /*
     * First, try to change the memory protection to PAGE_EXECUTE_READWRITE.
     * This is necessary if the target region is read-only (e.g., the .rdata
     * section where string literals are stored).
     */
    DWORD old_protect;
    VirtualProtectEx(hProcess, address, len, PAGE_EXECUTE_READWRITE, &old_protect);

    /* Write the new data to the target address */
    SIZE_T bytes_written = 0;
    BOOL success = WriteProcessMemory(hProcess, address, new_data, len, &bytes_written);

    /* Restore original protection (best-effort, ignore failure) */
    DWORD temp;
    VirtualProtectEx(hProcess, address, len, old_protect, &temp);

    /* Flush instruction cache in case we modified executable code */
    FlushInstructionCache(hProcess, address, len);

    return (success && bytes_written == len) ? 1 : 0;
}
