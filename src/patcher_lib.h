/*
 * patcher_lib.h - Public interface for the runtime memory patcher
 *
 * This header defines the testable API for finding processes,
 * scanning memory, and patching strings in a running process.
 * All functions operate through the Windows API.
 */

#ifndef PATCHER_LIB_H
#define PATCHER_LIB_H

/* Force ANSI (narrow char) versions of Windows API */
#undef UNICODE
#undef _UNICODE

#include <windows.h>

/*
 * Validate that old_pw and new_pw are acceptable for patching.
 * Rules:
 *   - Both must be non-NULL and non-empty
 *   - new_pw length must be <= old_pw length (to avoid buffer overflow)
 *
 * Returns: 1 if valid, 0 if invalid
 */
int validate_input(const char *old_pw, const char *new_pw);

/*
 * Find a running process by its executable name (e.g. "check.exe").
 * Uses the Windows Toolhelp32 snapshot API.
 *
 * Returns: the Process ID (PID) if found, 0 if not found
 */
DWORD find_process_by_name(const char *process_name);

/*
 * Scan readable memory regions of a process for occurrences of a
 * byte pattern (the old password string).
 *
 * hProcess:    handle to the target process (needs PROCESS_VM_READ)
 * pattern:     the byte pattern to search for
 * pattern_len: length of the pattern in bytes
 * addresses:   output array to fill with addresses of found occurrences
 * max_results: maximum number of results to return
 *
 * Returns: number of occurrences found (0 if none)
 */
int scan_process_memory(HANDLE hProcess, const char *pattern, size_t pattern_len,
                        void **addresses, int max_results);

/*
 * Write new data at a specific address in the target process's memory.
 * Will attempt to change memory protection if the region is read-only.
 *
 * hProcess: handle to the target process (needs PROCESS_VM_WRITE + PROCESS_VM_OPERATION)
 * address:  the memory address to write to
 * new_data: the bytes to write
 * len:      number of bytes to write
 *
 * Returns: 1 on success, 0 on failure
 */
int patch_memory(HANDLE hProcess, void *address, const char *new_data, size_t len);

#endif /* PATCHER_LIB_H */
