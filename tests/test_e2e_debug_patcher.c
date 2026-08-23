#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <string.h>

int main(void) {
    printf("=== Running E2E Test for debug_patcher.exe ===\n");

    /* Spawn check.exe with piped stdin/stdout */
    HANDLE hChildStdinRd, hChildStdinWr;
    HANDLE hChildStdoutRd, hChildStdoutWr;
    SECURITY_ATTRIBUTES saAttr;
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    CreatePipe(&hChildStdoutRd, &hChildStdoutWr, &saAttr, 0);
    SetHandleInformation(hChildStdoutRd, HANDLE_FLAG_INHERIT, 0);
    CreatePipe(&hChildStdinRd, &hChildStdinWr, &saAttr, 0);
    SetHandleInformation(hChildStdinWr, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.hStdError = hChildStdoutWr;
    si.hStdOutput = hChildStdoutWr;
    si.hStdInput = hChildStdinRd;
    si.dwFlags |= STARTF_USESTDHANDLES;
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessA("build\\check.exe", NULL, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        printf("Failed to start check.exe\n");
        return 1;
    }

    printf("Started check.exe with PID %lu\n", (unsigned long)pi.dwProcessId);
    Sleep(500);

    /* Write "pass\n" to stdin */
    DWORD written;
    WriteFile(hChildStdinWr, "pass\n", 5, &written, NULL);
    Sleep(200);

    /* Write "xxxx\n" to stdin */
    WriteFile(hChildStdinWr, "xxxx\n", 5, &written, NULL);
    Sleep(200);

    /* Write "pass\n" to stdin */
    WriteFile(hChildStdinWr, "pass\n", 5, &written, NULL);
    Sleep(200);

    /* Now run debug_patcher.exe check.exe pass */
    /* Wait, debug_patcher waits for Enter in its own stdin */
    /* Let's test what debug_patcher.c is actually finding in memory */

    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hChildStdinRd);
    CloseHandle(hChildStdinWr);
    CloseHandle(hChildStdoutRd);
    CloseHandle(hChildStdoutWr);

    return 0;
}
