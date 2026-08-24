#undef UNICODE
#undef _UNICODE
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <string.h>

int main(void) {
    printf("=========================================\n");
    printf("  Automated E2E Test for debug_patcher   \n");
    printf("=========================================\n\n");

    /* Stop existing check.exe */
    system("taskkill /F /IM check.exe 2>NUL");
    Sleep(300);

    /* 1. Start check.exe in background */
    STARTUPINFOA siCheck;
    PROCESS_INFORMATION piCheck;
    ZeroMemory(&siCheck, sizeof(siCheck));
    siCheck.cb = sizeof(siCheck);
    ZeroMemory(&piCheck, sizeof(piCheck));

    HANDLE hCheckStdinRd, hCheckStdinWr;
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;
    CreatePipe(&hCheckStdinRd, &hCheckStdinWr, &sa, 0);
    SetHandleInformation(hCheckStdinWr, HANDLE_FLAG_INHERIT, 0);

    HANDLE hCheckStdoutRd, hCheckStdoutWr;
    CreatePipe(&hCheckStdoutRd, &hCheckStdoutWr, &sa, 0);
    SetHandleInformation(hCheckStdoutRd, HANDLE_FLAG_INHERIT, 0);

    siCheck.dwFlags = STARTF_USESTDHANDLES;
    siCheck.hStdInput = hCheckStdinRd;
    siCheck.hStdOutput = hCheckStdoutWr;
    siCheck.hStdError = hCheckStdoutWr;

    if (!CreateProcessA("build\\check.exe", NULL, NULL, NULL, TRUE, 0, NULL, NULL, &siCheck, &piCheck)) {
        printf("FAILED to start check.exe\n");
        return 1;
    }
    printf("[1] check.exe started with PID %lu\n", piCheck.dwProcessId);
    Sleep(500);

    /* 2. Run debug_patcher.exe check.exe pass */
    printf("[2] Running debug_patcher.exe check.exe pass...\n");
    STARTUPINFOA siPatcher;
    PROCESS_INFORMATION piPatcher;
    ZeroMemory(&siPatcher, sizeof(siPatcher));
    siPatcher.cb = sizeof(siPatcher);

    HANDLE hPatcherStdoutRd, hPatcherStdoutWr;
    CreatePipe(&hPatcherStdoutRd, &hPatcherStdoutWr, &sa, 0);
    SetHandleInformation(hPatcherStdoutRd, HANDLE_FLAG_INHERIT, 0);

    siPatcher.dwFlags = STARTF_USESTDHANDLES;
    siPatcher.hStdOutput = hPatcherStdoutWr;
    siPatcher.hStdError = hPatcherStdoutWr;

    if (!CreateProcessA("build\\debug_patcher.exe", "build\\debug_patcher.exe check.exe pass", NULL, NULL, TRUE, 0, NULL, NULL, &siPatcher, &piPatcher)) {
        printf("FAILED to start debug_patcher.exe\n");
        return 1;
    }
    printf("[3] debug_patcher.exe started with PID %lu\n", piPatcher.dwProcessId);

    /* Wait for patcher to complete */
    WaitForSingleObject(piPatcher.hProcess, 5000);

    char patcherOut[4096] = {0};
    DWORD readBytes = 0;
    PeekNamedPipe(hPatcherStdoutRd, NULL, 0, NULL, &readBytes, NULL);
    if (readBytes > 0) {
        ReadFile(hPatcherStdoutRd, patcherOut, sizeof(patcherOut) - 1, &readBytes, NULL);
        printf("\n--- Patcher Output ---\n%s\n----------------------\n\n", patcherOut);
    }

    /* Clear check.exe pipe buffer */
    char junk[4096];
    while (PeekNamedPipe(hCheckStdoutRd, NULL, 0, NULL, &readBytes, NULL) && readBytes > 0) {
        ReadFile(hCheckStdoutRd, junk, sizeof(junk) - 1, &readBytes, NULL);
    }

    /* 3. Send "pass\n" to check.exe to verify Access Granted */
    printf("[4] Sending 'pass\\n' to check.exe...\n");
    DWORD written;
    WriteFile(hCheckStdinWr, "pass\n", 5, &written, NULL);
    Sleep(500);

    char checkOut[4096] = {0};
    PeekNamedPipe(hCheckStdoutRd, NULL, 0, NULL, &readBytes, NULL);
    if (readBytes > 0) {
        ReadFile(hCheckStdoutRd, checkOut, sizeof(checkOut) - 1, &readBytes, NULL);
        printf("\n--- check.exe Output ---\n%s\n------------------------\n\n", checkOut);
    }

    /* 4. Send "s3cr3t\n" to check.exe to verify Access Denied */
    printf("[5] Sending 's3cr3t\\n' (old password) to check.exe...\n");
    WriteFile(hCheckStdinWr, "s3cr3t\n", 7, &written, NULL);
    Sleep(500);

    ZeroMemory(checkOut, sizeof(checkOut));
    PeekNamedPipe(hCheckStdoutRd, NULL, 0, NULL, &readBytes, NULL);
    if (readBytes > 0) {
        ReadFile(hCheckStdoutRd, checkOut, sizeof(checkOut) - 1, &readBytes, NULL);
        printf("\n--- check.exe Output for old password ---\n%s\n-----------------------------------------\n\n", checkOut);
    }

    TerminateProcess(piCheck.hProcess, 0);
    TerminateProcess(piPatcher.hProcess, 0);
    CloseHandle(piCheck.hProcess);
    CloseHandle(piCheck.hThread);
    CloseHandle(piPatcher.hProcess);
    CloseHandle(piPatcher.hThread);

    return 0;
}
