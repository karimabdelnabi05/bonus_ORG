#undef UNICODE
#undef _UNICODE
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <string.h>

int main(void) {
    printf("====================================================\n");
    printf("  Automated Test: TRUE Algorithm-Blind Patcher      \n");
    printf("  Target: check_mystery.exe (Unknown Hash & Algo)    \n");
    printf("====================================================\n\n");

    /* Stop existing processes */
    system("taskkill /F /IM check_mystery.exe 2>NUL");
    Sleep(300);

    /* 1. Start check_mystery.exe */
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

    if (!CreateProcessA("build\\check_mystery.exe", NULL, NULL, NULL, TRUE, 0, NULL, NULL, &siCheck, &piCheck)) {
        printf("FAILED to start check_mystery.exe\n");
        return 1;
    }
    printf("[1] check_mystery.exe started with PID %lu\n", piCheck.dwProcessId);
    Sleep(500);

    DWORD written;

    /* Step 1 for check_mystery.exe: send 'aaaa' */
    printf("[2] Sending 'aaaa\\n' to check_mystery.exe...\n");
    WriteFile(hCheckStdinWr, "aaaa\n", 5, &written, NULL);
    Sleep(300);

    /* 2. Run debug_patcher.exe check_mystery.exe pass */
    printf("[3] Starting debug_patcher.exe check_mystery.exe pass...\n");
    STARTUPINFOA siPatcher;
    PROCESS_INFORMATION piPatcher;
    ZeroMemory(&siPatcher, sizeof(siPatcher));
    siPatcher.cb = sizeof(siPatcher);

    HANDLE hPatcherStdinRd, hPatcherStdinWr;
    CreatePipe(&hPatcherStdinRd, &hPatcherStdinWr, &sa, 0);
    SetHandleInformation(hPatcherStdinWr, HANDLE_FLAG_INHERIT, 0);

    HANDLE hPatcherStdoutRd, hPatcherStdoutWr;
    CreatePipe(&hPatcherStdoutRd, &hPatcherStdoutWr, &sa, 0);
    SetHandleInformation(hPatcherStdoutRd, HANDLE_FLAG_INHERIT, 0);

    siPatcher.dwFlags = STARTF_USESTDHANDLES;
    siPatcher.hStdInput = hPatcherStdinRd;
    siPatcher.hStdOutput = hPatcherStdoutWr;
    siPatcher.hStdError = hPatcherStdoutWr;

    if (!CreateProcessA("build\\debug_patcher.exe", "build\\debug_patcher.exe check_mystery.exe pass", NULL, NULL, TRUE, 0, NULL, NULL, &siPatcher, &piPatcher)) {
        printf("FAILED to start debug_patcher.exe\n");
        return 1;
    }
    printf("[4] debug_patcher.exe started with PID %lu\n", piPatcher.dwProcessId);
    Sleep(500);

    /* Patcher Step 1 Enter */
    printf("[5] Sending Enter to patcher (Step 1)... \n");
    WriteFile(hPatcherStdinWr, "\n", 1, &written, NULL);
    Sleep(500);

    /* Step 2 for check_mystery.exe: send 'bbbb' */
    printf("[6] Sending 'bbbb\\n' to check_mystery.exe...\n");
    WriteFile(hCheckStdinWr, "bbbb\n", 5, &written, NULL);
    Sleep(300);

    /* Patcher Step 2 Enter */
    printf("[7] Sending Enter to patcher (Step 2)... \n");
    WriteFile(hPatcherStdinWr, "\n", 1, &written, NULL);
    Sleep(500);

    /* Step 3 for check_mystery.exe: send 'pass' FIRST */
    printf("[8] Sending 'pass\\n' to check_mystery.exe...\n");
    WriteFile(hCheckStdinWr, "pass\n", 5, &written, NULL);
    Sleep(300);

    /* Patcher Step 3 Enter */
    printf("[9] Sending Enter to patcher (Step 3)... \n");
    WriteFile(hPatcherStdinWr, "\n", 1, &written, NULL);

    /* Wait for patcher to complete */
    WaitForSingleObject(piPatcher.hProcess, 5000);

    char patcherOut[4096] = {0};
    DWORD readBytes = 0;
    PeekNamedPipe(hPatcherStdoutRd, NULL, 0, NULL, &readBytes, NULL);
    if (readBytes > 0) {
        ReadFile(hPatcherStdoutRd, patcherOut, sizeof(patcherOut) - 1, &readBytes, NULL);
        printf("\n--- Patcher Output (Algorithm-Blind) ---\n%s\n----------------------------------------\n\n", patcherOut);
    }

    /* Clear stdout pipe buffer */
    char junk[4096];
    while (PeekNamedPipe(hCheckStdoutRd, NULL, 0, NULL, &readBytes, NULL) && readBytes > 0) {
        ReadFile(hCheckStdoutRd, junk, sizeof(junk) - 1, &readBytes, NULL);
    }

    /* 3. Send "pass\n" to check_mystery.exe to verify Access Granted */
    printf("[10] Verifying patched check_mystery.exe with 'pass\\n'...\n");
    WriteFile(hCheckStdinWr, "pass\n", 5, &written, NULL);
    Sleep(500);

    char checkOut[4096] = {0};
    PeekNamedPipe(hCheckStdoutRd, NULL, 0, NULL, &readBytes, NULL);
    if (readBytes > 0) {
        ReadFile(hCheckStdoutRd, checkOut, sizeof(checkOut) - 1, &readBytes, NULL);
        printf("\n--- check_mystery.exe Output ---\n%s\n--------------------------------\n\n", checkOut);
    }

    TerminateProcess(piCheck.hProcess, 0);
    TerminateProcess(piPatcher.hProcess, 0);
    CloseHandle(piCheck.hProcess);
    CloseHandle(piCheck.hThread);
    CloseHandle(piPatcher.hProcess);
    CloseHandle(piPatcher.hThread);

    return 0;
}
