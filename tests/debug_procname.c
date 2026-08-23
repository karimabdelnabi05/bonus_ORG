#undef UNICODE
#undef _UNICODE
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

int main(void) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("Failed to create snapshot, error %lu\n", GetLastError());
        return 1;
    }
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(snapshot, &entry)) {
        do {
            printf("PID: %6lu | Name: [%s]\n", (unsigned long)entry.th32ProcessID, entry.szExeFile);
        } while (Process32Next(snapshot, &entry));
    } else {
        printf("Process32First failed, error %lu\n", GetLastError());
    }
    CloseHandle(snapshot);
    return 0;
}
