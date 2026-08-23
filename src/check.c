/*
 * check.c - Target program for the runtime memory patcher exercise
 *
 * This program has a hardcoded password stored in a char array.
 * It loops, asking the user for a password and printing whether
 * access is granted or denied. The password is intentionally stored
 * as a plain char[] so it can be found via memory scanning.
 *
 * Compile: gcc -o check.exe src/check.c
 */

#include <stdio.h>
#include <string.h>
#include <windows.h>

int main(int argc, char *argv[]) {
    int daemon_mode = 0;
    if (argc > 1 && (strcmp(argv[1], "-d") == 0 || strcmp(argv[1], "--daemon") == 0)) {
        daemon_mode = 1;
    }

    /*
     * The password is stored as a char array on the stack/data segment.
     * Using a char[] (not a string literal pointer) ensures the compiler
     * places a mutable copy that can be overwritten via WriteProcessMemory.
     */
    char password[] = "123";
    char input[256];

    printf("=== Secure Access Terminal ===\n");
    printf("(Press Ctrl+C to exit)\n\n");

    while (1) {
        printf("Enter password: ");
        fflush(stdout);

        if (fgets(input, sizeof(input), stdin) == NULL) {
            if (daemon_mode) {
                printf("(stdin closed - daemon waiting for patcher...)\n");
                fflush(stdout);
                while (1) { Sleep(1000); }
            } else {
                break;
            }
        }

        /* Strip all trailing whitespace (newline, carriage return, spaces, tabs) */
        size_t len = strlen(input);
        while (len > 0 && (input[len - 1] == '\n' || input[len - 1] == '\r' ||
                           input[len - 1] == ' '  || input[len - 1] == '\t')) {
            input[--len] = '\0';
        }

        if (strcmp(input, password) == 0) {
            printf("Access Granted\n");
        } else {
            printf("Access Denied\n");
        }
        printf("\n");
    }

    return 0;
}
