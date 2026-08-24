/*
 * check_mystery.c - Target program with a mystery secret password
 *
 * The secret password and stored hash value are completely different from check.exe.
 * The attacker (and patcher) knows NOTHING about the stored hash integer in this binary.
 *
 * Compile: gcc -o check_mystery.exe src/check_mystery.c
 */

#include <stdio.h>
#include <string.h>
#include <windows.h>

/* djb2 hash function */
static unsigned long hash_password(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

/*
 * Secret password: "ComplexMysteryPass2026!"
 * djb2 hash = 3982710495UL
 *
 * Plaintext string "ComplexMysteryPass2026!" does NOT exist in memory or binary.
 */
volatile unsigned long stored_hash = 3982710495UL;

int main(int argc, char *argv[]) {
    int daemon_mode = 0;
    if (argc > 1 && (strcmp(argv[1], "-d") == 0 || strcmp(argv[1], "--daemon") == 0)) {
        daemon_mode = 1;
    }

    char input[256];

    printf("=== MYSTERY Access Terminal (Unknown Hash Target) ===\n");
    printf("(Press Ctrl+C to exit)\n\n");

    while (1) {
        printf("Enter password: ");
        fflush(stdout);

        if (fgets(input, sizeof(input), stdin) == NULL) {
            if (daemon_mode) {
                while (1) { Sleep(1000); }
            } else {
                break;
            }
        }

        size_t len = strlen(input);
        while (len > 0 && (input[len - 1] == '\n' || input[len - 1] == '\r' ||
                           input[len - 1] == ' '  || input[len - 1] == '\t')) {
            input[--len] = '\0';
        }

        volatile unsigned long input_hash = hash_password(input);

        if (input_hash == stored_hash) {
            printf("Access Granted\n");
        } else {
            printf("Access Denied\n");
        }
        printf("\n");
    }

    return 0;
}
