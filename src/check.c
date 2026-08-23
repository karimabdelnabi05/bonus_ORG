/*
 * check.c - Target program with HASHED password storage
 *
 * This program stores a HASH of the password (not the plaintext).
 * It uses the djb2 hash algorithm to hash user input and compares
 * the resulting hash against the pre-computed stored hash.
 *
 * The attacker does NOT know:
 *   1. What the original password is
 *   2. What hash algorithm is used
 *   3. What the stored hash value is
 *
 * Compile: gcc -o check.exe src/check.c
 */

#include <stdio.h>
#include <string.h>
#include <windows.h>

/* ========================================================================
 *  djb2 hash function (Dan Bernstein)
 *  A well-known, simple, non-cryptographic hash function.
 *  The attacker should NOT know this function exists.
 * ======================================================================== */
static unsigned long hash_password(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;  /* hash * 33 + c */
    }
    return hash;
}

int main(int argc, char *argv[]) {
    int daemon_mode = 0;
    if (argc > 1 && (strcmp(argv[1], "-d") == 0 || strcmp(argv[1], "--daemon") == 0)) {
        daemon_mode = 1;
    }

    /*
     * Pre-computed hash of the secret password.
     * The original password string does NOT exist anywhere in memory.
     * This value was computed offline: hash_password("s3cr3t") == 3511886547
     *
     * The attacker cannot search RAM for the plaintext password
     * because it is never stored as a string.
     */
    static unsigned long stored_hash = 401824839UL;

    char input[256];

    printf("=== Secure Access Terminal (Hashed) ===\n");
    printf("(Press Ctrl+C to exit)\n\n");

    while (1) {
        printf("Enter password: ");
        fflush(stdout);

        if (fgets(input, sizeof(input), stdin) == NULL) {
            if (daemon_mode) {
                printf("(stdin closed - daemon waiting...)\n");
                fflush(stdout);
                while (1) { Sleep(1000); }
            } else {
                break;
            }
        }

        /* Strip all trailing whitespace */
        size_t len = strlen(input);
        while (len > 0 && (input[len - 1] == '\n' || input[len - 1] == '\r' ||
                           input[len - 1] == ' '  || input[len - 1] == '\t')) {
            input[--len] = '\0';
        }

        /*
         * Hash the user input and compare against stored hash.
         * The comparison uses two unsigned long values (not strings).
         * A standard string scanner searching for "s3cr3t" will find nothing.
         */
        unsigned long input_hash = hash_password(input);

        if (input_hash == stored_hash) {
            printf("Access Granted\n");
        } else {
            printf("Access Denied\n");
        }
        printf("\n");
    }

    return 0;
}
