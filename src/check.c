/*
 * check.c - Target program with simple XOR hash authentication
 *
 * Password storage uses a simple XOR-based hash function.
 * Plaintext password "s3cr3t" is not stored in the binary.
 *
 * Stored hash for "s3cr3t": 287671138 (0x11258362)
 *
 * Runs in a loop so you can test both:
 *   1. Static file patching (before running)
 *   2. Live RAM patching (while running)
 *
 * Compile: gcc -o check.exe src/check.c
 */

#include <stdio.h>
#include <string.h>

/* Simple XOR hash function: (hash * 31) ^ character */
static unsigned long hash_password(const char *str) {
    unsigned long hash = 0x5A;
    int c;
    while ((c = *str++))
        hash = (hash * 31) ^ (unsigned char)c;
    return hash;
}

/* Stored XOR hash of "s3cr3t" in the .data section (volatile so RAM changes take effect) */
volatile unsigned long stored_hash = 287671138UL;

int main(void) {
    char input[256];

    printf("=== Password Verification Terminal ===\n");
    printf("(Press Ctrl+C to exit)\n\n");

    while (1) {
        printf("Enter password: ");
        fflush(stdout);

        if (!fgets(input, sizeof(input), stdin))
            break;

        /* Remove trailing newline */
        input[strcspn(input, "\r\n")] = '\0';

        /* Compare computed input hash against stored hash */
        if (hash_password(input) == stored_hash) {
            printf("Access Granted\n\n");
        } else {
            printf("Access Denied\n\n");
        }
    }

    return 0;
}
