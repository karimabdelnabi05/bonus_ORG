/*
 * check.c - Target program with simple XOR hash authentication
 *
 * Password storage uses a simple XOR-based hash function.
 * Plaintext password "s3cr3t" is not stored in the binary.
 *
 * Stored hash for "s3cr3t": 287671138 (0x11258362)
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

/* Stored XOR hash of "s3cr3t" in the .data section */
unsigned long stored_hash = 287671138UL;

int main(void) {
    char input[256];

    printf("Enter password: ");
    if (!fgets(input, sizeof(input), stdin))
        return 0;

    /* Remove trailing newline */
    input[strcspn(input, "\r\n")] = '\0';

    /* Compare computed input hash against stored hash */
    if (hash_password(input) == stored_hash) {
        printf("Access Granted\n");
    } else {
        printf("Access Denied\n");
    }

    return 0;
}
