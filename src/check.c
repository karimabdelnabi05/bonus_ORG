/*
 * check.c - Target program with hashed password verification
 *
 * This program validates a password against an XOR hash
 * stored inside the binary's .data section.
 * The plaintext password is not stored in the binary.
 *
 * Default Password: "s3cr3t" -> Hash: 287671138 (0x11258362)
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

/* Stored hash located in the .data section of the binary */
unsigned long stored_hash = 287671138UL;

int main(void) {
    char input[256];

    printf("=== Password Verification Terminal ===\n");
    printf("Enter Password: ");
    if (!fgets(input, sizeof(input), stdin))
        return 0;

    /* Strip newline characters */
    input[strcspn(input, "\r\n")] = '\0';

    /* Validate input hash against embedded stored hash */
    if (hash_password(input) == stored_hash) {
        printf("Access Granted\n");
    } else {
        printf("Access Denied\n");
    }

    return 0;
}
