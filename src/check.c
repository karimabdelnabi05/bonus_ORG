/*
 * check.c - Target program with hashed password / license verification
 *
 * This program simulates a protected software executable.
 * Instead of storing plaintext passwords, it stores an XOR hash
 * inside the binary's .data section.
 *
 * When executed, it hashes the user input and compares it against
 * the stored hash.
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

    printf("=== Software Authentication Terminal ===\n");
    printf("Enter Password / Device ID: ");
    if (!fgets(input, sizeof(input), stdin))
        return 0;

    /* Strip newline characters */
    input[strcspn(input, "\r\n")] = '\0';

    /* Validate input hash against embedded stored hash */
    if (hash_password(input) == stored_hash) {
        printf("Access Granted! Software unlocked.\n");
    } else {
        printf("Access Denied! Invalid credentials.\n");
    }

    return 0;
}
