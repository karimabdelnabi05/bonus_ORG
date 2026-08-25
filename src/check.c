/*
 * check.c - Simple password checker using hashed storage
 *
 * The password is NOT stored as plaintext in the binary.
 * Instead, a hash of the password is stored in the .data section.
 * User input is hashed at runtime and compared against the stored hash.
 *
 * Hash algorithm: djb2 (Dan Bernstein)
 * Original password: "s3cr3t" -> hash = 401824839
 *
 * Compile: gcc -o check.exe src/check.c
 */

#include <stdio.h>
#include <string.h>

/* djb2 hash function */
static unsigned long hash_password(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

/* Stored hash of "s3cr3t" - lives in .data section of the PE binary */
unsigned long stored_hash = 401824839UL;

int main(void) {
    char input[256];

    printf("Enter password: ");
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\r\n")] = '\0';

    if (hash_password(input) == stored_hash) {
        printf("Access Granted\n");
    } else {
        printf("Access Denied\n");
    }

    return 0;
}
