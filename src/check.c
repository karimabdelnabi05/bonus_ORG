/*
 * check.c - Target program with hashed password storage
 *
 * The password is NOT stored as plaintext in the binary.
 * Instead, a hash of the password is stored in the .data section.
 * User input is hashed at runtime and compared against the stored hash.
 *
 * Original password: "s3cr3t" -> hash = 401824839 (0x17F35C47)
 *
 * Compile: gcc -o check.exe src/check.c
 */

#include <stdio.h>
#include <string.h>

/* Hash algorithm (djb2: hash * 33 + c) */
static unsigned long hash_password(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

/* Stored hash of "s3cr3t" - located in the .data section of the binary */
unsigned long stored_hash = 401824839UL;

int main(void) {
    char input[256];

    printf("Enter password: ");
    if (!fgets(input, sizeof(input), stdin))
        return 0;

    /* Strip newline characters */
    input[strcspn(input, "\r\n")] = '\0';

    /* Compare computed input hash against stored hash */
    if (hash_password(input) == stored_hash) {
        printf("Access Granted\n");
    } else {
        printf("Access Denied\n");
    }

    return 0;
}
