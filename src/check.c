/*
 * check.c - Target program with hashed password & hashed tag verification
 *
 * Both the identifier tag and the password are stored as 32-bit XOR hashes.
 * This guarantees that NO plaintext strings (neither password nor tag) exist in the binary.
 *
 * Known XOR Hash Formula: (hash * 31) ^ character (seed: 0x5A)
 *
 * Tag:      "PASSTAG" -> tag_hash    = 192292035 (Hex: 0x0B7624C3, Bytes: C3 24 76 0B)
 * Password: "s3cr3t"  -> stored_hash = 287671138 (Hex: 0x11258362, Bytes: 62 83 25 11)
 *
 * Compile: gcc -o check.exe src/check.c
 */

#include <stdio.h>
#include <string.h>

/* Known XOR hash function: (hash * 31) ^ character */
static unsigned long hash_password(const char *str) {
    unsigned long hash = 0x5A;
    int c;
    while ((c = *str++))
        hash = (hash * 31) ^ (unsigned char)c;
    return hash;
}

/* Stored authentication structure: both tag and password are 4-byte hashes */
struct AuthData {
    unsigned long tag_hash;     /* Hashed identifier: xor_hash("PASSTAG") */
    unsigned long stored_hash;  /* 4-byte stored password hash */
};

struct AuthData auth = {
    .tag_hash = 192292035UL,    /* 0x0B7624C3 (Bytes: C3 24 76 0B) */
    .stored_hash = 287671138UL  /* 0x11258362 (Bytes: 62 83 25 11) */
};

int main(void) {
    char input[256];

    printf("=== Password Verification Terminal ===\n");
    printf("Enter Password: ");
    if (!fgets(input, sizeof(input), stdin))
        return 0;

    /* Strip newline characters */
    input[strcspn(input, "\r\n")] = '\0';

    /* Validate input hash against embedded stored hash */
    if (hash_password(input) == auth.stored_hash) {
        printf("Access Granted\n");
    } else {
        printf("Access Denied\n");
    }

    return 0;
}
