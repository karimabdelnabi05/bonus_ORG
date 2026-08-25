/*
 * patcher.c - Binary file patcher for hash-based password authentication
 *
 * How it works:
 *   1. You analyze check.exe in assembly/binary to find:
 *      - The hash algorithm used: djb2 (hash * 33 + c, initial 5381)
 *      - The stored hash value: 401824839 (0x17F35C47)
 *   2. This program opens check.exe as a binary file on disk.
 *   3. It computes the djb2 hash of your desired new password.
 *   4. It finds the old hash bytes in the file and replaces them with the new hash.
 *   5. check.exe now accepts your new password!
 *
 * Usage: patcher.exe <target.exe> <new_password>
 * Example: patcher.exe check.exe mypass
 *
 * Compile: gcc -o patcher.exe src/patcher.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* djb2 hash function - identified by analyzing check.exe's assembly */
static unsigned long djb2(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <target.exe> <new_password>\n", argv[0]);
        printf("Example: %s check.exe mypass\n", argv[0]);
        return 1;
    }

    const char *target_path = argv[1];
    const char *new_password = argv[2];

    /* The original stored hash identified from reverse-engineering check.exe */
    unsigned long old_hash = 401824839UL;
    unsigned long new_hash = djb2(new_password);

    printf("=== Binary File Patcher ===\n\n");
    printf("Target File:  %s\n", target_path);
    printf("Old Hash:     %lu (0x%08lX)\n", old_hash, old_hash);
    printf("New Password: \"%s\"\n", new_password);
    printf("New Hash:     %lu (0x%08lX)\n\n", new_hash, new_hash);

    /* Step 1: Open the executable file in read+write binary mode */
    FILE *f = fopen(target_path, "rb+");
    if (!f) {
        printf("ERROR: Cannot open file \"%s\"\n", target_path);
        return 1;
    }

    /* Step 2: Get file size and read all bytes into buffer */
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char *data = (unsigned char *)malloc(file_size);
    if (!data) {
        printf("ERROR: Memory allocation failed\n");
        fclose(f);
        return 1;
    }
    fread(data, 1, file_size, f);

    /* Step 3: Search for old hash bytes (little-endian: 47 5C F3 17) */
    long patch_offset = -1;
    for (long i = 0; i <= file_size - 4; i++) {
        if (*(unsigned long *)(data + i) == old_hash) {
            patch_offset = i;
            break;
        }
    }

    if (patch_offset < 0) {
        printf("ERROR: Old hash %lu not found in \"%s\"\n", old_hash, target_path);
        free(data);
        fclose(f);
        return 1;
    }

    /* Step 4: Overwrite old hash with new hash in the file */
    fseek(f, patch_offset, SEEK_SET);
    fwrite(&new_hash, sizeof(unsigned long), 1, f);

    fclose(f);
    free(data);

    printf("=== SUCCESS ===\n");
    printf("Found old hash at file offset: 0x%lX\n", patch_offset);
    printf("Replaced with new hash:        %lu\n\n", new_hash);
    printf("Run \"%s\" and type \"%s\" to verify Access Granted!\n", target_path, new_password);

    return 0;
}
