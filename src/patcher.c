/*
 * patcher.c - Binary file patcher for simple XOR hash authentication
 *
 * How it works:
 *   1. Reverse-engineer check.exe in assembly:
 *      - Hash function: (hash * 31) ^ c (initial seed: 0x5A)
 *      - Stored hash value: 287671138 (0x11258362)
 *   2. Opens check.exe as a binary file on disk.
 *   3. Computes the XOR hash of your new password.
 *   4. Replaces the old hash bytes with the new hash bytes.
 *
 * Usage: patcher.exe <target.exe> <new_password>
 * Example: patcher.exe check.exe mypass
 *
 * Compile: gcc -o patcher.exe src/patcher.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Simple XOR hash function identified from check.exe disassembly */
static unsigned long xor_hash(const char *str) {
    unsigned long hash = 0x5A;
    int c;
    while ((c = *str++))
        hash = (hash * 31) ^ (unsigned char)c;
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

    /* Stored hash discovered by inspecting check.exe binary */
    unsigned long old_hash = 287671138UL;
    unsigned long new_hash = xor_hash(new_password);

    printf("=== Binary File Patcher (XOR Hash) ===\n\n");
    printf("Target File:  %s\n", target_path);
    printf("Old Hash:     %lu (0x%08lX)\n", old_hash, old_hash);
    printf("New Password: \"%s\"\n", new_password);
    printf("New Hash:     %lu (0x%08lX)\n\n", new_hash, new_hash);

    /* Step 1: Open executable in read+write binary mode */
    FILE *f = fopen(target_path, "rb+");
    if (!f) {
        printf("ERROR: Cannot open file \"%s\"\n", target_path);
        return 1;
    }

    /* Step 2: Read binary into buffer */
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

    /* Step 3: Find old hash bytes in binary */
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

    /* Step 4: Overwrite old hash with new hash */
    fseek(f, patch_offset, SEEK_SET);
    fwrite(&new_hash, sizeof(unsigned long), 1, f);

    fclose(f);
    free(data);

    printf("=== SUCCESS ===\n");
    printf("Found old hash at file offset: 0x%lX\n", patch_offset);
    printf("Replaced with new hash:        %lu (0x%08lX)\n\n", new_hash, new_hash);
    printf("Run \"%s\" and type \"%s\" to verify Access Granted!\n", target_path, new_password);

    return 0;
}
