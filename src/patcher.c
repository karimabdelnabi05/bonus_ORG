/*
 * patcher.c - Binary file patcher for hash-based password programs
 *
 * How it works:
 *   1. You reverse-engineer check.exe (using x64dbg or a hex editor) to find:
 *      - The hash algorithm used (djb2)
 *      - The stored hash value (401824839 = 0x17F28347)
 *   2. This patcher opens check.exe as a binary FILE on disk.
 *   3. It searches for the old hash bytes in the file.
 *   4. It replaces them with hash(new_password).
 *   5. Now check.exe accepts your new password.
 *
 * Usage: patcher.exe <target.exe> <old_hash> <new_password>
 * Example: patcher.exe check.exe 401824839 mypass
 *
 * Compile: gcc -o patcher.exe src/patcher.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* djb2 hash function - same algorithm found in check.exe via reverse engineering */
static unsigned long djb2(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("Usage: %s <target.exe> <old_hash> <new_password>\n", argv[0]);
        printf("Example: %s check.exe 401824839 mypass\n", argv[0]);
        return 1;
    }

    const char *target_path = argv[1];
    unsigned long old_hash = strtoul(argv[2], NULL, 10);
    const char *new_password = argv[3];
    unsigned long new_hash = djb2(new_password);

    printf("=== Binary File Patcher ===\n\n");
    printf("Target file:  %s\n", target_path);
    printf("Old hash:     %lu (0x%08lX)\n", old_hash, old_hash);
    printf("New password: \"%s\"\n", new_password);
    printf("New hash:     %lu (0x%08lX)\n\n", new_hash, new_hash);

    /* Step 1: Read the entire binary file into memory */
    FILE *f = fopen(target_path, "rb");
    if (!f) {
        printf("ERROR: Cannot open \"%s\"\n", target_path);
        return 1;
    }
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char *data = (unsigned char *)malloc(file_size);
    fread(data, 1, file_size, f);
    fclose(f);

    printf("Read %ld bytes from \"%s\"\n", file_size, target_path);

    /* Step 2: Search for the old hash bytes (little-endian) in the binary */
    unsigned char old_bytes[4];
    old_bytes[0] = (old_hash) & 0xFF;
    old_bytes[1] = (old_hash >> 8) & 0xFF;
    old_bytes[2] = (old_hash >> 16) & 0xFF;
    old_bytes[3] = (old_hash >> 24) & 0xFF;

    unsigned char new_bytes[4];
    new_bytes[0] = (new_hash) & 0xFF;
    new_bytes[1] = (new_hash >> 8) & 0xFF;
    new_bytes[2] = (new_hash >> 16) & 0xFF;
    new_bytes[3] = (new_hash >> 24) & 0xFF;

    printf("Searching for bytes: %02X %02X %02X %02X\n", old_bytes[0], old_bytes[1], old_bytes[2], old_bytes[3]);

    int found = 0;
    long patch_offset = -1;

    for (long i = 0; i <= file_size - 4; i++) {
        if (data[i]   == old_bytes[0] &&
            data[i+1] == old_bytes[1] &&
            data[i+2] == old_bytes[2] &&
            data[i+3] == old_bytes[3]) {
            patch_offset = i;
            found++;
        }
    }

    if (found == 0) {
        printf("ERROR: Old hash not found in binary.\n");
        free(data);
        return 1;
    }

    printf("Found old hash at file offset 0x%lX (%d occurrence(s))\n\n", patch_offset, found);

    /* Step 3: Replace old hash bytes with new hash bytes */
    data[patch_offset]   = new_bytes[0];
    data[patch_offset+1] = new_bytes[1];
    data[patch_offset+2] = new_bytes[2];
    data[patch_offset+3] = new_bytes[3];

    /* Step 4: Write patched binary back to disk */
    f = fopen(target_path, "wb");
    if (!f) {
        printf("ERROR: Cannot write to \"%s\"\n", target_path);
        free(data);
        return 1;
    }
    fwrite(data, 1, file_size, f);
    fclose(f);
    free(data);

    printf("=== SUCCESS ===\n");
    printf("Patched \"%s\" at offset 0x%lX\n", target_path, patch_offset);
    printf("Old hash: %lu -> New hash: %lu\n", old_hash, new_hash);
    printf("Now run \"%s\" and type \"%s\" to get Access Granted!\n", target_path, new_password);

    return 0;
}
