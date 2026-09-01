/*
 * patcher.c - Binary File HEX Password Patcher (Identifier Tag Method)
 *
 * How it works:
 *   1. Opens the target .exe file on disk in binary read/write mode ("rb+").
 *   2. Computes the XOR hash of the new password: (hash * 31) ^ character.
 *   3. Scans the binary file searching for the magic identifier tag ("PASSTAG_").
 *   4. The 4 bytes immediately following the tag (offset + 8) hold the stored hash.
 *   5. Replaces the old HEX bytes with the new hash HEX bytes on disk.
 *   6. Closes the file. When check.exe is run again, it accepts the new password!
 *
 * Usage: patcher.exe <target.exe> <new_password>
 * Example: patcher.exe check.exe mypass
 *
 * Compile: gcc -o patcher.exe src/patcher.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The 8-byte magic identifier placed before the stored hash */
#define MAGIC_TAG "PASSTAG_"
#define TAG_LEN 8

/* Known XOR hash function: (hash * 31) ^ character (initial seed: 0x5A) */
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
    unsigned long new_hash = xor_hash(new_password);

    printf("============================================================\n");
    printf("        Binary File HEX Patcher (Identifier Tag Method)     \n");
    printf("============================================================\n\n");
    printf("Target File:  %s\n", target_path);
    printf("Identifier:   \"%s\" (%d bytes)\n", MAGIC_TAG, TAG_LEN);
    printf("New Password: \"%s\"\n", new_password);
    printf("New Hash:     %lu (Hex: 0x%08lX)\n\n", new_hash, new_hash);

    /* Step 1: Open the binary file on disk */
    FILE *f = fopen(target_path, "rb+");
    if (!f) {
        printf("ERROR: Cannot open file \"%s\". Make sure the file exists and is closed.\n", target_path);
        return 1;
    }

    /* Step 2: Read entire binary into memory */
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char *data = (unsigned char *)malloc(file_size);
    if (!data) {
        printf("ERROR: Memory allocation failed.\n");
        fclose(f);
        return 1;
    }
    fread(data, 1, file_size, f);

    /* Step 3: Scan the binary file for the MAGIC_TAG identifier */
    long tag_offset = -1;
    for (long i = 0; i <= file_size - TAG_LEN - 4; i++) {
        if (memcmp(data + i, MAGIC_TAG, TAG_LEN) == 0) {
            tag_offset = i;
            break;
        }
    }

    if (tag_offset < 0) {
        printf("ERROR: Magic identifier \"%s\" not found in \"%s\".\n", MAGIC_TAG, target_path);
        free(data);
        fclose(f);
        return 1;
    }

    /* Step 4: The stored hash is located immediately after the 8-byte tag */
    long patch_offset = tag_offset + TAG_LEN;
    unsigned long old_hash = *(unsigned long *)(data + patch_offset);

    /* Step 5: Prepare little-endian new hash bytes */
    unsigned char old_bytes[4];
    memcpy(old_bytes, data + patch_offset, 4);

    unsigned char new_bytes[4];
    new_bytes[0] = (new_hash) & 0xFF;
    new_bytes[1] = (new_hash >> 8) & 0xFF;
    new_bytes[2] = (new_hash >> 16) & 0xFF;
    new_bytes[3] = (new_hash >> 24) & 0xFF;

    printf("[*] Found Identifier \"%s\" at File Offset: 0x%lX\n", MAGIC_TAG, tag_offset);
    printf("[*] Target Stored Hash located at File Offset:      0x%lX\n", patch_offset);
    printf("    OLD HEX Bytes:  %02X %02X %02X %02X  (Hash: %lu / 0x%08lX)\n",
           old_bytes[0], old_bytes[1], old_bytes[2], old_bytes[3], old_hash, old_hash);
    printf("    NEW HEX Bytes:  %02X %02X %02X %02X  (Hash: %lu / 0x%08lX)\n\n",
           new_bytes[0], new_bytes[1], new_bytes[2], new_bytes[3], new_hash, new_hash);

    /* Step 6: Overwrite the 4 bytes on disk */
    fseek(f, patch_offset, SEEK_SET);
    fwrite(new_bytes, 1, 4, f);

    fclose(f);
    free(data);

    printf("============================================================\n");
    printf(">>> SUCCESS: %s has been permanently patched on disk!\n", target_path);
    printf(">>> Now run \"%s\" and enter \"%s\" to verify Access Granted!\n", target_path, new_password);
    printf("============================================================\n");

    return 0;
}
