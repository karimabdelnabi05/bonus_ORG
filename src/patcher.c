/*
 * patcher.c - Binary File HEX Password Patcher (Hashed Identifier Method)
 *
 * How it works:
 *   1. Computes the XOR hash of the identifier tag ("PASSTAG").
 *   2. Computes the XOR hash of the desired new password.
 *   3. Scans the binary file on disk for the 4-byte HASHED TAG (0x0B7624C3 / Bytes: C3 24 76 0B).
 *   4. The 4 bytes immediately following the tag hash (offset + 4) hold the password hash.
 *   5. Overwrites the 4 bytes on disk with the new password hash.
 *   6. When check.exe runs again, it permanently accepts the new password!
 *
 * Usage: patcher.exe <target.exe> <new_password>
 * Example: patcher.exe check.exe mypass
 *
 * Compile: gcc -o patcher.exe src/patcher.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The agreed-upon identifier tag string */
#define TAG_STRING "PASSTAG"

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

    /* Calculate 32-bit hashes using the known XOR hash algorithm */
    unsigned long tag_hash = xor_hash(TAG_STRING);
    unsigned long new_hash = xor_hash(new_password);

    /* Convert tag hash to 4 Little-Endian bytes */
    unsigned char tag_bytes[4];
    tag_bytes[0] = (tag_hash) & 0xFF;
    tag_bytes[1] = (tag_hash >> 8) & 0xFF;
    tag_bytes[2] = (tag_hash >> 16) & 0xFF;
    tag_bytes[3] = (tag_hash >> 24) & 0xFF;

    printf("============================================================\n");
    printf("      Binary File HEX Patcher (Hashed Identifier Method)    \n");
    printf("============================================================\n\n");
    printf("Target File:      %s\n", target_path);
    printf("Identifier:       \"%s\" -> HASH: %lu (Hex: 0x%08lX)\n", TAG_STRING, tag_hash, tag_hash);
    printf("Tag Search Bytes: %02X %02X %02X %02X\n", tag_bytes[0], tag_bytes[1], tag_bytes[2], tag_bytes[3]);
    printf("New Password:     \"%s\" -> HASH: %lu (Hex: 0x%08lX)\n\n", new_password, new_hash, new_hash);

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

    /* Step 3: Scan the binary file for the 4-byte HASHED TAG */
    long tag_offset = -1;
    for (long i = 0; i <= file_size - 8; i++) {
        if (memcmp(data + i, tag_bytes, 4) == 0) {
            tag_offset = i;
            break;
        }
    }

    if (tag_offset < 0) {
        printf("ERROR: Hashed identifier (%02X %02X %02X %02X) not found in \"%s\".\n",
               tag_bytes[0], tag_bytes[1], tag_bytes[2], tag_bytes[3], target_path);
        free(data);
        fclose(f);
        return 1;
    }

    /* Step 4: Stored password hash is located immediately after the 4-byte tag hash */
    long patch_offset = tag_offset + 4;
    unsigned long old_hash = *(unsigned long *)(data + patch_offset);

    /* Step 5: Prepare little-endian new hash bytes */
    unsigned char old_bytes[4];
    memcpy(old_bytes, data + patch_offset, 4);

    unsigned char new_bytes[4];
    new_bytes[0] = (new_hash) & 0xFF;
    new_bytes[1] = (new_hash >> 8) & 0xFF;
    new_bytes[2] = (new_hash >> 16) & 0xFF;
    new_bytes[3] = (new_hash >> 24) & 0xFF;

    printf("[*] Found Hashed Tag at File Offset:          0x%lX (Bytes: %02X %02X %02X %02X)\n",
           tag_offset, tag_bytes[0], tag_bytes[1], tag_bytes[2], tag_bytes[3]);
    printf("[*] Target Stored Hash located at File Offset: 0x%lX\n", patch_offset);
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
