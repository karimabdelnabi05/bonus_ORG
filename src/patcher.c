/*
 * patcher.c - Binary File HEX Password Patcher
 *
 * How it works:
 *   1. Opens the target .exe file directly on disk in binary read/write mode.
 *   2. Computes the XOR hash of the new password: (hash * 31) ^ character.
 *   3. Scans the binary HEX of the file to locate the embedded 4-byte hash.
 *   4. Replaces the old HEX bytes with the new hash HEX bytes on disk.
 *   5. Closes the file. When check.exe is opened again, it uses the new password!
 *
 * Usage: patcher.exe <target.exe> <new_password>
 * Example: patcher.exe check.exe mypass
 *
 * Compile: gcc -o patcher.exe src/patcher.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    printf("                  Binary File HEX Patcher                   \n");
    printf("============================================================\n\n");
    printf("Target File:  %s\n", target_path);
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

    /* Step 3: Parse PE headers to locate the .data section */
    if (data[0] != 'M' || data[1] != 'Z') {
        printf("ERROR: Not a valid Windows PE executable (missing MZ header).\n");
        free(data);
        fclose(f);
        return 1;
    }

    unsigned long pe_offset = *(unsigned long *)(data + 0x3C);
    unsigned short num_sections = *(unsigned short *)(data + pe_offset + 6);
    unsigned short opt_hdr_size = *(unsigned short *)(data + pe_offset + 20);
    unsigned long sections_start = pe_offset + 24 + opt_hdr_size;

    long data_file_offset = -1;
    long data_size = 0;

    for (int i = 0; i < num_sections; i++) {
        unsigned char *sec = data + sections_start + (i * 40);
        char name[9] = {0};
        memcpy(name, sec, 8);

        if (strcmp(name, ".data") == 0) {
            data_size = *(unsigned long *)(sec + 16);
            data_file_offset = *(unsigned long *)(sec + 20);
            break;
        }
    }

    if (data_file_offset < 0) {
        printf("ERROR: .data section not found in PE binary.\n");
        free(data);
        fclose(f);
        return 1;
    }

    /* Step 4: Find the stored hash location in .data section */
    long patch_offset = -1;
    unsigned long old_hash = 0;

    for (long off = 0; off + 4 <= data_size; off += 4) {
        unsigned long val = *(unsigned long *)(data + data_file_offset + off);
        if (val != 0) {
            patch_offset = data_file_offset + off;
            old_hash = val;
            break;
        }
    }

    if (patch_offset < 0) {
        printf("ERROR: No stored hash found in .data section.\n");
        free(data);
        fclose(f);
        return 1;
    }

    /* Step 5: Display HEX byte comparison */
    unsigned char old_bytes[4];
    memcpy(old_bytes, data + patch_offset, 4);

    unsigned char new_bytes[4];
    new_bytes[0] = (new_hash) & 0xFF;
    new_bytes[1] = (new_hash >> 8) & 0xFF;
    new_bytes[2] = (new_hash >> 16) & 0xFF;
    new_bytes[3] = (new_hash >> 24) & 0xFF;

    printf("[*] Found stored hash in .data section at File Offset: 0x%lX\n", patch_offset);
    printf("    OLD HEX Bytes:  %02X %02X %02X %02X  (Hash: %lu / 0x%08lX)\n",
           old_bytes[0], old_bytes[1], old_bytes[2], old_bytes[3], old_hash, old_hash);
    printf("    NEW HEX Bytes:  %02X %02X %02X %02X  (Hash: %lu / 0x%08lX)\n\n",
           new_bytes[0], new_bytes[1], new_bytes[2], new_bytes[3], new_hash, new_hash);

    /* Step 6: Overwrite the HEX bytes on disk */
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
