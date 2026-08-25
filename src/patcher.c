/*
 * patcher.c - Binary file patcher for hash-based password programs
 *
 * This patcher does NOT know the original password or the stored hash.
 * It opens check.exe as a binary file, parses the PE structure to find
 * the .data section, locates the stored hash value, and replaces it
 * with the hash of a new password.
 *
 * Usage: patcher.exe <target.exe> <new_password>
 * Example: patcher.exe check.exe mypass
 *
 * Compile: gcc -o patcher.exe src/patcher.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* djb2 hash function - identified by reverse-engineering the target binary */
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
    unsigned long new_hash = djb2(new_password);

    printf("=== Binary File Patcher ===\n\n");
    printf("Target file:  %s\n", target_path);
    printf("New password: \"%s\"\n", new_password);
    printf("New hash:     %lu (0x%08lX)\n\n", new_hash, new_hash);

    /* Step 1: Read the entire binary file */
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

    /* Step 2: Parse PE headers to find .data section */

    /* DOS header: first 2 bytes must be "MZ" */
    if (data[0] != 'M' || data[1] != 'Z') {
        printf("ERROR: Not a valid PE file (missing MZ header)\n");
        free(data);
        return 1;
    }

    /* e_lfanew at offset 0x3C gives the offset to PE signature */
    unsigned long pe_offset = *(unsigned long *)(data + 0x3C);
    if (data[pe_offset] != 'P' || data[pe_offset + 1] != 'E') {
        printf("ERROR: Not a valid PE file (missing PE signature)\n");
        free(data);
        return 1;
    }

    /* COFF header starts at pe_offset + 4 */
    unsigned short num_sections = *(unsigned short *)(data + pe_offset + 6);
    unsigned short optional_header_size = *(unsigned short *)(data + pe_offset + 20);

    /* Section headers start after optional header */
    unsigned long sections_offset = pe_offset + 24 + optional_header_size;

    printf("PE file: %d sections found\n", num_sections);

    /* Step 3: Find .data section */
    long data_section_offset = -1;
    long data_section_size = 0;

    for (int i = 0; i < num_sections; i++) {
        unsigned char *sec = data + sections_offset + (i * 40);
        char sec_name[9] = {0};
        memcpy(sec_name, sec, 8);

        unsigned long raw_size = *(unsigned long *)(sec + 16);
        unsigned long raw_offset = *(unsigned long *)(sec + 20);

        printf("  Section: %-8s  offset=0x%lX  size=0x%lX\n", sec_name, raw_offset, raw_size);

        if (strcmp(sec_name, ".data") == 0) {
            data_section_offset = raw_offset;
            data_section_size = raw_size;
        }
    }

    if (data_section_offset < 0) {
        printf("ERROR: .data section not found\n");
        free(data);
        return 1;
    }

    printf("\n.data section at file offset 0x%lX, size 0x%lX\n", data_section_offset, data_section_size);

    /* Step 4: Scan .data section for the stored hash (first non-zero 4-byte value) */
    long patch_offset = -1;
    unsigned long old_hash = 0;

    for (long i = data_section_offset; i + 4 <= data_section_offset + data_section_size; i += 4) {
        unsigned long val = *(unsigned long *)(data + i);
        if (val != 0) {
            patch_offset = i;
            old_hash = val;
            break;
        }
    }

    if (patch_offset < 0) {
        printf("ERROR: No stored hash found in .data section\n");
        free(data);
        return 1;
    }

    printf("Found stored hash: %lu (0x%08lX) at file offset 0x%lX\n\n", old_hash, old_hash, patch_offset);

    /* Step 5: Replace old hash with new hash */
    unsigned char new_bytes[4];
    new_bytes[0] = (new_hash) & 0xFF;
    new_bytes[1] = (new_hash >> 8) & 0xFF;
    new_bytes[2] = (new_hash >> 16) & 0xFF;
    new_bytes[3] = (new_hash >> 24) & 0xFF;

    data[patch_offset]   = new_bytes[0];
    data[patch_offset+1] = new_bytes[1];
    data[patch_offset+2] = new_bytes[2];
    data[patch_offset+3] = new_bytes[3];

    /* Step 6: Write patched binary back to disk */
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
