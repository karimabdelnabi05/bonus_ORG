# Comprehensive Line-by-Line Explanation of `patcher.c` (Identifier Tag Method)

This document provides an exhaustive, line-by-line breakdown of [`src/patcher.c`](../src/patcher.c).
It explains the purpose of every variable, system call, and algorithm used to locate the magic identifier tag (`"PASSTAG_"`) and patch the adjacent password hash in a Windows executable on disk.

---

## 📑 Table of Contents
1. [Overview and Objective](#overview-and-objective)
2. [Lines 24-30: Header Inclusions and Constants](#lines-24-30-header-inclusions-and-constants)
3. [Lines 32-39: The Known XOR Hash Algorithm](#lines-32-39-the-known-xor-hash-algorithm)
4. [Lines 41-50: Program Entry and Input Validation](#lines-41-50-program-entry-and-input-validation)
5. [Lines 52-58: Diagnostic Console Output](#lines-52-58-diagnostic-console-output)
6. [Lines 60-65: Opening the Binary File on Disk](#lines-60-65-opening-the-binary-file-on-disk)
7. [Lines 67-78: Reading the Entire File into RAM](#lines-67-78-reading-the-entire-file-into-ram)
8. [Lines 80-95: Scanning for the Magic Identifier Tag](#lines-80-95-scanning-for-the-magic-identifier-tag)
9. [Lines 97-117: Little-Endian Conversion and Diagnostic Display](#lines-97-117-little-endian-conversion-and-diagnostic-display)
10. [Lines 119-132: Overwriting File Bytes on Disk and Cleanup](#lines-119-132-overwriting-file-bytes-on-disk-and-cleanup)
11. [Key Concepts Summary](#key-concepts-summary)

---

## Overview and Objective

The goal of `patcher.c` is to locate the exact position of the password hash in `check.exe` by searching for a unique 8-byte anchor tag (`"PASSTAG_"`).
Once the tag is found, the 4 bytes immediately following the tag (`tag_offset + 8`) are replaced with the XOR hash of the new password.
This eliminates any need to hardcode file addresses or parse complex PE section headers.

---

## Lines 24-30: Header Inclusions and Constants

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The 8-byte magic identifier placed before the stored hash */
#define MAGIC_TAG "PASSTAG_"
#define TAG_LEN 8
```

- **Line 24 (`#include <stdio.h>`)**:
  Provides file operations (`fopen`, `fseek`, `ftell`, `fread`, `fwrite`, `fclose`) and console output (`printf`).
- **Line 25 (`#include <stdlib.h>`)**:
  Provides dynamic memory allocation (`malloc`, `free`).
- **Line 26 (`#include <string.h>`)**:
  Provides memory comparison functions (`memcmp`, `memcpy`).
- **Line 29 (`#define MAGIC_TAG "PASSTAG_"`)**:
  Defines the 8-byte string identifier that marks the position of the password hash in the binary.
- **Line 30 (`#define TAG_LEN 8`)**:
  Defines the length of the tag in bytes.

---

## Lines 32-39: The Known XOR Hash Algorithm

```c
/* Known XOR hash function: (hash * 31) ^ character (initial seed: 0x5A) */
static unsigned long xor_hash(const char *str) {
    unsigned long hash = 0x5A;
    int c;
    while ((c = *str++))
        hash = (hash * 31) ^ (unsigned char)c;
    return hash;
}
```

- **Line 33 (`static unsigned long xor_hash(const char *str)`)**:
  Defines the hash calculation function returning a 32-bit unsigned integer.
- **Line 34 (`unsigned long hash = 0x5A;`)**:
  Initializes the accumulator with starting seed `0x5A` (`90` in decimal).
- **Line 35 (`int c;`)**:
  Declares variable `c` to hold the ASCII value of each character during iteration.
- **Line 36 (`while ((c = *str++))`)**:
  Loops character by character through the string until reaching the null terminator `\0`.
- **Line 37 (`hash = (hash * 31) ^ (unsigned char)c;`)**:
  Applies the recurrence formula: multiplies by 31 and bitwise XORs with character `c`.
- **Line 38 (`return hash;`)**:
  Returns the computed 32-bit hash scalar.

---

## Lines 41-50: Program Entry and Input Validation

```c
int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <target.exe> <new_password>\n", argv[0]);
        printf("Example: %s check.exe mypass\n", argv[0]);
        return 1;
    }

    const char *target_path = argv[1];
    const char *new_password = argv[2];
    unsigned long new_hash = xor_hash(new_password);
```

- **Line 41 (`int main(int argc, char *argv[])`)**:
  Entry point of the program.
- **Line 42 (`if (argc != 3)`)**:
  Validates that exactly two arguments were passed (`argv[1]` = target executable, `argv[2]` = new password).
- **Lines 43-45**:
  Prints usage instructions and exits with code `1` if arguments are missing.
- **Line 47 (`target_path = argv[1];`)**:
  Stores target executable path string.
- **Line 48 (`new_password = argv[2];`)**:
  Stores new password string.
- **Line 49 (`new_hash = xor_hash(new_password);`)**:
  Computes the 32-bit hash for the new password.

---

## Lines 52-58: Diagnostic Console Output

```c
    printf("============================================================\n");
    printf("        Binary File HEX Patcher (Identifier Tag Method)     \n");
    printf("============================================================\n\n");
    printf("Target File:  %s\n", target_path);
    printf("Identifier:   \"%s\" (%d bytes)\n", MAGIC_TAG, TAG_LEN);
    printf("New Password: \"%s\"\n", new_password);
    printf("New Hash:     %lu (Hex: 0x%08lX)\n\n", new_hash, new_hash);
```

- Displays diagnostic information including target file, search tag name, new password, and computed hash.

---

## Lines 60-65: Opening the Binary File on Disk

```c
    /* Step 1: Open the binary file on disk */
    FILE *f = fopen(target_path, "rb+");
    if (!f) {
        printf("ERROR: Cannot open file \"%s\". Make sure the file exists and is closed.\n", target_path);
        return 1;
    }
```

- **Line 61 (`FILE *f = fopen(target_path, "rb+");`)**:
  Opens the file in **binary update mode (`"rb+"`)** allowing both reading and in-place writing.
- **Lines 62-65**:
  Error checking to verify the file was opened successfully.

---

## Lines 67-78: Reading the Entire File into RAM

```c
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
```

- **Line 68 (`fseek(f, 0, SEEK_END);`)**: Moves cursor to the end of the file.
- **Line 69 (`long file_size = ftell(f);`)**: Obtains total byte count of the file.
- **Line 70 (`fseek(f, 0, SEEK_SET);`)**: Rewinds cursor to byte 0.
- **Line 72 (`malloc(file_size);`)**: Allocates RAM buffer to hold file contents.
- **Line 78 (`fread(data, 1, file_size, f);`)**: Reads all binary bytes into memory for fast searching.

---

## Lines 80-95: Scanning for the Magic Identifier Tag

```c
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
```

- **Line 81 (`long tag_offset = -1;`)**: Initializes tag location to `-1` (not found).
- **Line 82 (`for (long i = 0; i <= file_size - TAG_LEN - 4; i++)`)**:
  Scans linearly through the binary buffer byte by byte.
- **Line 83 (`if (memcmp(data + i, MAGIC_TAG, TAG_LEN) == 0)`)**:
  Compares 8 bytes at current position with `"PASSTAG_"`.
  When a match is found, records the file offset in `tag_offset` and breaks the loop.
- **Lines 89-94**:
  Error checking to verify the identifier was found.

---

## Lines 97-117: Little-Endian Conversion and Diagnostic Display

```c
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
```

- **Line 98 (`long patch_offset = tag_offset + TAG_LEN;`)**:
  Calculates the target hash address: exactly 8 bytes after the start of `"PASSTAG_"`.
- **Line 99 (`old_hash = *(unsigned long *)(data + patch_offset);`)**:
  Reads the current 4-byte hash scalar.
- **Lines 104-108**:
  Converts `new_hash` into 4 **Little-Endian bytes** (`new_bytes[0..3]`).
- **Lines 110-115**:
  Prints clear diagnostic before/after byte comparison.

---

## Lines 119-132: Overwriting File Bytes on Disk and Cleanup

```c
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
```

- **Line 120 (`fseek(f, patch_offset, SEEK_SET);`)**:
  Moves the write cursor directly to the 4-byte hash location on disk (`0x8008`).
- **Line 121 (`fwrite(new_bytes, 1, 4, f);`)**:
  Overwrites the old 4 bytes with the new 4 bytes on disk.
- **Line 123 (`fclose(f);`)**:
  Saves and closes the file.
- **Line 124 (`free(data);`)**:
  Frees the temporary memory buffer.
- **Line 131 (`return 0;`)**:
  Exits cleanly with success code 0.

---

## Key Concepts Summary

| Concept | Explanation |
|---|---|
| **Magic Identifier (`PASSTAG_`)** | An 8-byte anchor tag placed right before the hash in binary memory. |
| **Offset Calculation (`tag_offset + 8`)** | Points directly to the start of the 4-byte hash variable. |
| **Little-Endian Format** | Lowest byte stored first (`0xFB4FC003` $\rightarrow$ `03 C0 4F FB`). |
| **In-Place File Patching (`rb+`)** | Modifies the exact 4 bytes on disk without rewriting or resizing the executable. |
