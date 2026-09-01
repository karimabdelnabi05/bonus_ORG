# Comprehensive Line-by-Line Explanation of `patcher.c` (Hashed Identifier Method)

This document provides an exhaustive, line-by-line breakdown of [`src/patcher.c`](../src/patcher.c).
It explains the purpose of every variable, system call, and algorithm used to locate the **4-byte hashed identifier** and patch the adjacent password hash in a Windows executable on disk.

---

## 📑 Table of Contents
1. [Overview and Objective](#overview-and-objective)
2. [Lines 18-24: Header Inclusions and Constants](#lines-18-24-header-inclusions-and-constants)
3. [Lines 26-33: The Known XOR Hash Algorithm](#lines-26-33-the-known-xor-hash-algorithm)
4. [Lines 35-53: Program Entry, Hash Calculation, and Diagnostics](#lines-35-53-program-entry-hash-calculation-and-diagnostics)
5. [Lines 55-60: Opening the Binary File on Disk](#lines-55-60-opening-the-binary-file-on-disk)
6. [Lines 62-73: Reading the Entire File into RAM](#lines-62-73-reading-the-entire-file-into-ram)
7. [Lines 75-90: Scanning for the 4-Byte Hashed Identifier](#lines-75-90-scanning-for-the-4-byte-hashed-identifier)
8. [Lines 92-111: Target Offset Calculation and Byte Comparison](#lines-92-111-target-offset-calculation-and-byte-comparison)
9. [Lines 113-125: Overwriting File Bytes on Disk and Cleanup](#lines-113-125-overwriting-file-bytes-on-disk-and-cleanup)
10. [Key Concepts Summary](#key-concepts-summary)

---

## Overview and Objective

The goal of `patcher.c` is to modify `check.exe` on disk without leaving any plaintext traces.
Both the tag string (`"PASSTAG"`) and the password (`"s3cr3t"`) are stored inside the binary as 32-bit XOR hashes.
The patcher computes the 4-byte hash of the tag, locates those 4 bytes in the binary file, and replaces the 4 bytes immediately following it with the hash of the new password.

---

## Lines 18-24: Header Inclusions and Constants

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The agreed-upon identifier tag string */
#define TAG_STRING "PASSTAG"
```

- **Line 18 (`#include <stdio.h>`)**:
  Provides standard file I/O operations (`fopen`, `fseek`, `ftell`, `fread`, `fwrite`, `fclose`) and console output (`printf`).
- **Line 19 (`#include <stdlib.h>`)**:
  Provides dynamic memory management (`malloc`, `free`).
- **Line 20 (`#include <string.h>`)**:
  Provides memory comparison functions (`memcmp`, `memcpy`).
- **Line 23 (`#define TAG_STRING "PASSTAG"`)**:
  Defines the agreed-upon tag identifier string whose hash will be searched in the binary.

---

## Lines 26-33: The Known XOR Hash Algorithm

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

- **Line 27 (`static unsigned long xor_hash(const char *str)`)**:
  Defines the hash calculation function returning a 32-bit unsigned long integer.
- **Line 28 (`unsigned long hash = 0x5A;`)**:
  Initializes the accumulator with starting seed `0x5A` (`90` in decimal).
- **Line 29 (`int c;`)**:
  Variable `c` holds the ASCII integer value of each character during iteration.
- **Line 30 (`while ((c = *str++))`)**:
  Iterates character by character through the string until reaching the null terminator `\0`.
- **Line 31 (`hash = (hash * 31) ^ (unsigned char)c;`)**:
  Applies the formula: multiplies by 31 and bitwise XORs with character `c`.
- **Line 32 (`return hash;`)**:
  Returns the computed 32-bit hash scalar.

---

## Lines 35-53: Program Entry, Hash Calculation, and Diagnostics

```c
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
```

- **Line 35**: Program entry point.
- **Line 36 (`if (argc != 3)`)**: Verifies that both arguments (`target.exe` and `new_password`) were supplied.
- **Line 44 (`unsigned long tag_hash = xor_hash(TAG_STRING);`)**:
  Computes the 32-bit hash for `"PASSTAG"` $\rightarrow$ `192292035` (`0x0B7624C3`).
- **Line 45 (`unsigned long new_hash = xor_hash(new_password);`)**:
  Computes the 32-bit hash for the desired new password (e.g. `"mypass"` $\rightarrow$ `4216307715`).
- **Lines 48-52**:
  Converts `tag_hash` into 4 **Little-Endian search bytes** (`[C3 24 76 0B]`).

---

## Lines 55-60: Opening the Binary File on Disk

```c
    /* Step 1: Open the binary file on disk */
    FILE *f = fopen(target_path, "rb+");
    if (!f) {
        printf("ERROR: Cannot open file \"%s\". Make sure the file exists and is closed.\n", target_path);
        return 1;
    }
```

- **Line 56 (`fopen(target_path, "rb+")`)**:
  Opens `check.exe` in binary read/write update mode (`"rb+"`).

---

## Lines 62-73: Reading the Entire File into RAM

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

- Loads the entire executable from disk into a contiguous RAM buffer `data` for fast scanning.

---

## Lines 75-90: Scanning for the 4-Byte Hashed Identifier

```c
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
```

- **Lines 77-82**:
  Scans linearly through the binary buffer checking if 4 consecutive bytes match `[C3 24 76 0B]`.
  When a match is found, `tag_offset` stores the file offset (e.g. `0x8000`).

---

## Lines 92-111: Target Offset Calculation and Byte Comparison

```c
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
```

- **Line 93 (`long patch_offset = tag_offset + 4;`)**:
  Because the tag hash is 4 bytes, the password hash starts at `tag_offset + 4` (`0x8004`).
- **Lines 100-103**:
  Converts `new_hash` into 4 **Little-Endian bytes** (`new_bytes[0..3]`).

---

## Lines 113-125: Overwriting File Bytes on Disk and Cleanup

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

- **Line 114 (`fseek(f, patch_offset, SEEK_SET);`)**:
  Positions the disk write cursor directly at byte `0x8004`.
- **Line 115 (`fwrite(new_bytes, 1, 4, f);`)**:
  Overwrites the old 4 bytes with the new password hash bytes.
- **Line 117 (`fclose(f);`)**:
  Commits changes and safely closes the file.

---

## Key Concepts Summary

| Concept | Explanation |
|---|---|
| **Hashed Tag (`0x0B7624C3`)** | The tag is stored as a 4-byte hash scalar (`C3 24 76 0B`), leaving zero plaintext in the binary. |
| **Offset Calculation (`tag_offset + 4`)** | The stored password hash is located immediately adjacent to the 4-byte tag hash. |
| **Little-Endian Format** | Smallest byte stored first in memory (`0xFB4FC003` $\rightarrow$ `03 C0 4F FB`). |
| **Zero Plaintext Security** | Plaintext strings for passwords and tags are completely absent from `.exe` file and RAM. |
