# Comprehensive Line-by-Line Explanation of `patcher.c`

This document provides an exhaustive, line-by-line breakdown of [`src/patcher.c`](../src/patcher.c).
It explains the purpose of every variable, system call, and algorithm used to patch a Windows executable on disk.

---

## 📑 Table of Contents
1. [Overview and Objective](#overview-and-objective)
2. [Lines 24-26: Header Inclusions](#lines-24-26-header-inclusions)
3. [Lines 28-35: The Known XOR Hash Algorithm](#lines-28-35-the-known-xor-hash-algorithm)
4. [Lines 37-46: Program Entry and Input Validation](#lines-37-46-program-entry-and-input-validation)
5. [Lines 48-53: Diagnostic Console Output](#lines-48-53-diagnostic-console-output)
6. [Lines 55-60: Opening the Binary File on Disk](#lines-55-60-opening-the-binary-file-on-disk)
7. [Lines 62-73: Reading the Entire File into RAM](#lines-62-73-reading-the-entire-file-into-ram)
8. [Lines 75-108: Parsing the Windows PE Header](#lines-75-108-parsing-the-windows-pe-header)
9. [Lines 110-128: Locating the Stored Hash Inside `.data`](#lines-110-128-locating-the-stored-hash-inside-data)
10. [Lines 130-144: Little-Endian Conversion and HEX Output](#lines-130-144-little-endian-conversion-and-hex-output)
11. [Lines 146-159: Overwriting File Bytes and Finalizing](#lines-146-159-overwriting-file-bytes-and-finalizing)
12. [Key Concepts Summary](#key-concepts-summary)

---

## Overview and Objective

The goal of `patcher.c` is to modify a compiled executable (`check.exe`) directly on disk so that it accepts a new password or Hardware Device ID.
It does this without needing the original source code, without recompiling, and without running `check.exe` in the background.

---

## Lines 24-26: Header Inclusions

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
```

- **Line 24 (`#include <stdio.h>`)**:
  Includes the Standard Input/Output library.
  Provides file operations (`fopen`, `fseek`, `ftell`, `fread`, `fwrite`, `fclose`) and console printing (`printf`).
- **Line 25 (`#include <stdlib.h>`)**:
  Includes the Standard General Utilities library.
  Provides dynamic memory management (`malloc`, `free`).
- **Line 26 (`#include <string.h>`)**:
  Includes string and memory manipulation functions (`strcmp`, `memcpy`).

---

## Lines 28-35: The Known XOR Hash Algorithm

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

- **Line 29 (`static unsigned long xor_hash(const char *str)`)**:
  Defines the hash calculation function.
  It takes a pointer to a string (`str`) and returns a 32-bit unsigned long integer.
- **Line 30 (`unsigned long hash = 0x5A;`)**:
  Initializes the accumulator with the starting seed value `0x5A` (`90` in decimal).
- **Line 31 (`int c;`)**:
  Declares variable `c` to hold the ASCII integer value of each character during iteration.
- **Line 32 (`while ((c = *str++))`)**:
  Iterates through the string character by character.
  In each step, `*str++` reads the current character into `c` and advances the pointer.
  When it hits the null terminator `\0` (ASCII 0), the loop terminates.
- **Line 33 (`hash = (hash * 31) ^ (unsigned char)c;`)**:
  Applies the mathematical hash formula: multiplies current hash by 31 and bitwise XORs with character `c`.
- **Line 34 (`return hash;`)**:
  Returns the final 32-bit hash value.

---

## Lines 37-46: Program Entry and Input Validation

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

- **Line 37 (`int main(int argc, char *argv[])`)**:
  Standard entry point of the program.
  `argc` is argument count, `argv` is the array of argument strings.
- **Line 38 (`if (argc != 3)`)**:
  Checks if the user provided the correct number of command-line arguments.
  `argc` must be 3 (`argv[0]` = program name, `argv[1]` = target executable, `argv[2]` = new password).
- **Lines 39-41**:
  Prints usage instructions and exits with return code `1` if arguments are missing.
- **Line 44 (`const char *target_path = argv[1];`)**:
  Stores the path to the target executable (e.g. `"check.exe"`).
- **Line 45 (`const char *new_password = argv[2];`)**:
  Stores the desired new password string (e.g. `"mypass"`).
- **Line 46 (`unsigned long new_hash = xor_hash(new_password);`)**:
  Computes the 32-bit XOR hash of the new password immediately.

---

## Lines 48-53: Diagnostic Console Output

```c
    printf("============================================================\n");
    printf("        Binary File HEX Patcher (Software Customizer)       \n");
    printf("============================================================\n\n");
    printf("Target File:  %s\n", target_path);
    printf("New Password: \"%s\"\n", new_password);
    printf("New Hash:     %lu (Hex: 0x%08lX)\n\n", new_hash, new_hash);
```

- **Lines 48-50**: Prints a title banner to the console.
- **Lines 51-53**: Displays the target file name, new password, and computed hash in decimal and hexadecimal format (`%lu` and `0x%08lX`).

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

- **Line 56 (`FILE *f = fopen(target_path, "rb+");`)**:
  Opens `check.exe` in **binary read/write update mode (`"rb+"`)**.
  - `r`: Read from the existing file.
  - `b`: Binary mode (prevents Windows newline `\r\n` translation).
  - `+`: Allows writing back changes to the exact same file without recreating it.
- **Line 57 (`if (!f)`)**:
  Error checking to verify the file was successfully opened.
- **Lines 58-59**:
  Prints an error message and terminates if the file does not exist or is locked.

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

- **Line 63 (`fseek(f, 0, SEEK_END);`)**:
  Moves the file read cursor to the very last byte of the file.
- **Line 64 (`long file_size = ftell(f);`)**:
  Queries the cursor position, giving the exact file size in bytes (e.g. `271,188` bytes).
- **Line 65 (`fseek(f, 0, SEEK_SET);`)**:
  Rewinds the file cursor back to the beginning (`offset 0`).
- **Line 67 (`unsigned char *data = (unsigned char *)malloc(file_size);`)**:
  Allocates a temporary heap buffer of size `file_size` to hold the raw binary bytes.
- **Lines 68-72**:
  Checks if `malloc` succeeded; closes file and exits if out of memory.
- **Line 73 (`fread(data, 1, file_size, f);`)**:
  Reads all bytes of `check.exe` from disk into the `data` memory buffer for inspection.

---

## Lines 75-108: Parsing the Windows PE Header

```c
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
```

- **Lines 76-81**:
  Validates the DOS Header magic bytes `MZ` (`0x4D 0x5A`) at bytes 0 and 1.
- **Line 83 (`pe_offset = *(unsigned long *)(data + 0x3C);`)**:
  In Windows PE files, offset `0x3C` (`e_lfanew`) stores the 4-byte pointer to the PE signature (`PE\0\0`).
- **Line 84 (`num_sections = *(unsigned short *)(data + pe_offset + 6);`)**:
  Reads the number of sections (e.g. `.text`, `.data`, `.rdata`) from the COFF header.
- **Line 85 (`opt_hdr_size = *(unsigned short *)(data + pe_offset + 20);`)**:
  Reads the size of the Optional Header.
- **Line 86 (`sections_start = pe_offset + 24 + opt_hdr_size;`)**:
  Calculates the exact byte offset where the Section Header Table begins.
- **Lines 91-101 (`for (int i = 0; i < num_sections; i++)`)**:
  Iterates through each 40-byte section header entry:
  - `sec = data + sections_start + (i * 40)`: Points to the current 40-byte section entry.
  - `memcpy(name, sec, 8)`: Copies the 8-byte section name string.
  - `if (strcmp(name, ".data") == 0)`: When the `.data` section is found:
    - `data_size`: Read from offset `+16` (`SizeOfRawData`).
    - `data_file_offset`: Read from offset `+20` (`PointerToRawData` — file offset `0x8000`).
- **Lines 103-108**:
  Validates that `.data` was found; exits if missing.

---

## Lines 110-128: Locating the Stored Hash Inside `.data`

```c
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
```

- **Lines 111-112**:
  Initializes `patch_offset = -1` and `old_hash = 0`.
- **Line 114 (`for (long off = 0; off + 4 <= data_size; off += 4)`)**:
  Scans 4 bytes (32-bit dwords) at a time through the `.data` section.
- **Line 115 (`val = *(unsigned long *)(data + data_file_offset + off);`)**:
  Reads the 4-byte integer at the current offset.
- **Line 116 (`if (val != 0)`)**:
  Finds the initialized variable (`stored_hash`).
- **Line 117 (`patch_offset = data_file_offset + off;`)**:
  Calculates the absolute file offset on disk (e.g. `0x8000`).
- **Line 118 (`old_hash = val;`)**:
  Stores the current hash value found in the binary (e.g. `287671138`).
- **Lines 123-128**:
  Error checking to verify a non-zero hash was located.

---

## Lines 130-144: Little-Endian Conversion and HEX Output

```c
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
```

- **Line 132 (`memcpy(old_bytes, data + patch_offset, 4);`)**:
  Copies the 4 old bytes from the binary buffer.
- **Lines 135-138**:
  Converts the 32-bit `new_hash` integer into 4 **little-endian bytes**:
  - `new_bytes[0] = (new_hash) & 0xFF`: Least Significant Byte (bits 0-7).
  - `new_bytes[1] = (new_hash >> 8) & 0xFF`: Bits 8-15.
  - `new_bytes[2] = (new_hash >> 16) & 0xFF`: Bits 16-23.
  - `new_bytes[3] = (new_hash >> 24) & 0xFF`: Most Significant Byte (bits 24-31).
- **Lines 140-144**:
  Prints a clear side-by-side comparison of the old HEX bytes vs new HEX bytes.

---

## Lines 146-159: Overwriting File Bytes and Finalizing

```c
    /* Step 6: Overwrite the HEX bytes on disk */
    fseek(f, patch_offset, SEEK_SET);
    fwrite(new_bytes, 1, 4, f);

    fclose(f);
    free(data);

    printf("============================================================\n");
    printf(">>> SUCCESS: %s has been permanently patched on disk!\n", target_path);
    printf(">>> Now run \"%s\" and enter \"%s\" to unlock!\n", target_path, new_password);
    printf("============================================================\n");

    return 0;
}
```

- **Line 147 (`fseek(f, patch_offset, SEEK_SET);`)**:
  Moves the file write cursor directly to offset `0x8000` in the open file handle `f`.
- **Line 148 (`fwrite(new_bytes, 1, 4, f);`)**:
  Writes the 4 new little-endian HEX bytes directly into the `check.exe` file on disk.
- **Line 150 (`fclose(f);`)**:
  Flushes all buffers and safely closes the file. The changes are now permanently saved.
- **Line 151 (`free(data);`)**:
  Frees the temporary memory buffer.
- **Lines 153-157**:
  Prints a success message confirming the file has been modified.
- **Line 158 (`return 0;`)**:
  Exits the program with standard success code `0`.

---

## Key Concepts Summary

| Concept | Explanation |
|---|---|
| **PE Header (`0x3C`)** | The Windows header structure pointing to section tables. |
| **`.data` Section (`0x8000`)** | Where initialized global variables (`stored_hash`) reside. |
| **Little-Endian Format** | Intel x86-64 stores lowest byte first (e.g. `0xFB4FC003` becomes `03 C0 4F FB`). |
| **Direct File I/O (`rb+`)** | Allows targeted in-place byte editing without rewriting the entire file. |
| **Zero Side-Effects** | The file size is unchanged; no other code or data is disturbed. |
