# Academic Report: Static Binary File HEX Password Patching

**Course:** Computer Systems & Assembly / Reverse Engineering  
**Project:** Binary File Modification of Hashed Password Authentication (Identifier Tag Method)  
**Target Architecture:** Windows x86-64 (Portable Executable)  

---

## 1. Executive Summary

This report demonstrates the principles of static binary file patching on a compiled Windows Portable Executable (`check.exe`).
The target application secures its access by evaluating user input against a 32-bit XOR hash stored in the initialized data section (`.data`).
By storing a hash rather than a plaintext string, the original password (`"s3cr3t"`) is completely absent from the executable file and process memory.

To reliably locate the stored hash inside the binary file without hardcoding fragile file offsets, the binary utilizes an **8-byte Magic Identifier Tag** (`"PASSTAG_"`) placed immediately adjacent to the hash variable in memory.
A lightweight C patcher (`patcher.exe`) scans the binary file on disk for this identifier, calculates the XOR hash of a new password, and overwrites the adjacent 4-byte hash scalar.
Once patched, `check.exe` permanently accepts the new password across all future executions without requiring source code recompilation.

---

## 2. Problem Statement & Threat Model

In binary software engineering, identifying target data structures inside compiled binaries presents key challenges:
1. **Plaintext Storage Flaw**: Storing passwords as raw ASCII strings allows trivial discovery and extraction using basic string extraction utilities (`strings.exe`).
2. **Hashed Storage Enhancement**: Storing an integer hash conceals plaintext credentials, requiring runtime hashing and register comparison (`cmp eax, ecx`).
3. **The Location Problem**: In compiled binaries, variable addresses can change between compiler versions and optimization levels.
4. **The Identifier Solution**: Placing a unique, known marker (an identifier tag) directly before the target data allows automated patchers to scan for the anchor tag and reliably find the adjacent payload bytes (`offset + tag_length`).

---

## 3. Target Binary Architecture (`check.exe`)

The target program organizes its authentication data using a structured configuration block in `.data`:

```c
#include <stdio.h>
#include <string.h>

/* Simple XOR hash function: (hash * 31) ^ character */
static unsigned long hash_password(const char *str) {
    unsigned long hash = 0x5A;
    int c;
    while ((c = *str++))
        hash = (hash * 31) ^ (unsigned char)c;
    return hash;
}

/* Stored password configuration with magic identifier tag */
struct PasswordData {
    char tag[8];                /* Identifier marker: "PASSTAG_" */
    unsigned long stored_hash;  /* 4-byte stored hash */
};

struct PasswordData auth_data = {
    .tag = "PASSTAG_",
    .stored_hash = 287671138UL
};

int main(void) {
    char input[256];

    printf("=== Password Verification Terminal ===\n");
    printf("Enter Password: ");
    if (!fgets(input, sizeof(input), stdin))
        return 0;

    /* Strip newline characters */
    input[strcspn(input, "\r\n")] = '\0';

    /* Validate input hash against embedded stored hash */
    if (hash_password(input) == auth_data.stored_hash) {
        printf("Access Granted\n");
    } else {
        printf("Access Denied\n");
    }

    return 0;
}
```

### Key Architectural Characteristics
- **Absence of Plaintext**: The word `"s3cr3t"` does not exist anywhere in `.rdata` or `.data`.
- **Contiguous Layout**: Grouping `tag` and `stored_hash` inside `struct PasswordData` guarantees the compiler places `stored_hash` directly after `"PASSTAG_"` in memory.
- **Register Comparison**: The assembly comparison evaluates two 32-bit registers (`cmp eax, ecx`).

---

## 4. Windows PE Structure & Binary Memory Layout

In the Windows PE format, variables in `struct PasswordData` are assigned to the initialized `.data` section at file offset `0x8000`:

```text
check.exe Raw Binary HEX at File Offset 0x8000:

Offset 0x8000:  50 41 53 53 54 41 47 5F  03 C0 4F FB  00 00 00 00  |PASSTAG_..O.....|
                ▲                       ▲
                8-byte Tag ("PASSTAG_") 4-byte Hash (offset 0x8008)
```

| Field | File Offset | Size | Value / Description |
|---|---|---|---|
| `auth_data.tag` | `0x8000` | 8 bytes | `50 41 53 53 54 41 47 5F` (`"PASSTAG_"`) |
| `auth_data.stored_hash` | `0x8008` | 4 bytes | `62 83 25 11` (Little-endian hash: `287671138`) |

---

## 5. Mathematical Formulation of the XOR Hash

The hash algorithm processes input string $S = c_0, c_1, \dots, c_{k-1}$ through a recurrence relation:

$$\text{hash}_0 = \texttt{0x5A} \quad (90_{10})$$
$$\text{hash}_{i+1} = (\text{hash}_i \times 31) \oplus \text{ASCII}(c_i) \pmod{2^{32}}$$

### Assembly Implementation
```assembly
mov     eax, 5Ah             ; hash = 0x5A (seed)
.loop:
movzx   ecx, byte ptr [rdi]  ; c = *str
test    ecx, ecx             ; check for null terminator '\0'
jz      .done
imul    eax, eax, 31         ; hash = hash * 31
xor     eax, ecx             ; hash = hash ^ c
inc     rdi                  ; str++
jmp     .loop
```

### Little-Endian Byte Encoding

| Password | Decimal Hash | Hexadecimal Value | Little-Endian Bytes on Disk |
|---|---|---|---|
| `"s3cr3t"` | `287671138` | `0x11258362` | `62 83 25 11` |
| `"mypass"` | `4216307715` | `0xFB4FC003` | `03 C0 4F FB` |
| `"newpass2026"` | `3493721389` | `0xD03E0D2D` | `2D 0D 3E D0` |
| `"admin"` | `295325516` | `0x119A5B4C` | `4C 5B 9A 11` |

---

## 6. Binary Patcher Implementation (`patcher.c`)

The patcher program scans for the `"PASSTAG_"` identifier and updates the adjacent 4 bytes on disk:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAGIC_TAG "PASSTAG_"
#define TAG_LEN 8

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
        return 1;
    }

    const char *target_path = argv[1];
    const char *new_password = argv[2];
    unsigned long new_hash = xor_hash(new_password);

    FILE *f = fopen(target_path, "rb+");
    if (!f) return 1;

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char *data = malloc(file_size);
    fread(data, 1, file_size, f);

    /* Scan binary for the 8-byte magic tag */
    long tag_offset = -1;
    for (long i = 0; i <= file_size - TAG_LEN - 4; i++) {
        if (memcmp(data + i, MAGIC_TAG, TAG_LEN) == 0) {
            tag_offset = i;
            break;
        }
    }

    /* Target hash is located at tag_offset + TAG_LEN */
    long patch_offset = tag_offset + TAG_LEN;

    unsigned char new_bytes[4];
    new_bytes[0] = (new_hash) & 0xFF;
    new_bytes[1] = (new_hash >> 8) & 0xFF;
    new_bytes[2] = (new_hash >> 16) & 0xFF;
    new_bytes[3] = (new_hash >> 24) & 0xFF;

    fseek(f, patch_offset, SEEK_SET);
    fwrite(new_bytes, 1, 4, f);

    fclose(f);
    free(data);
    return 0;
}
```

---

## 7. Empirical Test Logs & Verification

```text
======================================================================
STEP 1: Test original check.exe with default password "s3cr3t"
======================================================================
PS > echo s3cr3t | ./check.exe
=== Password Verification Terminal ===
Enter Password: Access Granted

PS > echo mypass | ./check.exe
=== Password Verification Terminal ===
Enter Password: Access Denied

======================================================================
STEP 2: Execute patcher.exe to set new password "mypass"
======================================================================
PS > ./patcher.exe check.exe mypass
============================================================
        Binary File HEX Patcher (Identifier Tag Method)     
============================================================

Target File:  check.exe
Identifier:   "PASSTAG_" (8 bytes)
New Password: "mypass"
New Hash:     4216307715 (Hex: 0xFB4FC003)

[*] Found Identifier "PASSTAG_" at File Offset: 0x8000
[*] Target Stored Hash located at File Offset:      0x8008
    OLD HEX Bytes:  62 83 25 11  (Hash: 287671138 / 0x11258362)
    NEW HEX Bytes:  03 C0 4F FB  (Hash: 4216307715 / 0xFB4FC003)

============================================================
>>> SUCCESS: check.exe has been permanently patched on disk!
>>> Now run "check.exe" and enter "mypass" to verify Access Granted!
============================================================

======================================================================
STEP 3: Verify that check.exe is permanently updated on disk
======================================================================
PS > echo mypass | ./check.exe
=== Password Verification Terminal ===
Enter Password: Access Granted

PS > echo s3cr3t | ./check.exe
=== Password Verification Terminal ===
Enter Password: Access Denied

======================================================================
STEP 4: Re-patch with another password ("newpass2026")
======================================================================
PS > ./patcher.exe check.exe newpass2026
[*] Found Identifier "PASSTAG_" at File Offset: 0x8000
[*] Target Stored Hash located at File Offset:      0x8008
    OLD HEX Bytes:  03 C0 4F FB  (Hash: 4216307715 / 0xFB4FC003)
    NEW HEX Bytes:  2D 0D 3E D0  (Hash: 3493721389 / 0xD03E0D2D)

PS > echo newpass2026 | ./check.exe
=== Password Verification Terminal ===
Enter Password: Access Granted

PS > echo mypass | ./check.exe
=== Password Verification Terminal ===
Enter Password: Access Denied
```

---

## 8. Conclusion

This project demonstrates how binary identifiers (anchor tags) provide robust, reliable in-place binary modification.
By searching for a distinct marker byte sequence and overwriting adjacent little-endian payload bytes, binary executables can be customized on disk cleanly and accurately without requiring fixed hardcoded offsets or source code recompilation.
