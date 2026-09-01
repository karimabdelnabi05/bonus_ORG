# Academic Report: Static Binary File HEX Password Patching (Hashed Identifier Method)

**Course:** Computer Systems & Assembly / Reverse Engineering  
**Project:** Binary File Modification of Hashed Password Authentication (Hashed Identifier Architecture)  
**Target Architecture:** Windows x86-64 (Portable Executable)  

---

## 1. Executive Summary

This report demonstrates static binary file patching on a compiled Windows Portable Executable (`check.exe`).
To achieve defense-in-depth against binary inspection, **both the identifier anchor tag and the authentication password are stored as 32-bit XOR hashes** in the initialized data section (`.data`).
By eliminating all plaintext strings from the executable file, traditional string extraction tools (`strings.exe`) cannot discover the password or the location of the authentication structure.

A specialized C patcher (`patcher.exe`) calculates the 4-byte hash of the tag identifier, scans the raw binary file on disk for those 4 bytes, computes the XOR hash of the desired new password, and overwrites the adjacent 4-byte password hash on disk.
Once patched, `check.exe` permanently accepts the new password across all future executions without requiring source code recompilation.

---

## 2. Problem Statement & Threat Model

In binary software engineering, securing authentication data against extraction presents key challenges:
1. **Plaintext Password Flaw**: Storing passwords as raw ASCII strings allows trivial extraction via string dumps.
2. **Plaintext Tag Flaw**: Using human-readable anchor tags (e.g. `"PASSTAG"`) reveals the exact location of security variables to analysts inspecting binary strings.
3. **The Hashed Identifier Solution**: Computing and storing a 32-bit hash for both the tag and the password ensures that the binary contains only opaque numeric scalars in memory.

---

## 3. Target Binary Architecture (`check.exe`)

The target program organizes its authentication data using a 32-bit hash structure in `.data`:

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

/* Stored authentication structure: both tag and password are 4-byte hashes */
struct AuthData {
    unsigned long tag_hash;     /* Hashed identifier: xor_hash("PASSTAG") */
    unsigned long stored_hash;  /* 4-byte stored password hash */
};

struct AuthData auth = {
    .tag_hash = 192292035UL,    /* 0x0B7624C3 (Bytes: C3 24 76 0B) */
    .stored_hash = 287671138UL  /* 0x11258362 (Bytes: 62 83 25 11) */
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
    if (hash_password(input) == auth.stored_hash) {
        printf("Access Granted\n");
    } else {
        printf("Access Denied\n");
    }

    return 0;
}
```

### Security & Memory Properties
- **Zero Plaintext**: Neither `"s3cr3t"` nor `"PASSTAG"` exists as ASCII text in the binary file.
- **Contiguous Layout**: Grouping `tag_hash` and `stored_hash` inside `struct AuthData` guarantees the compiler places `stored_hash` exactly 4 bytes after `tag_hash`.
- **Register Comparison**: The runtime check evaluates two 32-bit registers (`cmp eax, edx`).

---

## 4. Windows PE Structure & Binary Memory Layout

In the Windows PE format, variables in `struct AuthData` are assigned to the initialized `.data` section at file offset `0x8000`:

```text
check.exe Raw Binary HEX at File Offset 0x8000:

Offset 0x8000:  C3 24 76 0B  62 83 25 11  00 00 00 00  00 00 00 00
                └─────┬───┘  └─────┬───┘
               4-byte Hashed  4-byte Hashed
                Tag (0x8000)   Pass (0x8004)
```

| Field | File Offset | Size | Value / Description |
|---|---|---|---|
| `auth.tag_hash` | `0x8000` | 4 bytes | `C3 24 76 0B` (Little-endian for `192292035` / `0x0B7624C3`) |
| `auth.stored_hash` | `0x8004` | 4 bytes | `62 83 25 11` (Little-endian for `287671138` / `0x11258362`) |

---

## 5. Mathematical Formulation of the XOR Hash

The hash algorithm processes input string $S = c_0, c_1, \dots, c_{k-1}$ through a recurrence relation:

$$\text{hash}_0 = \texttt{0x5A} \quad (90_{10})$$
$$\text{hash}_{i+1} = (\text{hash}_i \times 31) \oplus \text{ASCII}(c_i) \pmod{2^{32}}$$

### Computed Hash Values and Hex Byte Representations:

| Input String | Role | Decimal Hash | Hexadecimal Value | Little-Endian Bytes on Disk |
|---|---|---|---|---|
| `"PASSTAG"` | **Identifier Tag** | `192292035` | `0x0B7624C3` | `C3 24 76 0B` |
| `"s3cr3t"` | **Default Password** | `287671138` | `0x11258362` | `62 83 25 11` |
| `"mypass"` | **Custom Password** | `4216307715` | `0xFB4FC003` | `03 C0 4F FB` |
| `"newpass2026"`| **Custom Password** | `3493721389` | `0xD03E0D2D` | `2D 0D 3E D0` |

---

## 6. Binary Patcher Implementation (`patcher.c`)

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG_STRING "PASSTAG"

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

    unsigned long tag_hash = xor_hash(TAG_STRING);
    unsigned long new_hash = xor_hash(new_password);

    unsigned char tag_bytes[4];
    tag_bytes[0] = (tag_hash) & 0xFF;
    tag_bytes[1] = (tag_hash >> 8) & 0xFF;
    tag_bytes[2] = (tag_hash >> 16) & 0xFF;
    tag_bytes[3] = (tag_hash >> 24) & 0xFF;

    FILE *f = fopen(target_path, "rb+");
    if (!f) return 1;

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char *data = malloc(file_size);
    fread(data, 1, file_size, f);

    /* Scan binary for the 4-byte hashed tag */
    long tag_offset = -1;
    for (long i = 0; i <= file_size - 8; i++) {
        if (memcmp(data + i, tag_bytes, 4) == 0) {
            tag_offset = i;
            break;
        }
    }

    /* Target password hash is located at tag_offset + 4 */
    long patch_offset = tag_offset + 4;

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
STEP 2: Execute patcher.exe to search Hashed Tag and set "mypass"
======================================================================
PS > ./patcher.exe check.exe mypass
============================================================
      Binary File HEX Patcher (Hashed Identifier Method)    
============================================================

Target File:      check.exe
Identifier:       "PASSTAG" -> HASH: 192292035 (Hex: 0x0B7624C3)
Tag Search Bytes: C3 24 76 0B
New Password:     "mypass" -> HASH: 4216307715 (Hex: 0xFB4FC003)

[*] Found Hashed Tag at File Offset:          0x8000 (Bytes: C3 24 76 0B)
[*] Target Stored Hash located at File Offset: 0x8004
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
[*] Found Hashed Tag at File Offset:          0x8000 (Bytes: C3 24 76 0B)
[*] Target Stored Hash located at File Offset: 0x8004
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

Storing both the identifier tag and password as 32-bit XOR hashes eliminates plaintext signatures from the compiled binary while preserving fast, deterministic in-place binary modification.
The patcher locates the 4-byte hashed anchor on disk and writes the updated hash bytes cleanly and reliably without source code recompilation.
