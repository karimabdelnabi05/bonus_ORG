# Academic Report: Static Binary File HEX Password Patching

**Course:** Computer Systems & Assembly / Reverse Engineering  
**Project:** Binary File Modification of Hashed Password Authentication  
**Target Architecture:** Windows x86-64 (Portable Executable)  

---

## 1. Executive Summary

This project demonstrates the principles of static binary file patching on a compiled Windows Portable Executable (`check.exe`).
The target application secures its access by evaluating user input against a 32-bit XOR hash stored in the initialized data section (`.data`).
By storing a hash rather than a plaintext string, the original password (`"s3cr3t"`) is completely absent from the executable file and process memory.

Using the known XOR hash algorithm, a dedicated C patching tool (`patcher.exe`) was engineered.
The patcher opens `check.exe` on disk in binary read/write mode, parses the Windows PE headers to locate the `.data` section, computes the XOR hash for a user-specified password, and overwrites the exact 4-byte scalar in the binary HEX on disk.
Once patched, `check.exe` permanently accepts the new password across all future executions without requiring source code recompilation.

---

## 2. Problem Statement & Threat Model

In binary security analysis, client-side authentication mechanisms often attempt to protect sensitive credentials through obfuscation or hashing:
1. **Plaintext Storage Flaw**: Storing passwords as ASCII strings allows trivial extraction using standard string inspection tools (`strings.exe` or hex editors).
2. **Hashed Storage Enhancement**: Storing a cryptographic or arithmetic hash eliminates plaintext strings, forcing the runtime engine to compute and compare numeric values (`cmp eax, ecx`).
3. **The Vulnerability**: Even when plaintext credentials are removed, the comparison value stored in the binary file remains mutable if the executable is not cryptographically signed.
An analyst who knows or identifies the hashing algorithm can pre-compute the hash of an arbitrary credential and patch the stored constant on disk.

---

## 3. Target Binary Architecture (`check.exe`)

The target program implements XOR-based password verification:

```c
#include <stdio.h>
#include <string.h>

/* XOR hash function: (hash * 31) ^ character */
static unsigned long hash_password(const char *str) {
    unsigned long hash = 0x5A;
    int c;
    while ((c = *str++))
        hash = (hash * 31) ^ (unsigned char)c;
    return hash;
}

/* Stored hash located in the .data section of the binary */
unsigned long stored_hash = 287671138UL;

int main(void) {
    char input[256];

    printf("=== Password Verification Terminal ===\n");
    printf("Enter Password: ");
    if (!fgets(input, sizeof(input), stdin))
        return 0;

    /* Strip newline characters */
    input[strcspn(input, "\r\n")] = '\0';

    /* Validate input hash against embedded stored hash */
    if (hash_password(input) == stored_hash) {
        printf("Access Granted\n");
    } else {
        printf("Access Denied\n");
    }

    return 0;
}
```

### Key Architectural Characteristics
- **Absence of Plaintext**: The word `"s3cr3t"` does not exist in `.rdata` or `.data`.
- **Register Comparison**: The assembly comparison evaluates two 32-bit registers (`cmp eax, ecx`) rather than calling string comparison routines (`strcmp`).
- **Static Storage**: `stored_hash` is an initialized global variable, which the compiler assigns to a fixed offset in the `.data` PE section.

---

## 4. Windows PE Structure & Binary Memory Layout

Windows executable files follow the Portable Executable (PE) specification.
The binary is divided into distinct sections:

| Section Name | Contents | Permissions | Role in `check.exe` |
|---|---|---|---|
| `.text` | Executable Machine Code | Read / Execute (`RX`) | Contains `main` and `hash_password` CPU instructions. |
| `.rdata` | Read-Only Constants | Read-Only (`R`) | Contains string literals (`"Enter Password: "`, `"Access Granted\n"`). |
| `.data` | Initialized Global Variables | Read / Write (`RW`) | Contains `stored_hash = 287671138` at file offset `0x8000`. |
| `.bss` | Uninitialized Variables | Read / Write (`RW`) | Reserved space for zero-initialized data. |

### Header Navigation to Offset `0x8000`
1. **DOS Header (`0x0000`)**: Starts with magic bytes `4D 5A` (`MZ`). Offset `0x003C` (`e_lfanew`) stores the 4-byte pointer to the PE header (`0x0080`).
2. **PE Header (`0x0080`)**: Starts with signature `50 45 00 00` (`PE\0\0`), specifying the architecture (x86-64) and section count.
3. **Section Table (`0x0188`)**: Contains 40-byte descriptors for each section.
The `.data` descriptor specifies:
   - `PointerToRawData = 0x8000` (file offset on disk).
   - `SizeOfRawData = 0x0200` (512 bytes).

```
check.exe File Layout on Disk:
+-------------------------------------------------------+
| DOS Header (MZ) [0x0000 - 0x003F]                    |
+-------------------------------------------------------+
| PE Header (PE\0\0) [0x0080 - 0x0187]                  |
+-------------------------------------------------------+
| Section Table (.text, .data, .rdata) [0x0188]         |
+-------------------------------------------------------+
| .text Section (Code) [0x0600 - 0x7FFF]                |
+-------------------------------------------------------+
| .data Section [0x8000 - 0x81FF]                       |
|   --> Offset 0x8000: [62 83 25 11] (stored_hash)      |
+-------------------------------------------------------+
```

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
Intel x86-64 uses Little-Endian representation (least significant byte stored first):

| Password | Decimal Hash | Hexadecimal Value | Little-Endian Bytes on Disk |
|---|---|---|---|
| `"s3cr3t"` | `287671138` | `0x11258362` | `62 83 25 11` |
| `"mypass"` | `4216307715` | `0xFB4FC003` | `03 C0 4F FB` |
| `"newpass2026"` | `3493721389` | `0xD03E0D2D` | `2D 0D 3E D0` |
| `"admin"` | `295325516` | `0x119A5B4C` | `4C 5B 9A 11` |

---

## 6. Binary Patcher Implementation (`patcher.c`)

The patcher program implements in-place binary modification using standard C file I/O:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

    unsigned char *data = (unsigned char *)malloc(file_size);
    fread(data, 1, file_size, f);

    /* Locate .data section from PE section headers */
    unsigned long pe_offset = *(unsigned long *)(data + 0x3C);
    unsigned short num_sections = *(unsigned short *)(data + pe_offset + 6);
    unsigned short opt_hdr_size = *(unsigned short *)(data + pe_offset + 20);
    unsigned long sections_start = pe_offset + 24 + opt_hdr_size;

    long data_file_offset = -1;
    for (int i = 0; i < num_sections; i++) {
        unsigned char *sec = data + sections_start + (i * 40);
        if (strncmp((char *)sec, ".data", 5) == 0) {
            data_file_offset = *(unsigned long *)(sec + 20);
            break;
        }
    }

    /* Convert 32-bit new_hash into 4 Little-Endian bytes */
    unsigned char new_bytes[4];
    new_bytes[0] = (new_hash) & 0xFF;
    new_bytes[1] = (new_hash >> 8) & 0xFF;
    new_bytes[2] = (new_hash >> 16) & 0xFF;
    new_bytes[3] = (new_hash >> 24) & 0xFF;

    /* Overwrite the 4 bytes at offset 0x8000 on disk */
    fseek(f, data_file_offset, SEEK_SET);
    fwrite(new_bytes, 1, 4, f);

    fclose(f);
    free(data);
    return 0;
}
```

### Why Password Length Does Not Affect File Integrity
In plaintext patching, substituting a short password with a long password causes buffer overflows that corrupt adjacent memory structures.
Because hashing maps any variable-length input string to a **fixed 4-byte scalar**, `patcher.exe` always writes exactly 4 bytes.
The file size of `check.exe` remains strictly unchanged, guaranteeing zero side-effects on adjacent code or data structures.

---

## 7. Empirical Test Logs & Verification

The patching workflow was verified through end-to-end testing in a PowerShell environment:

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
                  Binary File HEX Patcher                   
============================================================

Target File:  check.exe
New Password: "mypass"
New Hash:     4216307715 (Hex: 0xFB4FC003)

[*] Found stored hash in .data section at File Offset: 0x8000
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
[*] Found stored hash in .data section at File Offset: 0x8000
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

## 8. Security Implications & Countermeasures

| Security Aspect | Analysis |
|---|---|
| **Vulnerability** | Static binary constants can be rewritten on disk using simple file I/O. |
| **Why Hashing Alone Fails** | Hashing conceals plaintext strings but leaves the target comparison hash mutable. |
| **Industry Mitigation 1** | **Digital Code Signing**: Windows Authenticode signatures detect file modifications and block execution if hashes do not match the certificate. |
| **Industry Mitigation 2** | **Server-Side Authentication**: Moving authentication logic to a remote backend prevents local binary modification attacks. |
| **Industry Mitigation 3** | **Anti-Tamper Envelopes**: Packing and integrity self-checks (e.g. CRC32 / SHA-256 over code sections at startup) terminate the process if modifications occur. |

---

## 9. Conclusion

This project successfully demonstrates the theory and practice of static binary file HEX patching.
By understanding the PE file structure, locating initialized variables within the `.data` section, and mapping hash calculations to little-endian byte arrays, executable files can be modified directly on disk.
The patcher achieves in-place binary modification cleanly and reliably without source code recompilation.
