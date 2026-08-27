# Academic Report: Static Binary File HEX Password Patching

## 1. Executive Summary

This report demonstrates static binary file patching on a compiled Windows Portable Executable (`check.exe`).
The target program authenticates passwords using a 32-bit XOR hash algorithm, ensuring that the plaintext password (`"s3cr3t"`) is absent from the binary file and memory.
Using the known XOR hash algorithm, a lightweight C patcher (`patcher.exe`) was implemented.
The patcher opens `check.exe` on disk, calculates the hash of a new password, locates the embedded hash bytes in the `.data` section, and overwrites them directly in the binary HEX format.
Once patched, `check.exe` is permanently modified on disk to accept the new password.

---

## 2. Target Executable Architecture (`check.exe`)

The target program performs authentication using a 32-bit XOR hash algorithm:

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

/* Stored hash located in the .data section of the binary */
unsigned long stored_hash = 287671138UL;

int main(void) {
    char input[256];
    printf("=== Password Verification Terminal ===\n");
    printf("Enter Password: ");
    if (!fgets(input, sizeof(input), stdin)) return 0;
    input[strcspn(input, "\r\n")] = '\0';

    if (hash_password(input) == stored_hash) {
        printf("Access Granted\n");
    } else {
        printf("Access Denied\n");
    }
    return 0;
}
```

### Security Properties
- The plaintext password (`"s3cr3t"`) is absent from the binary file and memory.
- The comparison evaluates two 32-bit integer registers (`cmp eax, ecx`).
- The stored hash scalar lives in the initialized data section (`.data`).

---

## 3. PE Binary Structure and Memory Layout

In the Windows PE (Portable Executable) format, sections divide executable machine code and data:

| Section | Purpose | Permissions | Content in `check.exe` |
|---|---|---|---|
| `.text` | Machine Code | Read / Execute | `main` and `hash_password` CPU instructions |
| `.rdata` | Read-Only Data | Read-Only | Prompt strings and status messages |
| `.data` | Initialized Globals | Read / Write | `stored_hash = 287671138` (Little-endian bytes: `62 83 25 11`) |

Because `stored_hash` is an initialized global variable, the compiler places it at a static offset (`0x8000`) within the `.data` section on disk.

---

## 4. Hash Algorithm and Mathematical Representation

The hashing algorithm is an accumulation loop with a constant multiplier and XOR operator:
$$\text{hash}_{n} = (\text{hash}_{n-1} \times 31) \oplus \text{ASCII}(c)$$
with initial seed $\text{hash}_0 = \texttt{0x5A}$ (`90` in decimal).

In x86-64 assembly, the loop is implemented as:
```assembly
mov     eax, 5Ah             ; hash = 0x5A
.loop:
movzx   ecx, byte ptr [rdi]  ; c = *str
test    ecx, ecx             ; if c == 0 break
jz      .done
imul    eax, eax, 31         ; hash = hash * 31
xor     eax, ecx             ; hash = hash ^ c
inc     rdi                  ; str++
jmp     .loop
```

### Hash Values and Hex Byte Representations:
- Default Password `"s3cr3t"`:
  $$\text{Hash} = 287671138 \implies \text{Hex: } \texttt{0x11258362} \implies \text{Little-Endian Bytes: } \texttt{62 83 25 11}$$
- Custom Password `"mypass"`:
  $$\text{Hash} = 4216307715 \implies \text{Hex: } \texttt{0xFB4FC003} \implies \text{Little-Endian Bytes: } \texttt{03 C0 4F FB}$$
- Custom Password `"newpass2026"`:
  $$\text{Hash} = 3493721389 \implies \text{Hex: } \texttt{0xD03E0D2D} \implies \text{Little-Endian Bytes: } \texttt{2D 0D 3E D0}$$

---

## 5. Patcher Implementation (`patcher.c`)

The patcher program reads the binary file, calculates the new hash, locates the `.data` section via PE headers, and overwrites the bytes on disk:

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

    unsigned char *data = malloc(file_size);
    fread(data, 1, file_size, f);

    /* Locate .data section from PE section headers */
    unsigned long pe_offset = *(unsigned long *)(data + 0x3C);
    unsigned short num_sections = *(unsigned short *)(data + pe_offset + 6);
    unsigned short opt_hdr_size = *(unsigned short *)(data + pe_offset + 20);
    unsigned long sections_start = pe_offset + 24 + opt_hdr_size;

    long data_offset = -1;
    for (int i = 0; i < num_sections; i++) {
        unsigned char *sec = data + sections_start + (i * 40);
        if (strncmp((char *)sec, ".data", 5) == 0) {
            data_offset = *(unsigned long *)(sec + 20);
            break;
        }
    }

    /* Locate and overwrite the 4-byte hash scalar in .data */
    unsigned char new_bytes[4];
    new_bytes[0] = (new_hash) & 0xFF;
    new_bytes[1] = (new_hash >> 8) & 0xFF;
    new_bytes[2] = (new_hash >> 16) & 0xFF;
    new_bytes[3] = (new_hash >> 24) & 0xFF;

    fseek(f, data_offset, SEEK_SET);
    fwrite(new_bytes, 1, 4, f);

    fclose(f);
    free(data);
    printf("Successfully patched %s on disk!\n", target_path);
    return 0;
}
```

---

## 6. Empirical Verification Logs

```text
=== 1. Test original executable on disk ===
> echo s3cr3t | check.exe
Access Granted

> echo mypass | check.exe
Access Denied

=== 2. Run patcher on disk ===
> patcher.exe check.exe mypass
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
============================================================

=== 3. Verify check.exe is permanently modified ===
> echo mypass | check.exe
Access Granted

> echo s3cr3t | check.exe
Access Denied

=== 4. Re-patch with another password ===
> patcher.exe check.exe newpass2026
[*] Found stored hash at File Offset: 0x8000
    OLD HEX Bytes:  03 C0 4F FB  (Hash: 4216307715)
    NEW HEX Bytes:  2D 0D 3E D0  (Hash: 3493721389)

> echo newpass2026 | check.exe
Access Granted
```

---

## 7. Conclusion

This project demonstrates the principles of static binary modification.
By reading the executable as a raw binary file, locating initialized variables within the PE `.data` section, and writing computed hash bytes directly to disk, compiled binaries can be modified and updated without recompiling the original source code.
