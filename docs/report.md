# Academic Report: Binary Patching of an XOR Hash-Based Authentication Executable

## 1. Executive Summary

This project demonstrates static reverse engineering and binary file patching on a compiled Windows PE executable (`check.exe`).
The target program uses a simple XOR-based hash function for password authentication.
This ensures the plaintext password (`"s3cr3t"`) is completely absent from the compiled binary and memory.
By inspecting the disassembly of the binary, the hashing algorithm (`(hash * 31) ^ c`) and the stored hash value (`287671138`) were identified.
A lightweight C patcher (`patcher.exe`) was written to modify the executable file on disk directly, allowing any chosen password to gain access.

---

## 2. Target Application Architecture (`check.exe`)

The target program performs password authentication using a simple, classical XOR hash function:

```c
#include <stdio.h>
#include <string.h>

static unsigned long hash_password(const char *str) {
    unsigned long hash = 0x5A;
    int c;
    while ((c = *str++))
        hash = (hash * 31) ^ (unsigned char)c;
    return hash;
}

unsigned long stored_hash = 287671138UL;

int main(void) {
    char input[256];
    printf("Enter password: ");
    if (!fgets(input, sizeof(input), stdin)) return 0;
    input[strcspn(input, "\r\n")] = '\0';

    if (hash_password(input) == stored_hash)
        printf("Access Granted\n");
    else
        printf("Access Denied\n");

    return 0;
}
```

### Security Properties
- The plaintext string `"s3cr3t"` does not exist anywhere in the compiled executable.
- Running standard string extraction tools (`strings.exe`) will not reveal the valid password.
- The comparison in assembly evaluates two 32-bit registers (`cmp eax, ecx`) rather than invoking string comparison functions.

---

## 3. PE Binary Structure and Memory Layout

In the Portable Executable (PE) format on Windows, variables are organized into distinct sections:

| Section | Purpose | Permissions | Content in `check.exe` |
|---|---|---|---|
| `.text` | Machine Code | Read / Execute | `main` and `hash_password` CPU instructions |
| `.rdata` | Read-Only Data | Read-Only | Format strings (`"Enter password: "`, `"Access Granted\n"`) |
| `.data` | Initialized Globals | Read / Write | `stored_hash = 287671138` (Little-endian bytes: `62 83 25 11`) |

Because `stored_hash` is declared as an initialized global variable, the compiler places it inside the `.data` section at file offset `0x8000`.

---

## 4. Reverse Engineering Analysis

Disassembling `check.exe` reveals the exact XOR hashing loop:

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

The mathematical formulation extracted from the assembly is:
$$\text{hash}_{n} = (\text{hash}_{n-1} \times 31) \oplus \text{ASCII}(c)$$
with seed $\text{hash}_0 = \texttt{0x5A}$.

The comparison target loaded from `.data` is:
$$\text{stored\_hash} = 287671138 \quad (\text{Hex: } \texttt{0x11258362})$$

---

## 5. Patcher Implementation (`patcher.c`)

The patcher program implements file-level binary modification using standard C file I/O:

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

    const char *target = argv[1];
    const char *new_pass = argv[2];
    unsigned long old_hash = 287671138UL;
    unsigned long new_hash = xor_hash(new_pass);

    FILE *f = fopen(target, "rb+");
    if (!f) return 1;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char *data = malloc(size);
    fread(data, 1, size, f);

    for (long i = 0; i <= size - 4; i++) {
        if (*(unsigned long *)(data + i) == old_hash) {
            fseek(f, i, SEEK_SET);
            fwrite(&new_hash, sizeof(unsigned long), 1, f);
            printf("Patched %s at offset 0x%lX\n", target, i);
            break;
        }
    }

    fclose(f);
    free(data);
    return 0;
}
```

---

## 6. Empirical Test Results

```text
=== TEST 1: Original password before patch ===
> echo s3cr3t | check.exe
Enter password: Access Granted

=== TEST 2: New password before patch ===
> echo mypass | check.exe
Enter password: Access Denied

=== PATCHING: Replace 287671138 with xor_hash("mypass") ===
> patcher.exe check.exe mypass
=== Binary File Patcher (XOR Hash) ===
Target File:  check.exe
Old Hash:     287671138 (0x11258362)
New Password: "mypass"
New Hash:     4216307715 (0xFB4FC003)
Found old hash at file offset: 0x8000
Replaced with new hash:        4216307715 (0xFB4FC003)

=== TEST 3: New password after patch ===
> echo mypass | check.exe
Enter password: Access Granted

=== TEST 4: Old password after patch ===
> echo s3cr3t | check.exe
Enter password: Access Denied
```

---

## 7. Conclusion

This project proves that static hash storage inside client binaries is vulnerable to file-level binary patching.
By identifying the XOR hash algorithm through disassembly and updating the stored 4-byte scalar in the `.data` section, access can be granted to any desired password without recovering the original plaintext secret.
