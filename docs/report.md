# Academic Report: Binary Patching of a Hash-Based Authentication Executable

## 1. Executive Summary

This project demonstrates static reverse engineering and binary file patching on a compiled Windows PE executable (`check.exe`).
The target program uses hashed password storage, ensuring the plaintext password (`"s3cr3t"`) is absent from the binary file and memory.
By analyzing the binary assembly, the hashing algorithm (`djb2`) and the stored hash value (`401824839`) were identified.
A lightweight C patcher (`patcher.exe`) was developed to modify the executable on disk directly, allowing arbitrary passwords to be set.

---

## 2. Target Application Architecture (`check.exe`)

The target program performs password authentication using integer hash comparisons rather than string matching.

```c
#include <stdio.h>
#include <string.h>

static unsigned long hash_password(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

unsigned long stored_hash = 401824839UL;

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

### Security Properties of the Target
- The plaintext string `"s3cr3t"` does not exist anywhere in the compiled executable.
- Running standard string extraction tools (`strings.exe`) will not reveal the valid password.
- The comparison in assembly evaluates two 32-bit registers (`cmp eax, ecx`) rather than calling string comparison functions like `strcmp`.

---

## 3. PE Binary Structure and Memory Layout

In the Portable Executable (PE) format on Windows, variables are organized into specific sections:

| Section | Purpose | Permissions | Content in `check.exe` |
|---|---|---|---|
| `.text` | Machine Code | Read / Execute | `main` function and `hash_password` CPU instructions |
| `.rdata` | Read-Only Data | Read-Only | Format strings (`"Enter password: "`, `"Access Granted\n"`) |
| `.data` | Initialized Globals | Read / Write | `stored_hash = 401824839` (Little-endian bytes: `47 5C F3 17`) |

Because `stored_hash` is declared as an initialized global variable, the compiler places it inside the `.data` section at a fixed offset (`0x8000`).

---

## 4. Reverse Engineering Analysis

Inspecting the disassembly of `check.exe` reveals the exact hashing algorithm:

```assembly
mov     eax, 1505h           ; hash = 5381 (0x1505)
.loop:
movzx   ecx, byte ptr [rdi]  ; c = *str
test    ecx, ecx             ; check for null terminator '\0'
jz      .done
shl     eax, 5               ; hash << 5 (hash * 32)
add     eax, edx             ; (hash * 32) + hash = hash * 33
add     eax, ecx             ; (hash * 33) + c
inc     rdi                  ; str++
jmp     .loop
```

The mathematical formulation extracted from the assembly is:
$$\text{hash}_{n} = (\text{hash}_{n-1} \times 33) + \text{ASCII}(c)$$
with seed $\text{hash}_0 = 5381$.

This is the standard **djb2** hash algorithm.
The comparison target is loaded from memory as:
$$\text{stored\_hash} = 401824839 \quad (\text{Hex: } \texttt{0x17F35C47})$$

---

## 5. Patcher Implementation (`patcher.c`)

The patcher program implements file-level binary modification using standard C file I/O:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
        return 1;
    }

    const char *target = argv[1];
    const char *new_pass = argv[2];
    unsigned long old_hash = 401824839UL;
    unsigned long new_hash = djb2(new_pass);

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

=== PATCHING: Replace 401824839 with djb2("mypass") ===
> patcher.exe check.exe mypass
=== Binary File Patcher ===
Target File:  check.exe
Old Hash:     401824839 (0x17F35C47)
New Password: "mypass"
New Hash:     250477730 (0x0EEDFCA2)
Found old hash at file offset: 0x8000
Replaced with new hash:        250477730

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
By identifying the hash algorithm through disassembly and updating the stored 4-byte scalar in the `.data` section, access can be granted to any desired password without recovering the original plaintext secret.
