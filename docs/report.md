# Academic Report: Static & Dynamic Binary Patching of an XOR Hash Authentication Executable

## 1. Executive Summary

This report demonstrates both static (file-level) and dynamic (runtime RAM) binary patching of a compiled Windows PE executable (`check.exe`).
The target program authenticates passwords using a 32-bit XOR hash algorithm, ensuring that the plaintext password (`"s3cr3t"`) is absent from the binary file and process memory.
By disassembling the binary, the hashing formula (`(hash * 31) ^ c`) and the stored hash value (`287671138`) were identified.
Two distinct patchers were implemented:
1. `patcher.exe`: Performs static file patching on disk via standard file I/O.
2. `live_patcher.exe`: Performs dynamic process memory patching using Windows kernel APIs while the process is actively executing.

---

## 2. Target Application Architecture (`check.exe`)

The target program performs password authentication using an XOR accumulation hash:

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

volatile unsigned long stored_hash = 287671138UL;

int main(void) {
    char input[256];
    printf("=== Password Verification Terminal ===\n");
    while (1) {
        printf("Enter password: ");
        if (!fgets(input, sizeof(input), stdin)) break;
        input[strcspn(input, "\r\n")] = '\0';

        if (hash_password(input) == stored_hash)
            printf("Access Granted\n\n");
        else
            printf("Access Denied\n\n");
    }
    return 0;
}
```

### Security Properties
- The plaintext string `"s3cr3t"` does not appear anywhere in the compiled executable.
- Running string analysis tools (`strings.exe`) will not reveal the valid credential.
- The comparison evaluates two 32-bit integer registers (`cmp eax, ecx`).

---

## 3. PE Binary Structure and Memory Layout

In the Windows PE format, variables and code reside in specific sections:

| Section | Purpose | Permissions | Content in `check.exe` |
|---|---|---|---|
| `.text` | Executable Code | Read / Execute | `main` and `hash_password` instructions |
| `.rdata` | Read-Only Data | Read-Only | Prompt strings and banners |
| `.data` | Read-Write Globals | Read / Write | `stored_hash = 287671138` (Bytes: `62 83 25 11`) |

Because `stored_hash` is declared as an initialized global variable, the compiler places it in the `.data` section at file offset `0x8000`.

---

## 4. Reverse Engineering Analysis

Disassembling `check.exe` reveals the XOR hashing loop:

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

The mathematical formula extracted from the assembly is:
$$\text{hash}_{n} = (\text{hash}_{n-1} \times 31) \oplus \text{ASCII}(c)$$
with seed $\text{hash}_0 = \texttt{0x5A}$.

The comparison target loaded from `.data` is:
$$\text{stored\_hash} = 287671138 \quad (\text{Hex: } \texttt{0x11258362})$$

---

## 5. Method 1: Static File Patching (`patcher.c`)

The static patcher modifies `check.exe` on disk while closed using standard C file I/O:

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

## 6. Method 2: Dynamic RAM Patching (`live_patcher.c`)

The dynamic patcher modifies `check.exe` in live memory while actively running:

```c
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

/* Locates check.exe PID, scans RAM for old_hash, and overwrites with WriteProcessMemory */
int main(int argc, char *argv[]) {
    const char *new_pass = argv[1];
    unsigned long old_hash = 287671138UL;
    unsigned long new_hash = xor_hash(new_pass);

    DWORD pid = find_pid("check.exe");
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);

    MEMORY_BASIC_INFORMATION mbi;
    unsigned char *addr = NULL;

    while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY))) {
            unsigned char buf[4096];
            SIZE_T br;
            for (SIZE_T i = 0; i < mbi.RegionSize; i += sizeof(buf)) {
                if (ReadProcessMemory(hProcess, (unsigned char *)mbi.BaseAddress + i, buf, sizeof(buf), &br)) {
                    for (SIZE_T j = 0; j <= br - 4; j += 4) {
                        if (*(unsigned long *)(buf + j) == old_hash) {
                            void *target = (unsigned char *)mbi.BaseAddress + i + j;
                            WriteProcessMemory(hProcess, target, &new_hash, 4, NULL);
                            printf("Live-patched check.exe in RAM @ %p\n", target);
                            CloseHandle(hProcess);
                            return 0;
                        }
                    }
                }
            }
        }
        addr = (unsigned char *)mbi.BaseAddress + mbi.RegionSize;
    }
    CloseHandle(hProcess);
    return 1;
}
```

---

## 7. Comparative Analysis

| Feature | Static File Patching (`patcher.exe`) | Dynamic RAM Patching (`live_patcher.exe`) |
|---|---|---|
| **Target Medium** | `.exe` binary file on disk | Virtual Address Space in RAM |
| **Execution State** | Process must be **closed** | Process must be **running** |
| **Persistence** | Permanent (persists across restarts) | Volatile (resets when process exits) |
| **API Mechanism** | Standard C File I/O (`fopen`, `fwrite`) | Win32 Process APIs (`WriteProcessMemory`) |

---

## 8. Empirical Test Logs

```text
=== STATIC PATCH TEST ===
> echo s3cr3t | check.exe
Access Granted
> patcher.exe check.exe mypass
Patched offset 0x8000: 287671138 -> 4216307715
> echo mypass | check.exe
Access Granted

=== DYNAMIC RAM PATCH TEST ===
[Terminal 1] check.exe running (PID 22452)
Input: mypass -> Access Denied
[Terminal 2] live_patcher.exe mypass
Located stored_hash in RAM @ 00007FF7C9199000
Overwrote RAM: 287671138 -> 4216307715
[Terminal 1]
Input: mypass -> Access Granted (Immediate without restart!)
```

---

## 9. Conclusion

This project demonstrates comprehensive reverse engineering and patching capabilities across both persistent file storage and volatile process memory.
Whether modifying disk bytes or live virtual memory pages, isolating the hashing algorithm and hash variable in the `.data` section allows complete authentication bypass with arbitrary credentials.
