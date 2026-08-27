# Binary File HEX Password Patcher

A clean demonstration of static binary file HEX patching on a compiled Windows executable with XOR-hashed password authentication.

---

## 📌 Project Overview

1. **The Target Binary (`check.exe`)**: A compiled executable that validates a user password against an embedded XOR hash in the `.data` section. The plaintext password `"s3cr3t"` does not exist in the binary file or in memory.
2. **The Patcher Tool (`patcher.exe`)**: A C program that opens `check.exe` on disk, calculates the XOR hash of your chosen new password, and overwrites the embedded 4-byte hash in the binary HEX directly on disk.
3. **The Patched Binary**: When `check.exe` is executed again, it is permanently modified on disk to accept the new password.

---

## 🚀 Quick Start (Build & Run)

### 1. Compile Both Binaries
```powershell
gcc -o check.exe src/check.c
gcc -o patcher.exe src/patcher.c
```

### 2. Test Original Executable
```powershell
echo s3cr3t | ./check.exe
# Output: Access Granted

echo mypass | ./check.exe
# Output: Access Denied
```

### 3. Patch the Binary File on Disk
```powershell
./patcher.exe check.exe mypass
```
```text
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
```

### 4. Verify That `check.exe` is Permanently Changed
```powershell
echo mypass | ./check.exe
# Output: Access Granted

echo s3cr3t | ./check.exe
# Output: Access Denied
```

---

## 🔍 How It Works (The 3 Steps)

### Step 1: Known Hash Algorithm
`check.exe` calculates the hash of user input using a known XOR hash formula:
$$\text{hash}_{n} = (\text{hash}_{n-1} \times 31) \oplus \text{ASCII}(c) \quad \text{with seed } \text{hash}_0 = \texttt{0x5A}$$

In the assembly of `check.exe`, this corresponds to:
```assembly
mov     eax, 5Ah             ; hash = 0x5A
.loop:
movzx   ecx, byte ptr [rdi]  ; c = *str
test    ecx, ecx             ; check for null terminator '\0'
jz      .done
imul    eax, eax, 31         ; hash = hash * 31
xor     eax, ecx             ; hash = hash ^ c
inc     rdi                  ; str++
jmp     .loop
```

### Step 2: Hash Calculation
`patcher.exe` computes the XOR hash for the new password:
- For `"s3cr3t"`: $\text{Hash} = 287671138 \implies \text{Hex: } \texttt{0x11258362} \implies \text{Bytes: } \texttt{62 83 25 11}$
- For `"mypass"`: $\text{Hash} = 4216307715 \implies \text{Hex: } \texttt{0xFB4FC003} \implies \text{Bytes: } \texttt{03 C0 4F FB}$
- For `"newpass2026"`: $\text{Hash} = 3493721389 \implies \text{Hex: } \texttt{0xD03E0D2D} \implies \text{Bytes: } \texttt{2D 0D 3E D0}$

### Step 3: Direct Binary HEX Modification
`patcher.exe` opens `check.exe` directly on disk (`fopen("check.exe", "rb+")`):
1. Reads the PE section table to locate the `.data` section at file offset `0x8000`.
2. Locates the 4-byte hash scalar.
3. Overwrites the 4 HEX bytes directly in the file on disk using `fwrite()`.
4. Closes the file.

When `check.exe` is executed at any point in the future, it loads the new hash bytes directly from `.data`.

---

## 📁 Repository Structure

| File | Description |
|---|---|
| [`src/check.c`](src/check.c) | Target executable with XOR hash authentication. |
| [`src/patcher.c`](src/patcher.c) | Binary HEX file patcher that updates the embedded hash in `check.exe` on disk. |
| [`docs/code-explanation.md`](docs/code-explanation.md) | Exhaustive line-by-line breakdown and explanation of `patcher.c`. |
| [`docs/report.md`](docs/report.md) | Full academic report detailing the architecture, PE format, and verification logs. |
