# Binary Password Patcher (XOR Hash Authentication)

A clean demonstration of reverse-engineering a compiled binary with simple XOR-based hashed password storage and patching the executable on disk to accept a new password.

---

## 📌 Project Overview

1. **`check.exe`**: A program that validates a user password using a simple XOR hash function. The plaintext password (`"s3cr3t"`) does not exist in the binary file or memory.
2. **`patcher.exe`**: A C program that opens `check.exe` as a binary file on disk, locates the stored XOR hash in the `.data` section, and replaces it with the XOR hash of your chosen new password.

---

## 🚀 Quick Start (Build & Run)

### 1. Compile Both Programs
```powershell
gcc -o check.exe src/check.c
gcc -o patcher.exe src/patcher.c
```

### 2. Verify Original Password
```powershell
echo s3cr3t | ./check.exe
# Output: Access Granted

echo mypass | ./check.exe
# Output: Access Denied
```

### 3. Patch the Binary
```powershell
./patcher.exe check.exe mypass
# Output: Found old hash at file offset: 0x8000 -> Replaced with new hash: 4216307715
```

### 4. Verify Patched Password
```powershell
echo mypass | ./check.exe
# Output: Access Granted

echo s3cr3t | ./check.exe
# Output: Access Denied
```

---

## 🔍 How It Works (The 3 Steps)

### Step 1: Assembly Inspection
When inspecting `check.exe` in assembly, the password validation routine reveals two key details:
- **Hash Algorithm**: The loop calculates `hash = (hash * 31) ^ c` with an initial seed of `0x5A`.
- **Stored Hash**: The constant integer **`287671138`** (`0x11258362`) is loaded from the `.data` section.

```assembly
mov     eax, 5Ah             ; hash = 0x5A
.loop:
movzx   ecx, byte ptr [rdi]  ; c = *str
test    ecx, ecx             ; check for '\0'
jz      .done
imul    eax, eax, 31         ; hash = hash * 31
xor     eax, ecx             ; hash = hash ^ c
inc     rdi                  ; str++
jmp     .loop
```

### Step 2: Hash Calculation
`patcher.exe` uses the identified XOR formula to calculate the hash for the new password:
$$\text{XOR\_hash}("mypass") = 4216307715 \quad (\text{Hex: } \texttt{0xFB4FC003})$$

### Step 3: Binary Patching
`patcher.exe` opens `check.exe` directly on disk (`fopen("check.exe", "rb+")`):
- Locates the 4-byte sequence `62 83 25 11` (stored hash `287671138` in little-endian).
- Overwrites it with `03 C0 4F FB` (new hash `4216307715` in little-endian).

```
check.exe file on disk (Offset 0x8000):

BEFORE PATCH: [62 83 25 11]  -->  287671138   -->  XOR_hash("s3cr3t")
AFTER PATCH:  [03 C0 4F FB]  -->  4216307715  -->  XOR_hash("mypass")
```

---

## 📁 Repository Structure

| File | Description |
|---|---|
| [`src/check.c`](src/check.c) | Password verification program storing a 32-bit XOR hash in `.data`. |
| [`src/patcher.c`](src/patcher.c) | Binary file patcher that replaces the stored hash bytes on disk. |
| [`docs/report.md`](docs/report.md) | Full academic report with PE section breakdown and test verification. |
