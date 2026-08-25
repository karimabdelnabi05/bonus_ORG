# Binary Password Patcher (Reverse Engineering Bonus)

A clean demonstration of reverse-engineering a compiled binary with hashed password storage and patching the executable on disk to accept a new password.

---

## 📌 Project Overview

1. **`check.exe`**: A program that validates a user password against a stored **hash** (the plaintext password `"s3cr3t"` does not exist in the binary).
2. **`patcher.exe`**: A C program that opens `check.exe` as a binary file, locates the stored hash value in the `.data` section, and replaces it with the hash of your chosen new password.

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
# Output: Patched check.exe at offset 0x8000 (old hash: 401824839 -> new hash: 250477730)
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
- **Hash Algorithm**: The loop calculates `hash = (hash * 33) + c` starting at `5381` (the standard **djb2** hash algorithm).
- **Stored Hash**: The constant integer **`401824839`** (`0x17F35C47`) is loaded from the `.data` section.

```assembly
mov   eax, 1505h             ; hash = 5381
.loop:
movzx ecx, byte ptr [rdi]    ; c = *str
test  ecx, ecx
jz    .done
shl   eax, 5                 ; hash << 5 (hash * 32)
add   eax, eax_prev          ; hash * 32 + hash = hash * 33
add   eax, ecx               ; hash * 33 + c
inc   rdi
jmp   .loop
```

### Step 2: Hash Calculation
`patcher.exe` uses the identified `djb2` formula to calculate the hash for the new password:
$$\text{djb2}("mypass") = 250477730 \quad (\text{Hex: } \texttt{0x0EEDFCA2})$$

### Step 3: Binary Patching
`patcher.exe` opens `check.exe` directly on disk (`fopen("check.exe", "rb+")`):
- Locates the 4-byte sequence `47 5C F3 17` (stored hash `401824839` in little-endian).
- Overwrites it with `A2 FC ED 0E` (new hash `250477730` in little-endian).

```
check.exe file on disk (Offset 0x8000):

BEFORE PATCH: [47 5C F3 17]  -->  401824839  -->  hash("s3cr3t")
AFTER PATCH:  [A2 FC ED 0E]  -->  250477730  -->  hash("mypass")
```

---

## 📁 Repository Structure

| File | Description |
|---|---|
| [`src/check.c`](src/check.c) | Password verification program storing a 32-bit djb2 hash in `.data`. |
| [`src/patcher.c`](src/patcher.c) | Binary file patcher that replaces the stored hash bytes on disk. |
| [`docs/report.md`](docs/report.md) | Full academic report with PE section breakdown and test verification. |
