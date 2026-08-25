# Binary Password Patcher (Static & Dynamic RAM Patching)

A comprehensive reverse-engineering project demonstrating how to patch a compiled Windows executable with XOR-hashed password storage using two distinct approaches:
1. **Static File Patching** (modifies the `.exe` file on disk while closed).
2. **Dynamic RAM Patching** (modifies `check.exe` in live memory while actively running).

---

## 📌 Project Overview

- **`check.exe`**: Target application that authenticates user input against a 32-bit XOR hash stored in `.data`. The plaintext password `"s3cr3t"` does not exist in the binary file or memory.
- **`patcher.exe`**: Static file patcher that opens `check.exe` using standard file I/O (`fopen`, `fseek`, `fwrite`) and updates the stored hash bytes permanently on disk.
- **`live_patcher.exe`**: Dynamic RAM patcher that attaches to the running `check.exe` process and updates the stored hash in live memory using `WriteProcessMemory`.

---

## 🚀 Quick Start (Compilation)

```powershell
gcc -o check.exe src/check.c
gcc -o patcher.exe src/patcher.c
gcc -o live_patcher.exe src/live_patcher.c
```

---

## 🧪 Option 1: Static File Patching (Disk)

Use this method to permanently change the password in the `.exe` file on disk.

```powershell
# 1. Verify original password
echo s3cr3t | ./check.exe
# Output: Access Granted

# 2. Patch check.exe to accept "mypass"
./patcher.exe check.exe mypass
# Output: Patched offset 0x8000: 287671138 -> 4216307715

# 3. Verify new password
echo mypass | ./check.exe
# Output: Access Granted

echo s3cr3t | ./check.exe
# Output: Access Denied
```

---

## ⚡ Option 2: Dynamic RAM Patching (Live Process)

Use this method to change the password in live memory while `check.exe` is actively running.

### Terminal 1 (Start the target program):
```powershell
.\check.exe
```
- Type: `s3cr3t` $\rightarrow$ `Access Granted`
- Type: `mypass` $\rightarrow$ `Access Denied`

### Terminal 2 (Run the live patcher while check.exe is still open):
```powershell
.\live_patcher.exe mypass
```
```text
=== Dynamic Runtime Memory Patcher (XOR Hash) ===

Target Process: check.exe
[1] Found running check.exe (PID 22452)
[2] Located stored_hash in RAM @ 00007FF7C9199000
[3] Overwrote RAM: 287671138 -> 4216307715
=== SUCCESS ===
```

### Return to Terminal 1:
- Type: `mypass` $\rightarrow$ **`Access Granted`** (takes effect immediately without restarting!)
- Type: `s3cr3t` $\rightarrow$ **`Access Denied`**

---

## 🔍 How the Reverse Engineering Works

### 1. Assembly Analysis of `check.exe`
Inspecting `check.exe` in assembly reveals the XOR hashing loop and the stored hash value:

```assembly
mov     eax, 5Ah             ; hash = 0x5A (initial seed)
.loop:
movzx   ecx, byte ptr [rdi]  ; c = *str
test    ecx, ecx             ; check for null terminator '\0'
jz      .done
imul    eax, eax, 31         ; hash = hash * 31
xor     eax, ecx             ; hash = hash ^ c
inc     rdi                  ; str++
jmp     .loop
```

- **Hash Formula**: $\text{hash}_{n} = (\text{hash}_{n-1} \times 31) \oplus \text{ASCII}(c)$ starting with seed `0x5A`.
- **Stored Hash Constant**: `287671138` (`0x11258362`) in the `.data` section.

### 2. Hash Calculation
For the new password `"mypass"`:
$$\text{XOR\_hash}("mypass") = 4216307715 \quad (\text{Hex: } \texttt{0xFB4FC003})$$

---

## 📁 Repository Layout

| File | Description |
|---|---|
| [`src/check.c`](src/check.c) | Target binary with XOR-hashed password verification loop. |
| [`src/patcher.c`](src/patcher.c) | Static file patcher modifying `check.exe` bytes on disk (`fopen`/`fwrite`). |
| [`src/live_patcher.c`](src/live_patcher.c) | Dynamic memory patcher modifying running process RAM (`WriteProcessMemory`). |
| [`docs/report.md`](docs/report.md) | Full academic report detailing PE structure, assembly analysis, and both patchers. |
