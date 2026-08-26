# Binary File HEX Patcher (Software Licensing & Device-ID Customizer)

A clean demonstration of static binary file HEX patching on a compiled Windows executable with XOR-hashed password/license authentication.

---

## 📌 Project Overview & Real-World Use Case

This project simulates a real-world software licensing and device-binding workflow:
1. **The Software Template (`check.exe`)**: A software vendor compiles a single generic executable template that validates a user password or client Hardware Device ID against an embedded XOR hash in the `.data` section.
2. **The Customizer Tool (`patcher.exe`)**: When a customer purchases the software and provides their specific Device ID or password, the vendor runs `patcher.exe` to inspect the binary HEX of `check.exe` on disk, calculate the XOR hash of the customer's credential, and overwrite the embedded HEX bytes directly in the file.
3. **The Customized Binary**: When the client receives and executes `check.exe`, the file on disk is permanently customized to only unlock with their specific Hardware ID or password.

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
# Output: Access Granted! Software unlocked.

echo mypass | ./check.exe
# Output: Access Denied! Invalid credentials.
```

### 3. Patch the Binary File on Disk
```powershell
./patcher.exe check.exe mypass
```
```text
============================================================
        Binary File HEX Patcher (Software Customizer)       
============================================================

Target File:  check.exe
New Password: "mypass"
New Hash:     4216307715 (Hex: 0xFB4FC003)

[*] Found stored hash in .data section at File Offset: 0x8000
    OLD HEX Bytes:  62 83 25 11  (Hash: 287671138 / 0x11258362)
    NEW HEX Bytes:  03 C0 4F FB  (Hash: 4216307715 / 0xFB4FC003)

============================================================
>>> SUCCESS: check.exe has been permanently patched on disk!
>>> Now run "check.exe" and enter "mypass" to unlock!
============================================================
```

### 4. Verify That `check.exe` is Permanently Changed
```powershell
echo mypass | ./check.exe
# Output: Access Granted! Software unlocked.

echo s3cr3t | ./check.exe
# Output: Access Denied! Invalid credentials.
```

### 5. Patch with a Hardware Device ID (Customer License)
```powershell
./patcher.exe check.exe DEVICE_HWID_9981

echo DEVICE_HWID_9981 | ./check.exe
# Output: Access Granted! Software unlocked.
```

---

## 🔍 How It Works (The 3 Steps)

### Step 1: Known Hash Algorithm & Assembly Inspection
`check.exe` calculates the hash of user input using a known, classical XOR hash:
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
`patcher.exe` computes the XOR hash for the new password or Device ID:
- For `"s3cr3t"`: $\text{Hash} = 287671138 \implies \text{Hex: } \texttt{0x11258362} \implies \text{Bytes: } \texttt{62 83 25 11}$
- For `"mypass"`: $\text{Hash} = 4216307715 \implies \text{Hex: } \texttt{0xFB4FC003} \implies \text{Bytes: } \texttt{03 C0 4F FB}$
- For `"DEVICE_HWID_9981"`: $\text{Hash} = 929471645 \implies \text{Hex: } \texttt{0x37669C9D} \implies \text{Bytes: } \texttt{9D 9C 66 37}$

### Step 3: Direct Binary HEX Modification
`patcher.exe` opens `check.exe` as a raw binary file on disk (`fopen("check.exe", "rb+")`):
1. Reads the PE section table to locate the `.data` section at file offset `0x8000`.
2. Locates the 4-byte hash scalar.
3. Overwrites the 4 HEX bytes directly in the file on disk using `fwrite()`.
4. Closes the file.

When `check.exe` is run at any point in the future, it loads the new hash bytes directly from `.data`.

---

## 📁 Repository Structure

| File | Description |
|---|---|
| [`src/check.c`](src/check.c) | Target executable template with XOR hash authentication. |
| [`src/patcher.c`](src/patcher.c) | Binary HEX file patcher that updates the embedded hash in `check.exe` on disk. |
| [`docs/code-explanation.md`](docs/code-explanation.md) | Exhaustive line-by-line breakdown and explanation of `patcher.c`. |
| [`docs/report.md`](docs/report.md) | Full academic report detailing the use case, PE format, and verification logs. |
