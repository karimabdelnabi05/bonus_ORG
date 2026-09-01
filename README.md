# Binary File HEX Password Patcher (Identifier Tag Method)

A clean demonstration of static binary file HEX patching on a compiled Windows executable using a magic identifier tag (`"PASSTAG_"`) to locate and update an embedded XOR password hash.

---

## 📌 Project Overview

1. **The Target Binary (`check.exe`)**: A compiled executable that stores an 8-byte identifier tag (`"PASSTAG_"`) immediately before a 4-byte XOR password hash in the `.data` section.
2. **The Patcher Tool (`patcher.exe`)**: A C program that opens `check.exe` on disk, calculates the XOR hash of your chosen new password, scans the binary HEX for the `"PASSTAG_"` identifier, and overwrites the adjacent 4-byte hash on disk.
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
        Binary File HEX Patcher (Identifier Tag Method)     
============================================================

Target File:  check.exe
Identifier:   "PASSTAG_" (8 bytes)
New Password: "mypass"
New Hash:     4216307715 (Hex: 0xFB4FC003)

[*] Found Identifier "PASSTAG_" at File Offset: 0x8000
[*] Target Stored Hash located at File Offset:      0x8008
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

### Step 2: Identifier Tag in Binary HEX
Inside `check.c`, the identifier tag and stored hash are defined inside a continuous memory struct:

```c
struct PasswordData {
    char tag[8];                /* "PASSTAG_" */
    unsigned long stored_hash;  /* 4-byte hash */
};
```

In the raw binary HEX of `check.exe` at file offset `0x8000`:
```text
Offset 0x8000: [50 41 53 53 54 41 47 5F] [62 83 25 11]  |PASSTAG_b.%.....|
               ▲                         ▲
               8-byte Identifier         4-byte Hash (287671138)
```

### Step 3: Direct Binary HEX Modification
`patcher.exe` scans `check.exe` on disk:
1. Locates the 8-byte byte sequence `PASSTAG_` (`50 41 53 53 54 41 47 5F`).
2. Calculates target write offset: `tag_offset + 8`.
3. Overwrites the 4 HEX bytes (`62 83 25 11` $\rightarrow$ `03 C0 4F FB`) using `fwrite()`.
4. Closes the file.

When `check.exe` is executed at any point in the future, it loads the new hash bytes directly from `.data`.

---

## 📁 Repository Structure

| File | Description |
|---|---|
| [`src/check.c`](src/check.c) | Target executable with `"PASSTAG_"` identifier and XOR hash authentication. |
| [`src/patcher.c`](src/patcher.c) | Binary HEX file patcher that searches for `"PASSTAG_"` and updates adjacent bytes. |
| [`docs/code-explanation.md`](docs/code-explanation.md) | Exhaustive line-by-line breakdown and explanation of `patcher.c`. |
| [`docs/report.md`](docs/report.md) | Full academic report detailing the identifier method, PE format, and verification logs. |
