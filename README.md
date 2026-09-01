# Binary File HEX Password Patcher (Hashed Identifier Method)

A demonstration of static binary file HEX patching on a compiled Windows executable where **both the identifier tag and the password are stored as 32-bit XOR hashes**.
This guarantees that **zero plaintext strings** exist in the binary file.

---

## 📌 Project Overview

1. **The Target Binary (`check.exe`)**: A compiled executable that stores a 4-byte **Hashed Identifier Tag** (`xor_hash("PASSTAG")` = `192292035` / Bytes: `C3 24 76 0B`) immediately before the 4-byte XOR password hash in the `.data` section.
2. **The Patcher Tool (`patcher.exe`)**: A C program that opens `check.exe` on disk, calculates the XOR hash of the tag identifier (`C3 24 76 0B`), scans the binary HEX for those 4 bytes, computes the XOR hash of your new password, and overwrites the adjacent 4-byte hash on disk.
3. **The Patched Binary**: When `check.exe` is executed again, it reads the updated hash from disk and permanently unlocks with the new password.

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
      Binary File HEX Patcher (Hashed Identifier Method)    
============================================================

Target File:      check.exe
Identifier:       "PASSTAG" -> HASH: 192292035 (Hex: 0x0B7624C3)
Tag Search Bytes: C3 24 76 0B
New Password:     "mypass" -> HASH: 4216307715 (Hex: 0xFB4FC003)

[*] Found Hashed Tag at File Offset:          0x8000 (Bytes: C3 24 76 0B)
[*] Target Stored Hash located at File Offset: 0x8004
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

### Step 1: Known XOR Hash Formula
Both the tag and the password use the exact same XOR hash algorithm:
$$\text{hash}_{n} = (\text{hash}_{n-1} \times 31) \oplus \text{ASCII}(c) \quad \text{with initial seed } \text{hash}_0 = \texttt{0x5A}$$

- **Tag `"PASSTAG"`** $\rightarrow$ `192292035` (`0x0B7624C3` $\rightarrow$ Little-Endian bytes: `C3 24 76 0B`)
- **Password `"s3cr3t"`** $\rightarrow$ `287671138` (`0x11258362` $\rightarrow$ Little-Endian bytes: `62 83 25 11`)
- **New Password `"mypass"`** $\rightarrow$ `4216307715` (`0xFB4FC003` $\rightarrow$ Little-Endian bytes: `03 C0 4F FB`)

### Step 2: Binary Layout on Disk (No Plaintext)
Inside `check.c`, both values are grouped in a struct:

```c
struct AuthData {
    unsigned long tag_hash;     /* 4-byte hash: 192292035 */
    unsigned long stored_hash;  /* 4-byte hash: 287671138 */
};
```

In the raw binary HEX of `check.exe` at file offset `0x8000`:
```text
Offset 0x8000:  [ C3 24 76 0B ]  [ 62 83 25 11 ]
                └──────┬──────┘  └──────┬──────┘
                   4-byte Hashed     4-byte Hashed
                   Tag Identifier       Password
```

### Step 3: Binary Modification
`patcher.exe` scans `check.exe` on disk:
1. Calculates `xor_hash("PASSTAG")` to produce search bytes `C3 24 76 0B`.
2. Scans the binary file until it matches `C3 24 76 0B` at offset `0x8000`.
3. Calculates target write offset: `tag_offset + 4` (`0x8004`).
4. Overwrites the 4 bytes on disk (`62 83 25 11` $\rightarrow$ `03 C0 4F FB`) using `fwrite()`.
5. Closes the file.

---

## 📁 Repository Structure

| File | Description |
|---|---|
| [`src/check.c`](src/check.c) | Target executable with hashed tag (`C3 24 76 0B`) and XOR password authentication. |
| [`src/patcher.c`](src/patcher.c) | Binary HEX file patcher that searches for the hashed tag and updates adjacent bytes. |
| [`docs/presentation-guide.md`](docs/presentation-guide.md) | Oral presentation guide, spoken script, and Q&A for the doctor/professor. |
| [`docs/code-explanation.md`](docs/code-explanation.md) | Exhaustive line-by-line breakdown and explanation of `patcher.c`. |
| [`docs/report.md`](docs/report.md) | Full academic report detailing the hashed identifier architecture and verification logs. |
