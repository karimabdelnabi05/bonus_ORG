# Presentation & Defense Guide: Binary HEX Password Patching (Hashed Identifier Method)

This guide is designed for explaining the project to your doctor/professor during your project demonstration or oral defense.
It covers how both the identifier tag and password are stored as 32-bit XOR hashes, eliminating all plaintext strings from the binary.

---

## 📑 Table of Contents
1. [The 60-Second Spoken Script for the Doctor](#the-60-second-spoken-script-for-the-doctor)
2. [How the Hashed Identifier Method Works in Binary](#how-the-hashed-identifier-method-works-in-binary)
3. [Step-by-Step Execution Walkthrough](#step-by-step-execution-walkthrough)
4. [Frequently Asked Questions by Professors & Best Answers](#frequently-asked-questions-by-professors--best-answers)

---

## The 60-Second Spoken Script for the Doctor

You can read or speak this exact script when presenting:

> *"Doctor, our project demonstrates static binary file patching on a compiled Windows executable (`check.exe`) without recompiling the source code.*
> 
> *To maximize binary security, **both the identifier tag and the password are stored as 32-bit XOR hashes** in memory.*
> *This ensures that zero plaintext strings—neither the password nor the tag—exist anywhere in the executable file.*
> 
> *Our patcher tool (`patcher.exe`) uses the known XOR formula `(hash * 31) ^ character` to compute:*
> * 1. The 4-byte hash of the tag identifier (`PASSTAG` $\rightarrow$ `192292035` / Bytes: `C3 24 76 0B`).
> * 2. The 4-byte hash of the desired new password (`mypass` $\rightarrow$ `4216307715` / Bytes: `03 C0 4F FB`).
> 
> *The patcher opens `check.exe` on disk, scans the raw binary HEX for the 4-byte tag hash `C3 24 76 0B`, and overwrites the adjacent 4 bytes at `offset + 4` on disk.*
> 
> *When `check.exe` is opened again, it reads the updated hash from disk and permanently unlocks with the new password!"*

---

## How the Hashed Identifier Method Works in Binary

```text
[ Binary File check.exe on Disk ]

File Offset 0x8000:  [ C3 24 76 0B ]  [ 62 83 25 11 ]
                     └──────┬──────┘  └──────┬──────┘
                        4-byte Hashed     4-byte Hashed
                        Tag Identifier       Password
                         (192292035)        (287671138)
```

### In the C Source Code (`check.c`):
```c
struct AuthData {
    unsigned long tag_hash;     /* Hashed tag: 192292035 */
    unsigned long stored_hash;  /* Hashed pass: 287671138 */
};

struct AuthData auth = {
    .tag_hash = 192292035UL,    /* 0x0B7624C3 -> [ C3 24 76 0B ] */
    .stored_hash = 287671138UL  /* 0x11258362 -> [ 62 83 25 11 ] */
};
```
Grouping both 4-byte scalars inside `struct AuthData` guarantees contiguous placement in memory and on disk.

---

## Step-by-Step Execution Walkthrough

```text
[ 1. Compute Hashes ]
Tag "PASSTAG"      --> Hash: 192292035  --> Search Bytes: [ C3 24 76 0B ]
Password "mypass"  --> Hash: 4216307715 --> Replace Bytes: [ 03 C0 4F FB ]

[ 2. Scan Binary on Disk ]
Patcher searches raw bytes for: [ C3 24 76 0B ]
--> Found match at File Offset 0x8000

[ 3. Target Offset Calculation ]
Target Hash Offset = 0x8000 + 4 = 0x8004

[ 4. Overwrite on Disk ]
fseek(f, 0x8004, SEEK_SET);
fwrite(new_bytes, 1, 4, f);

[ 5. Permanent Update ]
BEFORE:  Offset 0x8004: [ 62 83 25 11 ]  --> 287671138  --> hash of "s3cr3t"
AFTER:   Offset 0x8004: [ 03 C0 4F FB ]  --> 4216307715 --> hash of "mypass"
```

---

## Frequently Asked Questions by Professors & Best Answers

### Q1: *"Why is the tag also hashed instead of storing a plaintext string?"*
> **Answer:** *"If the tag were stored as a plaintext ASCII string (like `'PASSTAG'`), anyone using basic string extraction utilities (`strings.exe`) could spot the tag and identify the authentication structure immediately. Storing the tag as a 32-bit hash integer eliminates all readable strings from the binary, leaving only raw numeric values in memory."*

### Q2: *"Does the length of the new password matter?"*
> **Answer:** *"No, password length does not matter. Because we use an XOR hash function, any input string—whether 1 character or 100 characters—is always compressed into the exact same fixed size: 4 bytes (32-bit integer). The file size of `check.exe` never changes, and no adjacent memory is corrupted."*

### Q3: *"What is Little-Endian format and why do the bytes look reversed?"*
> **Answer:** *"Intel x86-64 processors use Little-Endian byte ordering, which places the least significant byte first in memory. For example, the tag hash `192292035` (`0x0B7624C3`) is stored on disk as `C3 24 76 0B`."*

### Q4: *"How does `check.exe` verify the password when a user runs it?"*
> **Answer:** *"When `check.exe` runs, it computes the XOR hash of the user's input string dynamically at runtime and compares the resulting 32-bit register with the 4 bytes currently stored in `auth.stored_hash` (`cmp eax, edx`). If they match, access is granted."*
