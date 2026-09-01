# Presentation & Defense Guide: Binary HEX Password Patching (Identifier Method)

This guide is designed for explaining the project to your doctor/professor during your project demonstration or oral defense.
It covers the exact mechanics of how the patcher scans for the identifier tag (`"PASSTAG_"`), replaces the adjacent password hash, and answers common follow-up questions.

---

## 📑 Table of Contents
1. [The 60-Second Spoken Script for the Doctor](#the-60-second-spoken-script-for-the-doctor)
2. [How the Identifier Tag Method Works in Binary](#how-the-identifier-tag-method-works-in-binary)
3. [Step-by-Step Execution Walkthrough](#step-by-step-execution-walkthrough)
4. [Frequently Asked Questions by Professors & Best Answers](#frequently-asked-questions-by-professors--best-answers)

---

## The 60-Second Spoken Script for the Doctor

You can read or speak this exact script when presenting:

> *"Doctor, our project demonstrates static binary file patching on a compiled Windows executable (`check.exe`) without recompiling the source code.*
> 
> *Instead of storing a plaintext password, the application stores a 32-bit XOR hash in memory.*
> 
> *To locate where this hash lives in the binary file on disk, we use the **Identifier Marker Method**.*
> *We place an 8-byte magic tag (`PASSTAG_`) in memory immediately before the hash variable.*
> 
> *Our patcher tool (`patcher.exe`) opens `check.exe` directly on disk in binary read/write mode and scans the raw HEX bytes for the 8-byte identifier sequence `50 41 53 53 54 41 47 5F`.*
> 
> *Once the tag is found, the patcher knows that the 4 bytes immediately following it (`offset + 8`) contain the stored hash.*
> *It computes the known XOR hash for the new password using `(hash * 31) ^ character` and overwrites those exact 4 bytes on disk.*
> 
> *When `check.exe` is opened again, it reads the updated hash from disk and permanently unlocks with the new password!"*

---

## How the Identifier Tag Method Works in Binary

The identifier acts as an unambiguous anchor inside the compiled binary on disk:

```text
[ Binary File check.exe on Disk ]

File Offset 0x8000:  [ 50 41 53 53 54 41 47 5F ]  [ 62 83 25 11 ]  |PASSTAG_b.%.....|
                     └────────┬──────────────┘    └──────┬──────┘
                        8-byte Identifier           4-byte Hash
                           ("PASSTAG_")             (287671138)
```

### In the C Source Code (`check.c`):
```c
struct PasswordData {
    char tag[8];                /* Identifier: "PASSTAG_" */
    unsigned long stored_hash;  /* 4-byte hash scalar */
};

struct PasswordData auth_data = {
    .tag = "PASSTAG_",
    .stored_hash = 287671138UL
};
```
Grouping `tag` and `stored_hash` inside a struct ensures the compiler places the hash immediately adjacent to `"PASSTAG_"` in memory and on disk.

---

## Step-by-Step Execution Walkthrough

```text
[ 1. Scan Binary ]
Patcher searches raw bytes for: 50 41 53 53 54 41 47 5F ("PASSTAG_")
--> Found match at File Offset 0x8000

[ 2. Target Address ]
Target Hash Offset = 0x8000 + 8 = 0x8008

[ 3. Compute Hash ]
User requests new password: "mypass"
xor_hash("mypass") = 4216307715 (Hex: 0xFB4FC003)
Little-Endian Bytes: [ 03 C0 4F FB ]

[ 4. Overwrite on Disk ]
fseek(f, 0x8008, SEEK_SET);
fwrite(new_bytes, 1, 4, f);

[ 5. Permanent Update ]
BEFORE:  Offset 0x8008: [ 62 83 25 11 ]  --> 287671138  --> hash of "s3cr3t"
AFTER:   Offset 0x8008: [ 03 C0 4F FB ]  --> 4216307715 --> hash of "mypass"
```

---

## Frequently Asked Questions by Professors & Best Answers

### Q1: *"Does the length of the new password matter?"*
> **Answer:** *"No, password length does not matter. Because we use an XOR hash function, any input string—whether 1 character or 100 characters—is always compressed into the exact same fixed size: 4 bytes (32-bit integer). The file size of `check.exe` never changes, and no adjacent memory is corrupted."*

### Q2: *"Why is the file modified on disk while closed rather than while running in RAM?"*
> **Answer:** *"Static file patching modifies the `.exe` file on disk using `fopen("rb+")` and `fwrite()`. This makes the password change permanent across all future executions. On Windows, modifying an `.exe` file on disk while it is actively executing is blocked by OS file-locking mechanisms (`ERROR_SHARING_VIOLATION`), so static patching is performed on the closed executable."*

### Q3: *"What is Little-Endian format and why do the bytes look reversed?"*
> **Answer:** *"Intel x86-64 processors use Little-Endian byte ordering, which places the least significant byte first in memory. For example, the hash `287671138` (`0x11258362`) is stored on disk as the byte sequence `62 83 25 11`."*

### Q4: *"How does `check.exe` verify the password when a user runs it?"*
> **Answer:** *"When `check.exe` runs, it computes the XOR hash of the user's input string dynamically at runtime and compares the resulting 32-bit register with the 4 bytes currently stored in `auth_data.stored_hash` (`cmp eax, edx`). If they match, access is granted."*
