# Presentation & Defense Guide: Binary HEX Password Patching

This guide is designed for explaining the project to your doctor/professor during your project demonstration or oral defense.
It covers the two distinct methods for locating the target password in a binary file, along with ready-to-use spoken scripts and answers to follow-up questions.

---

## 📑 Table of Contents
1. [The 60-Second Spoken Script for the Doctor](#the-60-second-spoken-script-for-the-doctor)
2. [Method 1: The Magic Identifier Tag Method (`PASSTAG_`)](#method-1-the-magic-identifier-tag-method-passtag_)
3. [Method 2: The PE Section Header Table Method (No Tag Needed)](#method-2-the-pe-section-header-table-method-no-tag-needed)
4. [Side-by-Side Method Comparison](#side-by-side-method-comparison)
5. [Frequently Asked Questions by Professors & Best Answers](#frequently-asked-questions-by-professors--best-answers)

---

## The 60-Second Spoken Script for the Doctor

You can read or speak this exact script when presenting:

> *"Doctor, our project demonstrates static binary file patching on a compiled Windows executable (`check.exe`) without recompiling the source code.*
> 
> *Instead of storing a plaintext password, the application stores a 32-bit XOR hash inside the initialized data section (`.data`).*
> 
> *To locate where this hash lives in the binary file, we explored two standard approaches:*
> 
> * **1. The Identifier Tag Method**: We place an 8-byte marker tag (`PASSTAG_`) in memory immediately before the hash. Our patcher scans the raw binary file for this tag, and the next 4 bytes following the tag represent the stored hash.*
> * **2. The PE Section Header Method**: The patcher parses the Windows PE Section Table, locates the file offset of the `.data` section (at offset `0x8000`), and directly accesses the stored variable.*
> 
> *Once the patcher finds the 4-byte location, it uses our known XOR formula `(hash * 31) ^ character` to compute the hash for the new password, and overwrites those exact 4 bytes on disk.*
> 
> *When `check.exe` is opened again, it reads the updated hash from disk and permanently unlocks with the new password!"*

---

## Method 1: The Magic Identifier Tag Method (`PASSTAG_`)

This method places a distinct anchor marker directly before the password hash in binary memory.

```
[ Binary File check.exe on Disk ]
File Offset 0x8000:  [ 50 41 53 53 54 41 47 5F ]  [ 62 83 25 11 ]
                     └────────┬──────────────┘    └──────┬──────┘
                        8-byte Marker                4-byte Hash
                        ("PASSTAG_")              (287671138)
```

### How It Works Step-by-Step in Binary HEX:
1. **Search for the Marker**:
   The patcher opens `check.exe` as raw binary and scans byte-by-byte for the 8-byte sequence:
   `50 41 53 53 54 41 47 5F` (ASCII: `"PASSTAG_"`).
2. **Calculate the Target Offset**:
   When it finds `"PASSTAG_"` at offset `0x8000`, it adds 8 bytes (`0x8000 + 8 = 0x8008`).
   The next 4 bytes at `0x8008` are guaranteed to be the stored password hash.
3. **Overwrite the Bytes on Disk**:
   The patcher calculates the XOR hash of the new password (`"mypass"` $\rightarrow$ `03 C0 4F FB`), seeks directly to offset `0x8008`, and overwrites those 4 bytes.

### Why This Is Used in Industry:
- It is **100% reliable** and eliminates any ambiguity or fragile hardcoded addresses.
- It is the standard method used when creating software binary templates, license key injectors, and installer customizers.

---

## Method 2: The PE Section Header Table Method (No Tag Needed)

This is the generic method that works on arbitrary binaries **without requiring any special tags**.

```
[ PE File check.exe Structure ]
Offset 0x0000:  [ DOS Header "MZ" ]
Offset 0x003C:  [ Pointer to PE Header: 0x0080 ]
Offset 0x0080:  [ PE Header "PE\0\0" ]
Offset 0x0188:  [ Section Table: .text, .data, .rdata ]
                └─► ".data" Section is located at File Offset 0x8000
Offset 0x8000:  [ .data Section: Stored Variables ]
                └─► Offset 0x8000: [ 62 83 25 11 ] (4-byte hash scalar)
```

### How It Works Step-by-Step in Binary HEX:
1. **Read the DOS Header**:
   The patcher checks byte `0x0000` for `4D 5A` (`MZ`).
   It reads offset `0x003C` to find the address of the PE Header (`0x0080`).
2. **Read the Section Table**:
   At offset `0x0188`, it reads the Windows PE Section Table.
   The table specifies: *The `.data` section (where global variables live) is at file offset `0x8000`*.
3. **Locate the Variable in `.data`**:
   The patcher goes directly to file offset `0x8000` and reads the 4-byte initialized variable (`stored_hash`).
4. **Overwrite the Bytes on Disk**:
   It overwrites the 4 bytes at `0x8000` with the new password hash.

### Why This Is Used in Industry:
- It works on **any arbitrary compiled `.exe`** even if the original programmer did not leave a tag.

---

## Side-by-Side Method Comparison

| Comparison Feature | Method 1: Magic Identifier (`PASSTAG_`) | Method 2: PE Section Parsing |
|---|---|---|
| **Location Mechanism** | Scans for 8-byte tag `"PASSTAG_"`; target is at `tag_offset + 8`. | Reads PE Section Headers to find where `.data` begins (`0x8000`). |
| **Requires Marker in Code?** | Yes, placed in `check.c` before `stored_hash`. | No, relies on standard Windows PE format. |
| **Primary Real-World Use** | Software templates, product key injectors, game save anchors. | Reverse engineering and binary analysis of third-party `.exe` files. |
| **Execution Complexity** | Simple linear byte scan (`memcmp`). | PE structure header parsing. |

---

## Frequently Asked Questions by Professors & Best Answers

### Q1: *"Does the length of the new password matter?"*
> **Answer:** *"No, password length does not matter. Because we use a hash function, any input string—whether 1 character or 100 characters—is always compressed into the exact same fixed size: 4 bytes (32-bit integer). The file size of `check.exe` never changes, and no adjacent memory is corrupted."*

### Q2: *"Why is the file modified while closed rather than while running?"*
> **Answer:** *"Static file patching modifies the `.exe` file on disk using `fopen("rb+")` and `fwrite()`. This makes the password change permanent across all future executions. On Windows, modifying an `.exe` file on disk while it is actively running is blocked by OS file-locking mechanisms (`ERROR_SHARING_VIOLATION`), so static patching is performed on the closed executable."*

### Q3: *"What is Little-Endian format and why do the bytes look reversed?"*
> **Answer:** *"Intel x86-64 processors use Little-Endian byte ordering, which places the least significant byte first in memory. For example, the hash `287671138` (`0x11258362`) is stored on disk as the byte sequence `62 83 25 11`."*

### Q4: *"How does `check.exe` verify the password when a user runs it?"*
> **Answer:** *"When `check.exe` runs, it computes the XOR hash of the user's input string dynamically at runtime and compares the resulting 32-bit register with the 4 bytes currently stored in its `.data` section (`cmp eax, edx`). If they match, access is granted."*
