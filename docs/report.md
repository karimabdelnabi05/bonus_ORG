# Academic Report: Binary Patching of a Hash-Based Password Program

## 1. Introduction

This report demonstrates how to reverse-engineer and patch a compiled Windows executable that uses hashed password storage.
The target program (`check.exe`) stores a hash of the correct password in its `.data` section rather than storing the plaintext password.
The goal is to modify the binary file on disk so that it accepts a new password of our choosing.

## 2. The Target Program (`check.exe`)

The target program is simple:

```c
unsigned long stored_hash = 401824839UL;  /* hash of "s3cr3t" */

int main(void) {
    char input[256];
    printf("Enter password: ");
    fgets(input, sizeof(input), stdin);
    if (hash_password(input) == stored_hash)
        printf("Access Granted\n");
    else
        printf("Access Denied\n");
    return 0;
}
```

Key points:
- The plaintext password `"s3cr3t"` does NOT appear anywhere in the compiled binary.
- Only the integer `401824839` (the djb2 hash of `"s3cr3t"`) is stored.
- The hash is stored as a global variable, which the compiler places in the PE binary's `.data` section.

## 3. PE File Structure

A Windows `.exe` (PE - Portable Executable) file contains several sections:

| Section | Contents |
|---------|----------|
| `.text` | Executable machine code (instructions) |
| `.rdata` | Read-only data (string literals, constants) |
| `.data` | Read-write initialized global variables |
| `.bss` | Uninitialized global variables |

The `stored_hash` variable (`401824839`) resides in the **`.data` section** because it is a global initialized variable.
In memory, `401824839` is stored in little-endian byte order as: `47 5C F3 17`.

## 4. Reverse Engineering with x64dbg

To find the stored hash in the binary:

1. Open `check.exe` in **x64dbg**.
2. Navigate to the `.data` section (Memory Map tab).
3. Look for the `cmp` instruction that compares the input hash against the stored hash.
4. The stored hash value `401824839` (`0x17F35C47`) is visible as an immediate operand or at a memory address in the `.data` section.
5. Note the file offset where these bytes (`47 5C F3 17`) are located.

See `docs/x64dbg-guide.md` for the detailed step-by-step guide.

## 5. The Patcher (`patcher.c`)

The patcher is a C program that performs binary file patching:

```c
/* Simplified logic */
int main(int argc, char *argv[]) {
    unsigned long old_hash = strtoul(argv[2], NULL, 10);  /* e.g., 401824839 */
    unsigned long new_hash = djb2(argv[3]);                /* e.g., djb2("mypass") */

    /* Read check.exe as raw bytes */
    unsigned char *data = read_file("check.exe", &size);

    /* Search for old_hash bytes in little-endian */
    for (long i = 0; i < size - 4; i++) {
        if (memcmp(&data[i], &old_hash, 4) == 0) {
            /* Replace with new_hash bytes */
            memcpy(&data[i], &new_hash, 4);
        }
    }

    /* Write modified file back to disk */
    write_file("check.exe", data, size);
}
```

### What the patcher does:

1. **Reads** the entire `check.exe` file into a byte array.
2. **Computes** `djb2("mypass")` = `250477730` (`0x0EEDFCA2`).
3. **Searches** for the bytes `47 5C F3 17` (old hash in little-endian).
4. **Replaces** them with `A2 FC ED 0E` (new hash in little-endian).
5. **Writes** the modified binary back to disk.

### Before vs After:

```
File offset 0x8000 (inside .data section):

BEFORE: 47 5C F3 17   ->  401824839  ->  hash("s3cr3t")
AFTER:  A2 FC ED 0E   ->  250477730  ->  hash("mypass")
```

## 6. The djb2 Hash Algorithm

The hash algorithm used by `check.exe` is **djb2** (created by Daniel J. Bernstein):

```c
unsigned long djb2(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;  /* hash * 33 + c */
    return hash;
}
```

This was identified by reverse-engineering the assembly instructions in x64dbg.
The key pattern to recognize is the `shl reg, 5` / `add` / `add` sequence, which corresponds to `hash * 33 + c`.

## 7. Test Results

```
=== TEST 1: Original password before patch ===
> echo s3cr3t | check.exe
Access Granted

=== TEST 2: New password before patch ===
> echo mypass | check.exe
Access Denied

=== PATCHING ===
> patcher.exe check.exe 401824839 mypass
Found old hash at file offset 0x8000 (1 occurrence)
Patched check.exe: 401824839 -> 250477730

=== TEST 3: New password after patch ===
> echo mypass | check.exe
Access Granted

=== TEST 4: Old password after patch ===
> echo s3cr3t | check.exe
Access Denied
```

## 8. Conclusion

This project demonstrates that storing a hashed password in a binary does not prevent password modification.
An attacker who can:
1. Identify the hash algorithm (via disassembly)
2. Locate the stored hash in the `.data` section (via hex editor or debugger)
3. Compute the hash of a new password

can modify the binary file on disk to accept any password of their choosing, without ever knowing the original password.
