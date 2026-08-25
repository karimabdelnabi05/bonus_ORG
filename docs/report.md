# Academic Report: Binary Patching of a Hash-Based Password Program

## 1. Introduction

This report demonstrates how to modify a compiled executable's password by patching its binary file on disk.
The target program (`check.exe`) stores a hash of the correct password in its `.data` section.
A second program (`patcher.exe`) opens `check.exe` as a binary file, locates the stored hash, and replaces it with the hash of a new password.

## 2. The Target Program (`check.exe`)

```c
/* djb2 hash function */
static unsigned long hash_password(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;  /* hash * 33 + c */
    return hash;
}

/* Stored hash of "s3cr3t" - lives in .data section of the binary */
unsigned long stored_hash = 401824839UL;

int main(void) {
    char input[256];
    printf("Enter password: ");
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\r\n")] = '\0';

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
- `stored_hash` is a global variable, so the compiler places it in the PE binary's `.data` section.

## 3. How the Hash is Stored in the Binary

When `check.exe` is compiled, `stored_hash = 401824839` is stored as 4 bytes in little-endian format inside the `.data` section:

```
Decimal:     401824839
Hexadecimal: 0x17F35C47
Little-endian bytes: 47 5C F3 17
```

These 4 bytes exist at a specific offset inside the `check.exe` file on disk.

## 4. The Patcher Program (`patcher.exe`)

The patcher is a separate C program that opens `check.exe` as a binary file and modifies it:

### Usage
```
patcher.exe check.exe 401824839 mypass
```

### What it does step by step:

1. **Reads the file**: Opens `check.exe` with `fopen("check.exe", "rb")` and reads the entire file into a byte array using `fread()`.

2. **Computes the new hash**: Uses the same djb2 algorithm to compute `hash("mypass")` = `250477730` (`0x0EEDFCA2`).

3. **Searches for old hash bytes**: Scans the byte array for the sequence `47 5C F3 17` (the old hash in little-endian).

4. **Replaces the bytes**: Overwrites those 4 bytes with `A2 FC ED 0E` (the new hash in little-endian).

5. **Writes the file back**: Opens the file with `fopen("check.exe", "wb")` and writes the modified byte array back to disk using `fwrite()`.

### Before and after the patch:

```
.data section of check.exe:

BEFORE:  ... 47 5C F3 17 ...    (hash of "s3cr3t" = 401824839)
AFTER:   ... A2 FC ED 0E ...    (hash of "mypass" = 250477730)
```

## 5. PE File Structure

A Windows `.exe` file (PE format) contains several sections:

| Section | Contents |
|---------|----------|
| `.text` | Machine code (CPU instructions) |
| `.rdata` | Read-only data (string constants) |
| `.data` | Read-write global variables |

`stored_hash` is a global initialized variable, so it is placed in `.data` by the compiler.
The patcher finds and modifies these bytes directly in the `.data` section of the file.

## 6. Test Results

```
=== Before Patch ===
> echo s3cr3t | check.exe     -> Access Granted
> echo mypass | check.exe     -> Access Denied

=== Patching ===
> patcher.exe check.exe 401824839 mypass
  Found old hash at file offset 0x8000
  Old hash: 401824839 -> New hash: 250477730
  SUCCESS

=== After Patch ===
> echo mypass | check.exe     -> Access Granted
> echo s3cr3t | check.exe     -> Access Denied
```

## 7. Conclusion

This project shows that even when a password is stored as a hash rather than plaintext, the binary can still be patched.
The patcher program opens the target executable as a binary file, locates the stored hash bytes, and replaces them with the hash of a new password.
The entire process is done programmatically in C using standard file I/O functions (`fopen`, `fread`, `fwrite`), with no external tools required.
