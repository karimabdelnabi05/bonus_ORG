# Bonus Assignment - Binary Password Patcher

## What This Project Does

1. **`check.exe`** - A program that asks for a password. The password is stored as a **hash** (not plaintext) inside the binary.
2. **`patcher.exe`** - A C program that opens `check.exe` as a binary file, finds the stored hash, and replaces it with the hash of a new password.

No external tools are used. Everything is done in C code.

## How to Build and Run

```powershell
# Compile both programs
gcc -o check.exe src/check.c
gcc -o patcher.exe src/patcher.c

# Test: original password works
echo s3cr3t | ./check.exe
# Output: Access Granted

# Patch check.exe to change the password to "mypass"
./patcher.exe check.exe 401824839 mypass

# Test: new password works
echo mypass | ./check.exe
# Output: Access Granted

# Test: old password no longer works
echo s3cr3t | ./check.exe
# Output: Access Denied
```

## How It Works

### check.exe (the target)

- Uses the **djb2** hash algorithm to hash user input.
- Stores `hash("s3cr3t")` = `401824839` as a global variable in the `.data` section of the binary.
- Compares `hash(input) == stored_hash` to grant or deny access.
- The plaintext password `"s3cr3t"` does NOT exist anywhere in the compiled binary.

### patcher.exe (the patcher)

- Opens `check.exe` as a **binary file** using `fopen("check.exe", "rb")`.
- Reads the entire `.exe` file into a byte array.
- Computes `djb2("mypass")` = `250477730`.
- Searches for the old hash bytes (`47 5C F3 17`) in the file.
- Replaces them with the new hash bytes (`A2 FC ED 0E`).
- Writes the modified binary back to disk using `fopen("check.exe", "wb")`.

```
check.exe .data section (before patch):
  Offset 0x8000:  [47 5C F3 17]  =  401824839  =  hash("s3cr3t")

check.exe .data section (after patch):
  Offset 0x8000:  [A2 FC ED 0E]  =  250477730  =  hash("mypass")
```

## Files

| File | Description |
|------|-------------|
| `src/check.c` | Target program - hashes input, compares with stored hash |
| `src/patcher.c` | Opens check.exe as binary file, finds and replaces the stored hash |
| `docs/report.md` | Academic report explaining the approach |
