# Bonus Assignment - Binary Password Patcher

A demonstration of reverse engineering a hashed-password program and patching the binary to change the password.

## What This Project Does

1. **`check.exe`** - A program that asks for a password. The password is stored as a **hash** (not plaintext) inside the binary's `.data` section.
2. **`patcher.exe`** - A tool that modifies the `check.exe` binary file on disk, replacing the old stored hash with the hash of a new password.

## How It Works

### Step 1: Reverse Engineer `check.exe`

Open `check.exe` in **x64dbg** (or a hex editor) and find:
- The hash algorithm used (djb2)
- The stored hash value: `401824839` (hex: `0x17F35C47`)
- Located in the `.data` section at file offset `0x8000`

See [docs/x64dbg-guide.md](docs/x64dbg-guide.md) for the step-by-step walkthrough.

### Step 2: Patch the Binary

```powershell
# Compile
gcc -o check.exe src/check.c
gcc -o patcher.exe src/patcher.c

# Test original password
echo s3cr3t | ./check.exe
# Output: Access Granted

# Patch: replace old hash with hash("mypass")
./patcher.exe check.exe 401824839 mypass

# Test new password
echo mypass | ./check.exe
# Output: Access Granted
```

### Step 3: Verify

```powershell
# Old password no longer works
echo s3cr3t | ./check.exe
# Output: Access Denied

# New password works
echo mypass | ./check.exe
# Output: Access Granted
```

## Files

| File | Description |
|------|-------------|
| `src/check.c` | Target program - hashes input and compares with stored hash |
| `src/patcher.c` | Binary patcher - finds old hash bytes in .exe file and replaces them |
| `docs/report.md` | Academic report explaining the approach |
| `docs/x64dbg-guide.md` | Step-by-step x64dbg reverse engineering guide |

## The Approach

```
check.exe on disk:
  .data section contains: [47 5C F3 17]  (401824839 in little-endian)

patcher.exe:
  1. Reads check.exe as raw bytes
  2. Searches for bytes [47 5C F3 17]
  3. Replaces with hash("mypass") = [A2 FC ED 0E]
  4. Writes modified file back to disk

Result: check.exe now accepts "mypass" instead of "s3cr3t"
```
