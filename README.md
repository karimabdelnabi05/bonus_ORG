# Runtime Memory Patcher - Hashed Password Branch

A systems programming exercise demonstrating runtime process memory modification on Windows, even when the password is **hashed** and the attacker does **not know** the original password, the hash algorithm, or the stored hash value.

## What this does

This project contains two programs:

1. **`check.exe`** - A target program with a hashed password. The plaintext password string does NOT exist anywhere in memory - only its pre-computed hash value is stored. It loops, asking for a password and printing "Access Granted" or "Access Denied".
2. **`debug_patcher.exe`** - A tool that changes the password inside a *running* `check.exe` process **without knowing the original password or hash algorithm**.

## How the patcher works (Memory Snapshot Differencing)

Since the password is hashed, traditional string scanning cannot work. The patcher uses a **memory snapshot differencing** strategy:

1. Take a snapshot of all writable memory in `check.exe`
2. User types a wrong password (e.g., `aaaa`) - this changes `input_hash` in RAM
3. Take a second snapshot after a different wrong password (e.g., `bbbb`)
4. **Addresses that CHANGED** between snapshots = candidates for `input_hash` variable
5. **Addresses that STAYED THE SAME** nearby = candidates for `stored_hash` variable
6. User types desired new password (e.g., `mypass`)
7. Patcher reads the `input_hash` (hash of `mypass`) and copies it over `stored_hash`
8. Password is now changed - `mypass` grants access, old password is rejected!

## Quick Start

### Prerequisites
- GCC (MinGW-w64) or MSYS2 with `mingw-w64-x86_64-gcc`

### Build
```powershell
gcc -o build/check.exe src/check.c
gcc -o build/debug_patcher.exe src/debug_patcher.c
```

### Demo
```powershell
# Terminal 1: Start the target program
.\build\check.exe

# Terminal 2: Run the debug patcher
.\build\debug_patcher.exe check.exe mypass
```

Then follow the interactive prompts in Terminal 2.

## Project Structure

```
src/
  check.c              # Target program (hashed password using djb2)
  debug_patcher.c      # Hash-blind patcher using memory snapshot differencing
tests/
  test_harness.h       # Lightweight C test framework
  test_check.c         # check.exe integration tests
docs/
  x64dbg-guide.md      # Manual approach using x64dbg debugger
  report.md            # Full project report for professor submission
```

## Two Approaches

1. **Programmatic** (`debug_patcher.exe`) - Memory snapshot differencing to locate and overwrite hash values
2. **Manual** (x64dbg debugger) - Interactive memory inspection - see [`docs/x64dbg-guide.md`](docs/x64dbg-guide.md)
