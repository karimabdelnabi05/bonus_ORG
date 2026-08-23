# Runtime Memory Patcher - Bonus Project

A systems programming exercise demonstrating runtime process memory modification on Windows.

## What this does

This project contains two programs:

1. **`check.exe`** - A target program with a hardcoded password (`"123"`). It loops, asking for a password and printing "Access Granted" or "Access Denied".
2. **`patcher.exe`** - A tool that modifies the password inside a *running* `check.exe` process, without restarting or recompiling it.

## How it works

The patcher uses the Windows API to:
1. Find the `check.exe` process by name (`CreateToolhelp32Snapshot`)
2. Scan all readable memory regions for the old password (`VirtualQueryEx` + `ReadProcessMemory`)
3. Overwrite each occurrence with the new password (`WriteProcessMemory`)

## Quick Start

### Prerequisites
- GCC (MinGW-w64) or MSYS2 with `mingw-w64-x86_64-gcc`
- GNU Make

### Build
```bash
make all
```

### Demo
```bash
# Terminal 1: Start the target program
./build/check.exe

# Terminal 2: Patch the password from "123" to "abc"
./build/patcher.exe check.exe 123 abc
```

Now go back to Terminal 1 and try typing `abc` - it should print "Access Granted"!

### Run Tests
```bash
# Build and run check.exe tests
make test-check

# For patcher tests, first start check.exe in another terminal, then:
make test-patcher
```

## Project Structure

```
src/
  check.c          # Target program
  patcher.c        # Patcher CLI entry point
  patcher_lib.h    # Patcher library public interface
  patcher_lib.c    # Patcher library implementation
tests/
  test_harness.h   # Lightweight C test framework
  test_check.c     # check.exe integration tests
  test_patcher.c   # Patcher unit + integration tests
docs/
  x64dbg-guide.md        # Manual approach using x64dbg debugger
  cheat-engine-guide.md  # Manual approach using Cheat Engine
  report.md              # Full project report for professor submission
Makefile
```

## Two Approaches

This project documents two approaches to runtime memory patching:

1. **Programmatic** (this codebase) - Custom C tool using Windows API (`patcher.exe`)
2. **Manual** (x64dbg / Cheat Engine) - Interactive debugger memory inspection - see [`docs/x64dbg-guide.md`](docs/x64dbg-guide.md)
