# Academic Project Report: Runtime Memory Patching (Hashed Passwords)

**Course**: Systems Programming / Computer Security
**Project**: Bonus Project - Dynamic Binary Password Patching (Hashed Version)
**Target File**: `check.exe` (Compiled C binary with hashed password)

---

## Executive Summary

This report documents the design, theoretical foundations, implementation, and verification of a runtime process memory patcher that can change a hashed password in a running executable without knowing:
- The original plaintext password
- The hash algorithm used
- The stored hash value

Two distinct approaches were demonstrated:
1. **Programmatic Approach**: A custom C application (`debug_patcher.exe`) using Memory Snapshot Differencing combined with Win32 Process Memory APIs.
2. **Manual GUI Approach**: Interactive memory inspection and register analysis using **x64dbg** debugger.

---

## 1. The Challenge: Why Hashing Breaks Traditional Patching

### Traditional String Scanning (Fails!)
In the plaintext version, the password `"123"` exists as ASCII bytes (`0x31 0x32 0x33`) in RAM.
A memory scanner can search for these bytes and overwrite them.

### Hashed Storage (Our Target)
In this version, `check.exe` stores `hash("s3cr3t") = 401824839` (an unsigned long integer).
The plaintext string `"s3cr3t"` **never appears in memory**.
A scanner searching for `"s3cr3t"` finds **0 results**.
A scanner cannot search for the hash value either because the attacker does not know what it is.

---

## 2. Solution: Memory Snapshot Differencing

### Core Insight
Even though we cannot search for the hash value directly, we can observe how memory CHANGES when the program processes different inputs.

When a user types a password into `check.exe`:
- The `input_hash` variable **changes** (different input = different hash)
- The `stored_hash` variable **stays the same** (it is a constant)
- Both variables live **near each other** on the stack or in the data segment

### Algorithm
```
Snapshot 1: User types "aaaa"  -> input_hash = H("aaaa"),  stored_hash = H("s3cr3t")
Snapshot 2: User types "bbbb"  -> input_hash = H("bbbb"),  stored_hash = H("s3cr3t")

Diff Analysis:
  - Addresses that CHANGED between snapshots  = input_hash candidates
  - Addresses that STAYED SAME near changes   = stored_hash candidates

Patch:
  User types "mypass" -> input_hash = H("mypass")
  Copy input_hash value over stored_hash location
  Result: stored_hash is now H("mypass") -> typing "mypass" grants access!
```

---

## 3. Windows API Architecture

The debug patcher uses the same Win32 APIs as the plaintext version, plus additional memory analysis:

1. **`CreateToolhelp32Snapshot`**: Enumerate processes to find `check.exe` by name.
2. **`OpenProcess`**: Obtain a process handle with VM read/write permissions.
3. **`VirtualQueryEx`**: Iterate through all committed memory regions to build a complete memory map.
4. **`ReadProcessMemory`**: Capture memory snapshots for differential analysis.
5. **`WriteProcessMemory`**: Overwrite the stored hash with the new hash.
6. **`VirtualProtectEx`**: Temporarily grant write permissions to read-only pages.

---

## 4. Implementation Details

### Target Binary (`src/check.c`)
```c
// The password is stored ONLY as a hash - no plaintext in memory
unsigned long stored_hash = 401824839UL;  // djb2("s3cr3t")

unsigned long input_hash = hash_password(user_input);
if (input_hash == stored_hash) {
    printf("Access Granted\n");
}
```

### Debug Patcher (`src/debug_patcher.c`)
- **Memory Snapshot Differencing**: Takes two snapshots of writable process memory after different user inputs.
- **Change Detection**: Identifies addresses where values changed (input_hash candidates).
- **Proximity Heuristic**: Finds unchanged values near changed values (stored_hash candidates).
- **Hash Overwrite**: Copies the input hash of the desired new password over the stored hash location.

---

## 5. Manual Approach: x64dbg Debugger

The same password change can be performed manually using x64dbg:

1. Attach x64dbg to `check.exe`.
2. Set a breakpoint on the comparison instruction (`cmp` or `test`).
3. Type the desired new password. The breakpoint fires.
4. In the CPU registers or memory dump, read where the stored hash lives.
5. Copy the input hash bytes over the stored hash bytes.
6. Resume execution - the new password now grants access.

See `docs/x64dbg-guide.md` for detailed step-by-step instructions.

---

## 6. Comparison of Approaches

| Criteria | Programmatic (`debug_patcher.exe`) | Manual GUI (`x64dbg`) |
|---|---|---|
| **Knows Original Password?** | No | No |
| **Knows Hash Algorithm?** | No | No |
| **Knows Stored Hash Value?** | No (discovers it via differencing) | No (discovers it via register inspection) |
| **Automation** | Semi-automated (3 interactive prompts) | Fully manual |
| **Educational Value** | Memory snapshot analysis, differential debugging | CPU register analysis, disassembly reading |

---

## 7. Instructions to Reproduce

### Building from Source
```powershell
gcc -o build/check.exe src/check.c
gcc -o build/debug_patcher.exe src/debug_patcher.c
```

### Running the Demonstration
1. Start `check.exe` in Terminal 1:
   ```powershell
   .\build\check.exe
   ```
2. Run `debug_patcher.exe` in Terminal 2:
   ```powershell
   .\build\debug_patcher.exe check.exe mypass
   ```
3. Follow the interactive prompts:
   - Type `aaaa` into Terminal 1, press Enter in Terminal 2
   - Type `bbbb` into Terminal 1, press Enter in Terminal 2
   - Type `mypass` into Terminal 1, press Enter in Terminal 2
4. Return to Terminal 1 and type `mypass` - **Access Granted!**
