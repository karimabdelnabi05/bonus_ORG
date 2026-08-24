# Academic Project Report: Runtime Memory Patching (Hashed Passwords)

**Course**: Systems Programming / Computer Security  
**Project**: Bonus Project - Dynamic Binary Password Patching (Hashed Version)  
**Target File**: `check.exe` (Compiled C binary with hashed password storage)  

---

## Executive Summary

This report documents the theoretical background, Win32 architecture, implementation, and empirical verification of an automated runtime process memory patcher. 

The project objective is to modify an authentication password inside a running compiled C application (`check.exe`) from `"s3cr3t"` to `"pass"` without closing, restarting, or recompiling the binary.

Crucially, `check.exe` uses **cryptographic/non-cryptographic hashing** (`djb2` hash). The plaintext string `"s3cr3t"` **does not exist anywhere in memory or in the binary file**. Only the pre-computed 32-bit hash integer (`401824839`) is stored in the executable's `.data` section.

Two approaches were demonstrated and evaluated:
1. **Programmatic Approach**: An automated C application (`debug_patcher.exe`) utilizing Win32 Process Memory APIs (`CreateToolhelp32Snapshot`, `VirtualQueryEx`, `ReadProcessMemory`, `WriteProcessMemory`, `VirtualProtectEx`).
2. **Manual Debugger Approach**: Interactive memory inspection using **x64dbg**.

---

## 1. System Architecture & Memory Model

### Virtual Address Space & Process Isolation
Windows enforces private Virtual Address Space (VAS) isolation between processes. Process $A$ cannot directly access memory belonging to Process $B$. To inspect or modify another process's virtual memory space, the operating system provides kernel-mediated APIs via `kernel32.dll`.

### Hashed Password Memory Storage
Unlike naive applications that store passwords in plain ASCII text (`char password[] = "123"`), `check.exe` stores only a hash value:

```c
/* Global stored hash variable located in .data section */
volatile unsigned long stored_hash = 401824839UL; // djb2("s3cr3t")
```

When a user enters a password at runtime:
1. `check.exe` reads the input string via `fgets()`.
2. It strips trailing line endings (`\r\n`).
3. It passes the input to `hash_password()`.
4. It compares `input_hash == stored_hash`.

Because `"s3cr3t"` is never stored as text, traditional string search utilities find **0 occurrences** in RAM.

---

## 2. Win32 API Architecture

The patcher tool (`src/debug_patcher.c`) uses five core Win32 subsystem APIs:

```text
[Toolhelp32 Snapshot] ──> OpenProcess() ──> VirtualQueryEx() ──> ReadProcessMemory() ──> WriteProcessMemory()
```

1. **`CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)`**:  
   Enumerates system processes to find `check.exe` and retrieve its Process ID (PID).
2. **`OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid)`**:  
   Requests a process handle with virtual memory read/write access rights from the Windows Security Manager.
3. **`VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi))`**:  
   Iterates through virtual memory pages to discover committed (`MEM_COMMIT`) readable regions in the target process.
4. **`ReadProcessMemory(hProcess, baseAddr, buffer, regionSize, &bytesRead)`**:  
   Reads page contents into local buffer memory to scan for the target hash integer (`401824839`).
5. **`VirtualProtectEx(hProcess, targetAddr, size, PAGE_EXECUTE_READWRITE, &oldProtect)`**:  
   Temporarily unlocks page write permissions if the region is protected.
6. **`WriteProcessMemory(hProcess, targetAddr, &newHash, sizeof(newHash), &bytesWritten)`**:  
   Overwrites the stored hash (`401824839`) with the new password hash (`2090608092` = `hash("pass")`).

---

## 3. Source Code Explanation

### 1. Target Binary (`src/check.c`)
- **`hash_password(const char *str)`**: Implements djb2 hashing:
  $$H(s) = \left( H(s-1) \times 33 \right) + c$$
- **`stored_hash`**: Declared at global file scope as `volatile unsigned long stored_hash = 401824839UL;` to ensure it resides in the executable's writable `.data` section.

### 2. Automated Patcher (`src/debug_patcher.c`)
- **`hash_password(new_password)`**: Computes `target_new_hash = 2090608092` for the new password `"pass"`.
- **`find_process_by_name("check.exe")`**: Resolves `PID` dynamically.
- **Memory Scanner**: Scans process memory regions for `INITIAL_STORED_HASH` (`401824839`) or existing updated hashes.
- **Overwrites RAM**: Calls `WriteProcessMemory` to patch the location live in RAM in `<10ms`.

---

## 4. Empirical Test Verification

The codebase includes automated unit and end-to-end integration test harnesses (`tests/test_check.c` and `tests/test_patcher_e2e.c`).

### Empirical Test Execution Output
```text
=========================================
  Automated E2E Test for debug_patcher   
=========================================

[1] check.exe started with PID 14756
[2] Running debug_patcher.exe check.exe pass...
[3] debug_patcher.exe started with PID 23104

--- Patcher Output ---
=== Automated Runtime Memory Patcher ===

[1/4] Validating inputs...
  Target password: "pass" (hash = 2090608092)

[2/4] Finding process "check.exe"...
  OK: Found PID 14756

[3/4] Scanning process memory for stored hash (401824839)...
  PATCHED @ 00007ff6eb319000 (hash updated to 2090608092)

[4/4] Results:
  SUCCESS: Patched 1 memory location(s).

Password in "check.exe" changed to: "pass"
----------------------

[4] Sending 'pass\n' to check.exe...
--- check.exe Output ---
Access Granted

[5] Sending 's3cr3t\n' (old password) to check.exe...
--- check.exe Output for old password ---
Access Denied
```

---

## 5. Comparison of Approaches

| Criteria | Programmatic (`debug_patcher.exe`) | Manual GUI (`x64dbg`) |
|---|---|---|
| **Execution Time** | Instant (<10ms) | Manual (~1-2 minutes) |
| **Automation** | 100% Automated Scriptable CLI | Interactive GUI Workflow |
| **ASLR Resilience** | Built-in via dynamic `VirtualQueryEx` scan | Manual address lookup per run |
| **Dependencies** | Standard Win32 API (`kernel32.dll`) | Requires standalone x64dbg debugger |
| **Educational Value** | Deep understanding of Win32 process memory internal APIs | Disassembly inspection & register analysis |

---

## 6. Instructions to Reproduce

### Build
```powershell
gcc -Wall -Wextra -std=c99 -o build/check.exe src/check.c
gcc -Wall -Wextra -std=c99 -o build/debug_patcher.exe src/debug_patcher.c
```

### Demonstration
1. Terminal 1: Run `.\build\check.exe`
2. Terminal 2: Run `.\build\debug_patcher.exe check.exe pass`
3. Return to Terminal 1 and type `pass` $\rightarrow$ **`Access Granted`**!
