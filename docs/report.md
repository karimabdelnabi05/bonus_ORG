# Academic Project Report: Runtime Process Memory Patching

**Course**: Systems Programming / Computer Security  
**Project**: Bonus Project - Dynamic Binary Password Patching  
**Target File**: `check.exe` (Compiled C binary)  

---

## Executive Summary

This report documents the design, theoretical foundations, implementation, and empirical verification of a runtime process memory patcher. The project objective is to modify an authentication password stored within a running compiled executable (`check.exe`) from `"123"` to `"abc"` without terminating, restarting, or recompiling the binary.

Two distinct approaches were demonstrated and evaluated:
1. **Programmatic Approach**: A custom C application (`patcher.exe`) using Win32 Process Memory APIs (`OpenProcess`, `VirtualQueryEx`, `ReadProcessMemory`, `WriteProcessMemory`).
2. **Manual GUI Approach**: Interactive dynamic inspection using **Cheat Engine**.

---

## 1. System Architecture & Memory Model

### Virtual Address Space & Process Isolation
Modern operating systems (including Windows x64) enforce virtual memory isolation between processes. Each process runs in its own private Virtual Address Space (VAS). Process $A$ cannot directly dereference pointers belonging to Process $B$.

To interact with another process's virtual address space, the operating system provides kernel-mediated subsystem APIs exposed via `kernel32.dll`.

### Address Space Layout Randomization (ASLR)
Under Windows, binaries compiled with ASLR have their base load address randomized upon each execution. Consequently, hardcoding static memory addresses (e.g. `0x00401000`) is unreliable. A robust patcher must dynamically scan the process address space at runtime using `VirtualQueryEx`.

---

## 2. Windows API Architecture

The custom patcher library (`src/patcher_lib.c`) utilizes five core Win32 functions:

```
[Toolhelp32 Snapshot] ---> OpenProcess() ---> VirtualQueryEx() ---> ReadProcessMemory() ---> WriteProcessMemory()
```

1. **`CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)`**  
   Enumerates all running system processes to find `check.exe` and retrieve its Process ID (PID).
2. **`OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid)`**  
   Requests a process handle with virtual memory read/write permissions from the Windows Security Manager.
3. **`VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi))`**  
   Iterates through virtual memory pages to discover committed (`MEM_COMMIT`) and readable memory regions, skipping non-accessible pages (`PAGE_NOACCESS`, `PAGE_GUARD`).
4. **`ReadProcessMemory(hProcess, baseAddr, buffer, regionSize, &bytesRead)`**  
   Copies page contents into local buffer space for pattern matching.
5. **`WriteProcessMemory(hProcess, targetAddr, newData, length, &bytesWritten)`**  
   Overwrites target memory bytes. Automatically handles copy-on-write page faults; calls `VirtualProtectEx` if necessary to grant `PAGE_EXECUTE_READWRITE` permissions.

---

## 3. Implementation Details

### Target Binary (`src/check.c`)
The target binary stores the target password in a stack-allocated character array:
```c
char password[] = "123";
```
Storing the string in a mutable `char[]` array ensures that the compiler places the byte sequence in writeable stack/data memory.

### Patcher Library (`src/patcher_lib.c`)
- **Safety Checks**: Validates that $\text{length}(\text{new\_password}) \le \text{length}(\text{old\_password})$ to prevent buffer overflows into adjacent stack frames.
- **Pattern Matcher**: Performs linear scanning across mapped virtual regions for ASCII byte sequence `0x31 0x32 0x33` (`"123"`).
- **Null-Padding**: Null-terminates shorter replacement strings to clean up residual bytes.

---

## 4. Empirical Verification & Test Results

The codebase includes an automated test harness (`tests/test_harness.h`) executing 15 unit and integration tests across 10 TDD cycles.

### Test Execution Output
```text
=== check.exe Integration Tests ===
  correct_password_grants_access                     PASS
  wrong_password_denies_access                       PASS

=== Patcher Unit & Integration Tests ===
--- Input Validation ---
  validate_rejects_longer_new_password               PASS
  validate_accepts_same_length_password              PASS
  validate_accepts_shorter_password                  PASS
  validate_rejects_null_old                          PASS
  validate_rejects_null_new                          PASS
  validate_rejects_empty_old                         PASS
  validate_rejects_empty_new                         PASS

--- Process Finding ---
  find_process_finds_running_check_exe               PASS
  find_process_returns_zero_for_nonexistent          PASS

--- Memory Scanning ---
  scan_memory_finds_password_string                  PASS
  scan_memory_returns_zero_for_missing_string        PASS

--- Memory Patching ---
  patch_memory_overwrites_and_readback_matches       PASS

--- End-to-End ---
  e2e_patch_changes_password_in_running_check        PASS

Tests: 15 total, 15 passed
ALL TESTS PASSED
```

---

## 5. Comparison of Approaches

| Criteria | Programmatic (`patcher.exe`) | Manual GUI (Cheat Engine / x64dbg) |
|---|---|---|
| **Automation** | 100% automated scriptable CLI | Manual interactive workflow |
| **Speed** | Instant (<50ms execution) | Requires manual scan & edit (~1-2 minutes) |
| **ASLR Resilience** | Built-in via dynamic `VirtualQueryEx` scan | Manual search/pattern match per session |
| **Dependencies** | Standard Win32 API (`kernel32.dll`) | Requires standalone GUI tools (Cheat Engine / x64dbg) |
| **Educational Value** | Deep understanding of Win32 process memory internal APIs | Interactive visual memory inspection & disassembly analysis |

---

## 6. Instructions to Reproduce

### Building from Source
```powershell
# Build binaries using GCC / MinGW
make all

# Or using PowerShell build script:
.\build.ps1 all
```

### Running the Demonstration
1. Start `check.exe` in terminal 1:
   ```cmd
   .\build\check.exe
   ```
2. Run `patcher.exe` in terminal 2:
   ```cmd
   .\build\patcher.exe check.exe 123 abc
   ```
3. Return to terminal 1 and enter `abc` to confirm access granted!
