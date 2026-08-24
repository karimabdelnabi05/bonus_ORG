# Runtime Memory Patcher (Hashed Passwords) - Bonus Project

An academic systems programming project demonstrating runtime process memory modification on Windows binaries with **hashed password storage**.

---

## 📌 Project Overview

This repository contains two C programs:

1. **`check.exe`** — Target binary with a hashed password. The plaintext password string (`"s3cr3t"`) **does not exist anywhere in memory or in the binary file**; only its pre-computed djb2 hash (`401824839`) is stored in the `.data` section.
2. **`debug_patcher.exe`** — An automated Windows tool that scans a running `check.exe` process's RAM, computes the hash for a new password (e.g., `"pass"` = `2090608092`), and overwrites the stored hash live in memory via `WriteProcessMemory`.

---

## 🚀 Quick Start (2 Commands)

### Step 1: Start `check.exe`
```powershell
.\build\check.exe
```
*(Leave it running in Terminal 1).*

### Step 2: Run `debug_patcher.exe`
```powershell
.\build\debug_patcher.exe check.exe pass
```

### Step 3: Test in Terminal 1:
- Type **`pass`** $\rightarrow$ **`Access Granted`** 🎉
- Type **`s3cr3t`** (old password) $\rightarrow$ **`Access Denied`**

---

## 🛠️ How It Works (Win32 API Architecture)

```
[patcher.exe] ──> 1. CreateToolhelp32Snapshot()  ──> Finds PID of check.exe
              ──> 2. OpenProcess(PROCESS_VM_READ|WRITE) ──> Obtains RAM Handle
              ──> 3. VirtualQueryEx() + ReadProcessMemory() ──> Scans .data Section for Stored Hash
              ──> 4. VirtualProtectEx() + WriteProcessMemory() ──> Overwrites Stored Hash
```

---

## 📁 Repository Structure

```text
bonus_ORG/
├── README.md               # Quick Start & Project Overview
├── docs/
│   ├── report.md           # 🎓 Full Academic Report for Professor
│   └── x64dbg-guide.md     # Step-by-Step Manual Debugger Guide
├── src/
│   ├── check.c             # Target Binary (Hashed Password Storage)
│   └── debug_patcher.c     # Automated Win32 Process Memory Patcher
└── tests/
    ├── test_harness.h      # Lightweight C Unit Test Framework
    ├── test_check.c        # Integration Tests for check.exe
    └── test_patcher_e2e.c  # Automated End-to-End Test for Patcher
```

---

## 🎓 Documentation & Reports

- **Academic Report**: Read [`docs/report.md`](docs/report.md) for the full theoretical report (Virtual Memory, PE Sections, Win32 APIs, Test Results).
- **Debugger Guide**: Read [`docs/x64dbg-guide.md`](docs/x64dbg-guide.md) for step-by-step x64dbg instructions.
