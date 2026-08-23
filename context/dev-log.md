# Dev Log

## 2026-08-23 16:51 - Project Completion & Verification

- **Target Executable (`src/check.c`)**: Built and verified. Hardcoded password `"123"` stored in mutable char array on stack. Includes optional `-d` daemon mode for background process testing.
- **Patcher Tool (`src/patcher.c`, `src/patcher_lib.c`, `src/patcher_lib.h`)**: Built and verified. Automatically finds process by name using `CreateToolhelp32Snapshot`, enumerates memory regions via `VirtualQueryEx`, searches for old password, and overwrites with new password via `WriteProcessMemory`. Enforces length safety ($\text{new\_len} \le \text{old\_len}$).
- **Test Suite (`tests/`)**: Built lightweight custom C test harness (`tests/test_harness.h`). Implemented 15 total unit and integration tests across 10 TDD cycles. All 15 tests passing cleanly!
- **Build System**: Created `Makefile` and `build.ps1` supporting GCC (MinGW-w64).
- **Documentation**:
  - `docs/cheat-engine-guide.md`: Step-by-step guide for manual GUI memory patching using Cheat Engine.
  - `docs/report.md`: Academic report for the professor covering virtual memory theory, Win32 APIs, implementation code walk-through, and comparative evaluation.
  - `README.md`: Quick start guide.
- **GitHub Repository**: Pushed to [karimabdelnabi05/bonus_ORG](https://github.com/karimabdelnabi05/bonus_ORG). Closed all 4 GitHub issues (#1, #2, #3, #4).
