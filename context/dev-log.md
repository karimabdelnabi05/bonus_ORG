# Dev Log

## 2026-08-23 16:30 - Project scaffolding & TDD setup

- Created GitHub repo: karimabdelnabi05/bonus_ORG
- Created 4 GitHub issues as vertical slices
- Set up TDD plan with 10 RED-GREEN cycles
- Wrote all source files:
  - `src/check.c` - target program with hardcoded password "123"
  - `src/patcher_lib.h` - public interface for patcher library
  - `src/patcher_lib.c` - full implementation (validate, find process, scan memory, patch)
  - `src/patcher.c` - CLI entry point
- Wrote all test files:
  - `tests/test_harness.h` - custom lightweight C test framework
  - `tests/test_check.c` - integration tests for check.exe (cycles 1-2)
  - `tests/test_patcher.c` - unit + integration tests for patcher (cycles 3-10)
- Created build system: Makefile + build.ps1 (PowerShell alternative)
- Created README.md, .gitignore
- Installing MSYS2 for GCC compiler - awaiting completion
- NEXT: Compile and run RED-GREEN cycles once gcc is available
