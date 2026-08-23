# Dev Log

## 2026-08-24 01:13 - Hashed Password Branch

- **Target Executable (`src/check.c`)**: Uses djb2 hash. Password `"s3cr3t"` is stored only as hash value `401824839`. Plaintext never appears in memory or binary (verified by test).
- **Debug Patcher (`src/debug_patcher.c`)**: Uses Memory Snapshot Differencing to locate stored hash in RAM without knowing the password, hash algorithm, or hash value. Works by comparing two memory snapshots taken after different wrong password inputs.
- **Test Suite (`tests/`)**: 3 integration tests passing (correct password grants access, wrong password denies, plaintext not in binary).
- **Documentation**:
  - `docs/x64dbg-guide.md`: Manual approach using x64dbg debugger for hashed passwords.
  - `docs/report.md`: Academic report for professor covering memory snapshot differencing theory and implementation.
- **GitHub Repository**: Pushed to [karimabdelnabi05/bonus_ORG](https://github.com/karimabdelnabi05/bonus_ORG) on branch `hashed-password`.
