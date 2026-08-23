# Cheat Engine Guide: Manual Runtime Memory Patching

This guide explains how to use **Cheat Engine** to find and replace the password string in a running instance of `check.exe` at runtime.

---

## Overview

Cheat Engine is a standard memory scanner and debugger for Windows. It allows you to search the RAM of any running process for specific values (strings, integers, floats, byte sequences) and modify them in place without closing or recompiling the target application.

---

## Prerequisites

1. **Target Executable**: Compile `check.exe` using GCC or download the compiled binary.
   ```cmd
   make check
   ```
2. **Cheat Engine**: Download and install Cheat Engine from [cheatengine.org](https://www.cheatengine.org/).

---

## Step-by-Step Instructions

### Step 1: Start `check.exe`
Open a command prompt or terminal and launch `check.exe`:
```cmd
.\build\check.exe
```
The terminal will display:
```text
=== Secure Access Terminal ===
(Press Ctrl+C to exit)

Enter password:
```
*Leave this terminal window open.*

---

### Step 2: Open Cheat Engine and Attach to Process
1. Open **Cheat Engine**.
2. Click the **Monitor/Computer Icon** (top-left corner, glowing red/green) to open the Process List.
3. In the **Process List** window:
   - Select the **Processes** tab.
   - Find and click `check.exe`.
   - Click **Open**.

---

### Step 3: Configure Scan Settings for String Search
In the main Cheat Engine window (right pane):
1. Change **Value Type** from `4 Bytes` to **`String`**.
2. A **Text** box will appear. Type the original password: **`123`**.
3. Check the options:
   - **Case sensitive**: Checked (optional for "123", but good practice).
   - **Unicode/UTF-16**: Unchecked (since `check.c` uses standard ANSI 1-byte C strings).
4. Click **First Scan**.

---

### Step 4: Inspect Search Results
After the scan completes:
- The left pane will list all memory addresses where `"123"` was found (typically 1 to 5 occurrences).
- Look at the **Address**, **Value**, and **Type** columns.

---

### Step 5: Modify the String in Memory
1. Double-click the address corresponding to `check.exe` memory (or select all and press the red arrow to move them to the lower address table).
2. In the bottom table, double-click the **Value** entry (`123`).
3. In the dialog box that appears, enter your new password (e.g., **`abc`**).
4. Click **OK**.

> **Important Constraint**: The new password string must be **the same length or shorter** than the old password (e.g., 3 characters for `"123"` -> `"abc"` or `"ab"`). If you write a longer string (e.g., `"abcdef"`), you will overwrite adjacent stack memory and cause a buffer overflow or crash.

---

### Step 6: Verify the Patch
1. Switch back to your `check.exe` terminal window.
2. Type the old password: **`123`** → Response: **`Access Denied`**.
3. Type the new password: **`abc`** → Response: **`Access Granted`**!

---

## Technical Explanation & Theory

### How Cheat Engine Scans Memory
Cheat Engine calls the Windows API `VirtualQueryEx` to enumerate every committed memory region (`MEM_COMMIT`) in the target process address space. For every readable region, it reads the memory into its own buffer using `ReadProcessMemory` and performs a byte pattern search for `"123"` (ASCII bytes `0x31 0x32 0x33`).

### How Cheat Engine Modifies Memory
When you change the value in Cheat Engine, it calls `WriteProcessMemory`. If the target memory page is read-only or copy-on-write, Cheat Engine automatically calls `VirtualProtectEx` to temporarily add `PAGE_EXECUTE_READWRITE` permissions before writing.

---

## Troubleshooting

| Problem | Cause | Solution |
|---|---|---|
| Process `check.exe` not found | `check.exe` is not running or running under different user rights | Run Cheat Engine as Administrator or restart `check.exe` |
| Scan returns 0 results | Value Type is not set to `String`, or Unicode box is checked | Set Value Type to `String` and uncheck UTF-16 |
| Target process crashes on patch | New password was longer than old password, overwriting adjacent memory | Keep new password length <= old password length |
