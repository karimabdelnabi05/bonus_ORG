# x64dbg Step-by-Step Guide: Manual Runtime Memory Patching

This guide documents the exact manual workflow for inspecting and patching the password in a running instance of `check.exe` using **x64dbg**, an open-source x64/x32 debugger for Windows.

---

## Overview

x64dbg allows developers and security researchers to attach to a running Windows process, inspect its Virtual Address Space (VAS), view machine code disassembly, and edit memory bytes live at runtime.

---

## Prerequisites

1. **Target Executable**: Compile `check.exe` using GCC or use the pre-built binary in `build/check.exe`.
2. **x64dbg Debugger**: Installed on your system (located at `C:\Users\karee\AppData\Local\Microsoft\WinGet\Packages\x64dbg.x64dbg_...`).

---

## Step-by-Step Instructions

### Step 1: Start `check.exe`
Open PowerShell or Command Prompt and run:
```powershell
.\build\check.exe
```
*Keep this terminal window open.*

---

### Step 2: Launch x64dbg and Attach to Process
1. Open **x64dbg**.
2. Go to **File $\rightarrow$ Attach** (or press `Alt + A`).
3. Select `check.exe` from the process list and click **Attach**.
4. Press **`F9`** (Run) until the status bar at the bottom-left turns blue/yellow and says **`Running`**.

---

### Step 3: Search Memory for Password Pattern
1. Click the **Memory Map** tab (or press `Alt + M`).
2. Right-click anywhere in the memory regions table $\rightarrow$ click **Find Pattern** (or press `Ctrl + B`).
3. In the search box, select **ASCII** and type: **`123`**.
4. Click **OK**.
5. A new tab titled **`Pattern: 313233`** will open listing all memory match addresses.

---

### Step 4: Jump to Memory Dump and Edit Bytes
1. **Double-click** the first result line in the `Pattern: 313233` tab.  
   *(x64dbg will automatically jump to that address in the **Dump 1** window at the bottom-left).*
2. In the **Dump 1** window, highlight the bytes `31 32 33` (`"123"`).
3. Right-click the highlighted bytes $\rightarrow$ **Binary** $\rightarrow$ **Edit...** (or press `Ctrl + E`).
4. In the ASCII input field of the edit pop-up, change `123` to **`abc`**.
5. Click **OK**.

---

### Step 5: Resume Execution and Verify
1. Press **`F9`** in x64dbg to keep `check.exe` running.
2. Return to your `check.exe` terminal window:
   - Type **`123`** $\rightarrow$ **`Access Denied`**
   - Type **`abc`** $\rightarrow$ **`Access Granted`**!

---

## Summary of Techniques Supported in x64dbg

| Technique | Description | Requires Knowing Password? |
|---|---|---|
| **Data Memory Patching** | Finding ASCII `"123"` in RAM and overwriting bytes to `"abc"` | **Yes** (searches for old string) |
| **Instruction Patching** | Locating `strcmp` / `jne` conditional jump and patching `jne` $\rightarrow$ `nop` | **No** (grants access for ANY input!) |
