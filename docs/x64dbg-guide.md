# x64dbg Guide: Changing a Hashed Password at Runtime

This guide explains how to use **x64dbg** to change the password in a running `check.exe` instance where the password is **hashed**.
You do NOT need to know the original password, the hash algorithm, or the stored hash value.

---

## How It Works (Theory)

When `check.exe` runs the comparison `if (input_hash == stored_hash)`, both values exist in CPU registers or on the stack at that exact moment.
By setting a breakpoint on the comparison instruction, you can:
1. See the stored hash value in a register or memory
2. Overwrite it with the hash of your desired new password

---

## Step-by-Step Instructions

### Step 1: Start `check.exe`
```powershell
.\build\check.exe
```

### Step 2: Launch x64dbg and Attach
1. Open **x64dbg**.
2. Press **`Alt + A`** (File -> Attach), select `check.exe`, click **Attach**.
3. Press **`F9`** until status bar says **`Running`**.

### Step 3: Find the Comparison Instruction
1. In the **CPU** tab, right-click -> **Search for** -> **All Modules** -> **String references**.
2. Look for the string `"Access Granted"`. Double-click it.
3. You will land near this assembly code:
   ```assembly
   call   hash_password          ; Hash user input
   cmp    eax, [rbp-0x8]         ; Compare input_hash (eax) vs stored_hash (stack)
   jne    0x00401080             ; Jump to "Access Denied" if not equal
   lea    rcx, "Access Granted"  ; Load "Access Granted" string
   ```
4. **Set a breakpoint** on the `cmp` instruction by clicking on that line and pressing **`F2`**.

### Step 4: Trigger the Breakpoint
1. Go to `check.exe` terminal and type your **desired new password** (e.g., `mypass`). Press Enter.
2. x64dbg will pause at the `cmp` instruction.

### Step 5: Read the Register Values
At the breakpoint, look at the **Registers** pane (top-right):
- **`EAX`** (or `RAX`) = `input_hash` (the hash of `"mypass"` that you just typed)
- The `cmp` instruction's second operand (e.g., `[rbp-0x8]`) = `stored_hash` (the unknown hash)

### Step 6: Overwrite the Stored Hash
1. In the **Dump** tab, press **`Ctrl + G`** (Go to address).
2. Type the address of the stored hash (the memory operand from the `cmp` instruction, e.g., `rbp-8`).
3. You will see the stored hash bytes in the Dump window.
4. Right-click -> **Binary** -> **Edit...** (`Ctrl + E`).
5. Copy the value from `EAX` (the input hash) into these bytes.
6. Click **OK**.

### Step 7: Resume and Verify
1. Remove the breakpoint by pressing **`F2`** on the `cmp` line again.
2. Press **`F9`** to resume execution.
3. In `check.exe` terminal:
   - Type **`mypass`** -> **`Access Granted`**!
   - Type the old password -> **`Access Denied`**!
