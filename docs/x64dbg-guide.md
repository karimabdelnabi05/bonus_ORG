# x64dbg Guide: Finding the Stored Hash in check.exe

This guide shows how to use x64dbg to reverse-engineer `check.exe` and find:
1. The stored hash value
2. The hash algorithm
3. The file offset where the hash is stored

## Prerequisites

- Download x64dbg from: https://x64dbg.com
- Compile `check.exe`: `gcc -o check.exe src/check.c`

## Step 1: Open check.exe in x64dbg

1. Launch **x64dbg** (use `x96dbg.exe`, then select **x64**).
2. Go to **File > Open** and select `check.exe`.
3. x64dbg will break at the entry point.

## Step 2: Find the Main Function

1. Press **Ctrl+G** (Go to address).
2. Type `main` and press Enter.
3. You should see the `main` function's assembly code.

## Step 3: Find the Hash Comparison

Look for a `cmp` (compare) instruction near a conditional jump (`je` or `jne`).
This is where the program compares `hash(input)` against `stored_hash`:

```asm
call    <hash_password>       ; hash the user input
mov     [rbp+xxx], eax        ; store result in input_hash
mov     ecx, [<stored_hash>]  ; load stored_hash from .data section
cmp     eax, ecx              ; compare input_hash == stored_hash
jne     <access_denied>       ; jump if not equal
```

The value loaded from `.data` is the stored hash: **`0x17F35C47`** = **`401824839`** in decimal.

## Step 4: Find the Hash in the .data Section

1. Go to the **Memory Map** tab (Alt+M).
2. Find the `.data` section of `check.exe`.
3. Double-click to view its contents in the hex dump.
4. Look for the bytes: **`47 5C F3 17`** (little-endian representation of `401824839`).

```
Address          Hex                                      ASCII
00007FF7xxxx8000 47 5C F3 17 00 00 00 00 ...             G\..
```

The stored hash is at file offset **`0x8000`** in the `.data` section.

## Step 5: Identify the Hash Algorithm

Go back to the `hash_password` function and examine its assembly:

```asm
mov     eax, 1505h            ; hash = 5381 (0x1505)
.loop:
movzx   ecx, byte [rdi]      ; c = *str
test    ecx, ecx              ; if c == 0, break
je      .done
shl     eax, 5                ; hash << 5
add     eax, eax_prev         ; (hash << 5) + hash = hash * 33
add     eax, ecx              ; hash * 33 + c
inc     rdi                   ; str++
jmp     .loop
```

The pattern `hash = 5381`, `hash * 33 + c` identifies this as the **djb2** algorithm.

## Step 6: Patch Using the Patcher

Now that you know:
- **Hash algorithm**: djb2
- **Stored hash value**: 401824839
- **Location**: `.data` section at offset `0x8000`

Run the patcher:

```powershell
patcher.exe check.exe 401824839 mypass
```

This replaces bytes `47 5C F3 17` with `A2 FC ED 0E` (`hash("mypass")`).

## Alternative: Manual Patch in x64dbg

Instead of using the patcher program, you can patch directly in x64dbg:

1. In the hex dump, right-click the bytes `47 5C F3 17`.
2. Select **Binary > Edit**.
3. Change to: `A2 FC ED 0E` (little-endian of `djb2("mypass")` = `250477730`).
4. Go to **File > Patch file** to save the modified binary.
