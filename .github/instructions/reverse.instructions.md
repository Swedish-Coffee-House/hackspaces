# Reverse Engineering Instructions

Systematic approach to reverse engineering binaries, analyzing obfuscated code, and understanding program behavior.

## Initial Setup

```bash
mkdir -p ~/ctf/reverse/[challenge_name]
cd ~/ctf/reverse/[challenge_name]
touch analysis.md strings_output.txt disasm_notes.txt
```

## Step 1: Pre-Analysis

### Basic File Analysis

```bash
# File type identification
file binary_file
file -i binary_file  # MIME type

# Check architecture and compilation
file binary_file
# Expected output: ELF 64-bit LSB executable, x86-64
# Or: PE32 executable (for Windows)

# Check if stripped
file binary_file | grep stripped
# stripped = no debugging symbols
# not stripped = has symbols (easier to analyze)

# List symbols (if not stripped)
nm binary_file
nm -D binary_file  # Dynamic symbols only

# Check dependencies
ldd binary_file
# Shows required shared libraries

# Check for packing/obfuscation
upx -t binary_file
# If packed with UPX

# Strings analysis
strings binary_file
strings -n 10 binary_file  # Minimum length 10
strings -e l binary_file   # 16-bit little-endian
strings binary_file | grep -i "flag\|password\|secret"
```

### Security Mechanisms

```bash
# Check protections (checksec)
checksec --file=binary_file

# Look for:
# - RELRO: Full/Partial/No (prevents GOT overwrite)
# - Stack: Canary found/No canary (stack protection)
# - NX: NX enabled/disabled (no execute on stack)
# - PIE: PIE enabled/No PIE (position independent)
# - FORTIFY: Enabled/Disabled (additional checks)

# Manual check for NX
readelf -l binary_file | grep -A 1 GNU_STACK

# Check for PIE
readelf -h binary_file | grep Type
# DYN = PIE enabled, EXEC = No PIE
```

### Running the Binary

```bash
# Run normally
./binary_file

# With ltrace (library calls)
ltrace ./binary_file

# With strace (system calls)
strace ./binary_file
strace -e trace=open,read,write ./binary_file

# With input redirection
echo "test input" | ./binary_file
./binary_file < input.txt

# Monitor network activity
strace -e trace=network ./binary_file
```

## Step 2: Static Analysis with Ghidra

### Setup Ghidra Project

1. Launch Ghidra:
```bash
ghidraRun
```

2. Create new project:
   - File → New Project
   - Non-Shared Project
   - Choose directory and name

3. Import binary:
   - File → Import File
   - Select binary
   - Use default options (or specify architecture if needed)

4. Analyze:
   - Double-click binary to open CodeBrowser
   - Analysis → Auto Analyze
   - Accept default analyzers
   - Wait for completion

### Navigating Ghidra

**Find main function**:
- Symbol Tree → Functions → main
- Or search: Search → For Strings → "main"
- Entry point is often `_start` → calls `__libc_start_main(main, ...)`

**Decompilation**:
- Click on function in Listing window
- View decompiled C code in Decompile window
- Right-click variables → Rename (R key)
- Right-click functions → Edit Function Signature

**Key analysis areas**:
```c
// Look for:
// 1. Input functions
scanf("%s", buffer);
fgets(buffer, size, stdin);
read(fd, buffer, size);

// 2. Comparison logic
if (input == expected_value)
if (strcmp(input, "correct") == 0)

// 3. Flag construction
sprintf(flag, "flag{%s}", secret);

// 4. Interesting strings
char *secret = "hidden_value";
```

### Following Program Flow

**Cross-references**:
- Right-click function/variable → References → Find References To
- Shows where it's called/used

**Control flow**:
- Window → Function Graph
- Visual representation of execution paths
- Helps understand complex conditionals

**Data flow**:
- Track variable usage through function
- Use decompiler's highlighting (click variable)

### Extracting Information

```c
// Common patterns:

// Pattern 1: Hardcoded flag
char flag[] = "flag{hardcoded_secret}";

// Pattern 2: XOR encoding
for (i = 0; i < len; i++) {
    decoded[i] = encoded[i] ^ key;
}

// Pattern 3: Character-by-character check
if (input[0] == 'f' && input[1] == 'l' && 
    input[2] == 'a' && input[3] == 'g')

// Pattern 4: Mathematical check
if ((input[0] * 3 + 7) == 310)  // input[0] = 101 = 'e'

// Pattern 5: Custom algorithm
int check(char *input) {
    int sum = 0;
    for (int i = 0; input[i]; i++)
        sum += input[i] * (i + 1);
    return sum == 12345;
}
```

### Scripting Ghidra

**Python script** (Ghidra script):
```python
# Script to extract XOR key and decode

# Get current program
program = getCurrentProgram()

# Find data at address
addr = toAddr(0x00401000)
length = 32

# Read bytes
data = getBytes(addr, length)

# Process
key = 0x42
decoded = ''.join(chr(b ^ key) for b in data)
print("Decoded: " + decoded)
```

## Step 3: Dynamic Analysis with GDB/pwndbg

### Basic GDB Commands

```bash
# Start GDB
gdb ./binary_file
gdb -q ./binary_file  # Quiet mode

# Set breakpoint
break main
break *0x400123  # At specific address
break function_name

# Run
run
run arg1 arg2
run < input.txt

# Step through code
stepi  # Step one instruction (si)
nexti  # Next instruction, skip calls (ni)
step   # Step one line (s)
next   # Next line, skip calls (n)
continue  # Continue execution (c)

# Examine registers
info registers
info registers rax rbx rcx

# Examine memory
x/10x $rsp        # 10 hex words at stack pointer
x/s 0x400500      # String at address
x/10i $rip        # 10 instructions at current position
x/10gx $rsp       # 10 giant (64-bit) hex values

# Set values
set $rax = 0x1234
set {int}0x400500 = 42

# Disassemble
disassemble main
disas function_name
```

### pwndbg Enhancements

```bash
# pwndbg is loaded automatically if installed

# Enhanced display
context  # Show registers, stack, code, backtrace

# Search memory
search "flag"
search -t string "flag"
search -t bytes 0x41424344

# Heap analysis
heap
bins
vis_heap_chunks

# ROP gadgets
rop --grep "pop rdi"
```

### Solving Challenges Dynamically

**Example 1: Find comparison value**:
```bash
# Set breakpoint at comparison
gdb ./binary
break *0x40062a  # Address of cmp instruction

# Run
run

# Check what's being compared
x/s $rdi  # First argument
x/s $rsi  # Second argument
# Or check registers shown in context
```

**Example 2: Bypass checks**:
```bash
# Set breakpoint before check
break *0x400630

# Run
run
# Enter any input

# Force jump
set $rip = 0x400650  # Skip to success code
# Or modify zero flag
set $eflags |= (1 << 6)  # Set ZF

# Continue
continue
```

**Example 3: Extract flag from memory**:
```bash
# Set breakpoint after flag is built
break *0x400700

run
# Let program build flag in memory

# Find flag in memory
search "flag{"
# Or if you know the address
x/s 0x601040
```

## Step 4: Dealing with Obfuscation

### Packed Binaries

```bash
# Detect packing
upx -t binary_file
strings binary_file | less  # Packed = few strings

# Unpack UPX
upx -d binary_file -o unpacked_file

# Manual unpacking (if custom packer)
# 1. Run in debugger
# 2. Let it unpack itself in memory
# 3. Dump unpacked memory
gdb ./packed_binary
break *0x... (OEP - Original Entry Point)
run
dump memory unpacked.bin 0x400000 0x500000
```

### Anti-Debugging

```bash
# Common techniques:
# 1. ptrace detection
# 2. Timing checks
# 3. Debugger process detection

# Bypass with patching
# Use Ghidra or radare2 to:
# - NOP out detection
# - Patch conditional jumps
# - Modify constants
```

### Obfuscated Code

**Control flow flattening**:
- Main logic in switch/case blocks
- State machine pattern
- Solution: Use symbolic execution (angr)

**String obfuscation**:
```python
# Strings decoded at runtime
# Find decoding routine in Ghidra
# Replicate in Python

def decode_string(encoded, key):
    decoded = ""
    for i, c in enumerate(encoded):
        decoded += chr(ord(c) ^ key[i % len(key)])
    return decoded
```

**VM-based obfuscation**:
- Custom virtual machine interprets bytecode
- Very difficult to reverse manually
- Focus on input/output behavior instead

## Step 5: Alternative Tools

### radare2

```bash
# Open binary
r2 ./binary_file

# Analyze
aaa  # Analyze all

# List functions
afl

# Disassemble function
pdf @main

# Visual mode
VV  # Visual graph mode

# Seek to address
s 0x400500

# Print strings
iz

# Search
/ flag  # Search for string

# Quit
q
```

### Hopper (macOS)

- GUI disassembler
- Good for macOS/iOS binaries
- Cleaner decompilation than Ghidra for some binaries

### Binary Ninja

- Modern RE platform
- Better decompilation for some binaries
- Python API for scripting

## Step 6: Deobfuscation & Script Extraction

### Python Bytecode (.pyc)

```bash
# Decompile Python bytecode
uncompyle6 script.pyc > script.py
# Or
decompyle3 script.pyc > script.py
```

### Java (.class, .jar)

```bash
# Decompile Java
jadx -d output/ app.jar
# Or use JD-GUI (graphical)

# Examine JAR contents
unzip app.jar -d extracted/
```

### .NET (C#)

```bash
# Use dnSpy (Windows) or ILSpy
# Or command line:
ilspycmd app.exe -o output/
```

### JavaScript Obfuscation

```javascript
// Use online tools:
// - https://deobfuscate.io/
// - https://matthewfl.com/unPacker.html

// Or Node.js de-obfuscation
// Install: npm install -g js-beautify
js-beautify obfuscated.js > readable.js
```

## Common Reverse Engineering Patterns

### Pattern 1: Serial/License Check
```c
bool check_license(char *input) {
    // Generate expected serial from algorithm
    // Compare with input
    int expected = 0;
    for (int i = 0; i < 8; i++)
        expected += (input[i] ^ 0x42) * (i + 1);
    return expected == 1337;
}
// Solution: Reverse the algorithm or brute force
```

### Pattern 2: Encoded Flag
```c
char encoded[] = "\x67\x7b\x63\x65...";
char key = 0x12;
for (int i = 0; i < sizeof(encoded); i++)
    printf("%c", encoded[i] ^ key);
// Solution: Extract encoded data and key, decode
```

### Pattern 3: Flag Construction
```c
sprintf(flag, "flag{%s_%d_%s}", part1, number, part2);
// Solution: Find values of part1, number, part2 in binary
```

## Checklist

- [ ] Identified binary type and architecture
- [ ] Checked security protections (checksec)
- [ ] Ran strings analysis
- [ ] Executed binary with ltrace/strace
- [ ] Loaded into Ghidra and analyzed
- [ ] Found main function and key logic
- [ ] Identified input/output functions
- [ ] Tracked flag construction or comparison
- [ ] Used GDB to verify dynamic behavior
- [ ] Checked for packing/obfuscation
- [ ] Extracted or computed flag
- [ ] Verified flag format before submission

## Resources

- Ghidra documentation: https://ghidra-sre.org/
- pwndbg commands: https://github.com/pwndbg/pwndbg/blob/dev/FEATURES.md
- radare2 book: https://book.rada.re/
- Reverse engineering challenges: https://crackmes.one/
