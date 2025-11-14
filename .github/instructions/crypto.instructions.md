# Cryptography Challenge Instructions

Systematic approach to solving cryptography and encoding challenges.

## Initial Setup

```bash
mkdir -p ~/ctf/crypto/[challenge_name]
cd ~/ctf/crypto/[challenge_name]
touch analysis.md
```

## Step 1: Identify Cipher/Encoding Type

### Visual Inspection

**Check character set**:
- Only A-Z → Likely classical cipher (Caesar, Vigenère, substitution)
- A-Za-z0-9+/= → Base64
- 0-9a-fA-F → Hexadecimal
- Binary (0s and 1s) → Binary encoding
- Mix with special chars → Could be URL encoding, custom encoding

**Check patterns**:
```python
text = "ENCRYPTED_TEXT_HERE"

# Length analysis
print(f"Length: {len(text)}")
print(f"Divisible by 16: {len(text) % 16 == 0}")  # AES block size
print(f"Divisible by 8: {len(text) % 8 == 0}")   # DES block size

# Character frequency
from collections import Counter
freq = Counter(text.upper())
print(freq.most_common(10))
# English: E(12.7%), T(9.1%), A(8.2%), O(7.5%), I(7%), N(6.7%)
```

### Automated Detection

```python
import base64
import binascii
from urllib.parse import unquote

def detect_encoding(data):
    """Try common encodings"""
    results = {}
    
    # Base64
    try:
        decoded = base64.b64decode(data)
        if decoded.isprintable():
            results['base64'] = decoded.decode('utf-8', errors='ignore')
    except: pass
    
    # Hex
    try:
        decoded = binascii.unhexlify(data)
        if decoded.isprintable():
            results['hex'] = decoded.decode('utf-8', errors='ignore')
    except: pass
    
    # URL encoding
    results['url'] = unquote(data)
    
    # ROT13
    results['rot13'] = data.translate(
        str.maketrans(
            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
            'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
        )
    )
    
    return results
```

## Step 2: Classical Cryptanalysis

### Caesar/ROT Cipher

```python
def caesar_bruteforce(ciphertext):
    """Try all 26 possible shifts"""
    for shift in range(26):
        plaintext = ''
        for char in ciphertext:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                shifted = (ord(char) - base - shift) % 26
                plaintext += chr(shifted + base)
            else:
                plaintext += char
        print(f"Shift {shift:2d}: {plaintext}")
```

### Frequency Analysis

```python
def frequency_analysis(text):
    """Analyze character frequency"""
    from collections import Counter
    
    # Count letters only
    letters = [c.upper() for c in text if c.isalpha()]
    freq = Counter(letters)
    
    total = sum(freq.values())
    print("Letter frequencies:")
    for letter, count in freq.most_common():
        percentage = (count / total) * 100
        print(f"{letter}: {percentage:5.2f}% ({count})")
    
    # English frequency (for comparison)
    english_freq = {
        'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97,
        'N': 6.75, 'S': 6.33, 'H': 6.09, 'R': 5.99, 'D': 4.25
    }
```

### Substitution Cipher

```python
def substitution_attack(ciphertext):
    """Helper for manual substitution solving"""
    # Start with most common letters
    mapping = {}
    
    # E is most common in English
    # Find most common in ciphertext and map to E
    
    def apply_mapping(text, mapping):
        result = ''
        for char in text:
            result += mapping.get(char.upper(), char)
        return result
    
    # Interactive solving
    print("Ciphertext:", ciphertext)
    print("\nCurrent mapping:", mapping)
    print("Plaintext:", apply_mapping(ciphertext, mapping))
```

### Vigenère Cipher

```bash
# Use online tools or vigenere-solver
pip3 install vigenere

# Python
from vigenere import decode
key_length = detect_key_length(ciphertext)
key = break_vigenere(ciphertext, key_length)
plaintext = decode(ciphertext, key)
```

## Step 3: Modern Cryptanalysis

### RSA Attacks

**Step 1: Extract parameters**:
```python
# Common formats
n = 12345678...  # Modulus
e = 65537        # Public exponent
c = 98765432...  # Ciphertext

# Sometimes given as PEM:
from Crypto.PublicKey import RSA
with open('pubkey.pem', 'r') as f:
    key = RSA.import_key(f.read())
    n = key.n
    e = key.e
```

**Step 2: Check for small exponent**:
```python
import gmpy2

# If e=3 and no padding
plaintext = gmpy2.iroot(c, 3)[0]
print(f"Plaintext: {plaintext}")
```

**Step 3: Try factoring n**:
```bash
# Check factordb.com first
curl "http://factordb.com/api?query=$n"

# Or use automated tool
git clone https://github.com/RsaCtfTool/RsaCtfTool
cd RsaCtfTool
python3 RsaCtfTool.py -n [n] -e [e] --uncipher [c]
```

**Step 4: Manual factorization (if small)**:
```python
def fermat_factorization(n):
    """Works well when p and q are close"""
    import gmpy2
    a = gmpy2.isqrt(n) + 1
    b2 = a*a - n
    while not gmpy2.is_square(b2):
        a += 1
        b2 = a*a - n
    b = gmpy2.isqrt(b2)
    return a - b, a + b

p, q = fermat_factorization(n)
```

**Step 5: Decrypt**:
```python
from Crypto.Util.number import inverse, long_to_bytes

# Calculate private exponent
phi = (p - 1) * (q - 1)
d = inverse(e, phi)

# Decrypt
m = pow(c, d, n)
flag = long_to_bytes(m)
print(flag.decode())
```

### AES/DES Analysis

**ECB mode detection**:
```python
def detect_ecb(ciphertext, block_size=16):
    """Detect ECB mode by finding repeated blocks"""
    blocks = [ciphertext[i:i+block_size] 
              for i in range(0, len(ciphertext), block_size)]
    return len(blocks) != len(set(blocks))

# If ECB detected, exploit by:
# 1. Creating chosen plaintexts
# 2. Looking for block repetitions
```

**Padding oracle attack** (if applicable):
```bash
# Use padbuster
padbuster http://target/decrypt ENCRYPTED_COOKIE 16 \
  -cookies auth=ENCRYPTED_COOKIE
```

### Hash Cracking

**Identify hash type**:
```bash
# Use hash-identifier
hash-identifier

# Or hashid
hashid -m 'HASH_HERE'
```

**Crack with hashcat**:
```bash
# MD5
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt

# SHA1
hashcat -m 100 -a 0 hash.txt wordlist.txt

# SHA256
hashcat -m 1400 -a 0 hash.txt wordlist.txt

# NTLM
hashcat -m 1000 -a 0 hash.txt wordlist.txt

# With rules
hashcat -m 0 hash.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule
```

**Crack with John the Ripper**:
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
john --show hash.txt
```

**Check online databases**:
- CrackStation: https://crackstation.net/
- md5decrypt.net
- HashKiller

## Step 4: Custom/Obfuscated Crypto

### XOR Analysis

```python
def xor_bruteforce_single_byte(ciphertext):
    """Try all 256 single-byte XOR keys"""
    for key in range(256):
        plaintext = bytes([b ^ key for b in ciphertext])
        try:
            decoded = plaintext.decode('utf-8')
            if 'flag' in decoded.lower():
                print(f"Key {key:02x}: {decoded}")
        except:
            pass

def xor_bruteforce_multi_byte(ciphertext, key_length):
    """Bruteforce multi-byte XOR key"""
    # Use frequency analysis on each position
    key = []
    for i in range(key_length):
        # Extract bytes at positions i, i+keylen, i+2*keylen, ...
        chunk = bytes(ciphertext[i::key_length])
        # Bruteforce single byte for this chunk
        # ... (similar to single byte)
    return bytes(key)

# Automated XOR tools
# xortool -l [key_length] ciphertext.bin
```

### Analyzing Crypto Code

```python
# Look for:
# 1. Weak random number generation
import random  # NOT cryptographically secure
random.randint(0, 100)  # Predictable!

# Should use:
import secrets
secrets.randbelow(100)

# 2. Weak key derivation
key = hashlib.md5(password.encode()).digest()  # WEAK

# 3. Custom crypto implementations (likely broken)
def custom_encrypt(data, key):
    # Any custom implementation is suspect
    pass

# 4. ECB mode or no IV
cipher = AES.new(key, AES.MODE_ECB)  # BAD

# 5. Key reuse
```

## Step 5: Multi-Layer Decoding

Many challenges require multiple steps:

```python
import base64
import binascii

def decode_chain(data):
    """Try common decoding chains"""
    # Example: Base64 → Hex → ROT13
    
    step1 = base64.b64decode(data)
    print(f"After Base64: {step1}")
    
    step2 = binascii.unhexlify(step1)
    print(f"After Hex: {step2}")
    
    step3 = rot13(step2.decode())
    print(f"After ROT13: {step3}")
    
    return step3

# Use CyberChef for visual chaining:
# https://gchq.github.io/CyberChef/
```

## Common CTF Crypto Patterns

### Pattern 1: Weak RSA
- Small public exponent (e=3)
- Small prime factors
- Same n, different e (common modulus attack)
- Wiener's attack (small d)

### Pattern 2: Classical with Twist
- Caesar cipher with multiple passes
- Vigenère with keyword hint in challenge
- Substitution with partial plaintext known

### Pattern 3: Encoding Layers
- Base64 → Hex → Base64 → XOR
- Try CyberChef's "Magic" operation

### Pattern 4: Known Plaintext
- Flag format known: `flag{...}`
- Use known plaintext to recover key

## Tools Quick Reference

```bash
# CyberChef (online)
open https://gchq.github.io/CyberChef/

# RSA tools
python3 RsaCtfTool.py --help

# Hash cracking
hashcat --help
john --help

# XOR analysis
xortool --help

# Sage (advanced math)
sage
```

## Checklist

- [ ] Identified encoding/cipher type
- [ ] Tried automated detection tools
- [ ] Performed frequency analysis (if applicable)
- [ ] Checked for weak parameters (RSA: small e, factorable n)
- [ ] Tried online databases for hash cracking
- [ ] Considered multi-layer encoding
- [ ] Reviewed any provided source code for weaknesses
- [ ] Tested with known plaintext (flag format)
- [ ] Verified flag format before submission
