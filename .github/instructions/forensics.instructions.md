# Digital Forensics Challenge Instructions

Systematic approach to forensics, steganography, memory analysis, and PCAP challenges.

## Initial Setup

```bash
mkdir -p ~/ctf/forensics/[challenge_name]
cd ~/ctf/forensics/[challenge_name]
touch findings.md
```

## Step 1: File Analysis Basics

### Initial File Identification

```bash
# Basic file info
file suspicious_file
file -i suspicious_file  # MIME type

# Check for multiple files concatenated
binwalk suspicious_file

# View hex dump
xxd suspicious_file | head -20
hexdump -C suspicious_file | less

# Check for strings
strings suspicious_file
strings -n 10 suspicious_file  # Min length 10
strings -e l suspicious_file   # 16-bit little-endian
strings -e b suspicious_file   # 16-bit big-endian
```

### File Metadata

```bash
# EXIF data (images, documents, PDFs)
exiftool suspicious_file
exiftool -a -G1 suspicious_file  # All tags with groups

# Check for hidden metadata
exiftool -s -G suspicious_file

# PDF analysis
pdfinfo document.pdf
pdftotext document.pdf - | grep -i flag

# Office document metadata
olevba suspicious.docx
olevba suspicious.xlsm  # Check for macros
```

### File Carving

```bash
# Extract embedded files
binwalk -e suspicious_file
# Creates _suspicious_file.extracted/ directory

# Foremost (recover deleted files)
foremost -i disk_image.dd -o output/
# Recovers by file signature

# Scalpel (more configurable)
scalpel -b -o output/ disk_image.dd

# Strings with context
strings -t d suspicious_file > strings_output.txt
# -t d shows decimal offset
```

## Step 2: Steganography

### Image Steganography

**Visual inspection**:
```bash
# View image properties
identify image.png
identify -verbose image.png

# Compare LSB (Least Significant Bit)
# Use StegSolve (GUI tool) or:
convert image.png -depth 1 lsb.png
```

**Check image end**:
```bash
# Files appended to image
tail -c 1000 image.jpg | xxd
binwalk image.jpg

# Extract
dd if=image.jpg of=hidden.zip bs=1 skip=OFFSET
```

**Steghide** (password-based):
```bash
# Try without password
steghide extract -sf image.jpg

# With password
steghide extract -sf image.jpg -p PASSWORD

# Check info
steghide info image.jpg
```

**Zsteg** (PNG/BMP analysis):
```bash
gem install zsteg
zsteg image.png
zsteg -a image.png  # All extraction methods

# Try specific bit orders
zsteg -b 1 image.png
zsteg -o msb image.png
```

**Stegsnow** (whitespace steganography):
```bash
# Extract from text file
stegsnow -C suspicious.txt

# With password
stegsnow -C -p PASSWORD suspicious.txt
```

### Audio Steganography

```bash
# Spectral analysis (visualize)
sox audio.wav -n spectrogram -o spectrogram.png

# Or use Audacity (GUI)
audacity audio.wav
# Analyze > Plot Spectrum
# View > Spectrogram

# Check for LSB audio encoding
# Use Sonic Visualizer or DeepSound
```

### Other Steganography

**QR codes**:
```bash
# Scan QR code from image
zbarimg image.png
```

**Barcodes**:
```bash
# Use zbar
zbarcam  # For webcam
zbarimg barcode.png
```

## Step 3: Memory Forensics

### Volatility 3 Analysis

**Step 1: Identify image info**:
```bash
python3 vol.py -f memory.dmp windows.info
python3 vol.py -f memory.dmp linux.info
```

**Step 2: List processes**:
```bash
# Windows
python3 vol.py -f memory.dmp windows.pslist
python3 vol.py -f memory.dmp windows.pstree
python3 vol.py -f memory.dmp windows.psscan  # Find hidden

# Linux
python3 vol.py -f memory.dmp linux.pslist
```

**Step 3: Network connections**:
```bash
# Windows
python3 vol.py -f memory.dmp windows.netscan

# Linux
python3 vol.py -f memory.dmp linux.netstat
```

**Step 4: Extract process memory**:
```bash
# Dump specific process
python3 vol.py -f memory.dmp -o dump/ windows.memmap --pid 1234 --dump

# Dump all processes
python3 vol.py -f memory.dmp -o dump/ windows.pslist --dump
```

**Step 5: Command line history**:
```bash
# Windows
python3 vol.py -f memory.dmp windows.cmdline

# Bash history (Linux)
python3 vol.py -f memory.dmp linux.bash
```

**Step 6: Files and registry**:
```bash
# List files
python3 vol.py -f memory.dmp windows.filescan

# Dump specific file
python3 vol.py -f memory.dmp -o dump/ windows.dumpfiles --virtaddr 0xADDRESS

# Registry
python3 vol.py -f memory.dmp windows.registry.hivelist
python3 vol.py -f memory.dmp windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"
```

**Step 7: Malware hunting**:
```bash
# Suspicious processes
python3 vol.py -f memory.dmp windows.malfind

# DLL analysis
python3 vol.py -f memory.dmp windows.dlllist --pid 1234
```

### Strings Analysis on Memory

```bash
# Extract all strings
strings -e l memory.dmp > strings_unicode.txt
strings -a memory.dmp > strings_ascii.txt

# Search for flags
grep -i "flag\|password\|secret" strings_*.txt

# URL extraction
grep -Eo 'https?://[^ ]+' strings_ascii.txt
```

## Step 4: Network Forensics (PCAP)

### Wireshark Analysis

**Initial inspection**:
```bash
# Command line
tshark -r capture.pcap

# Basic stats
capinfos capture.pcap
tshark -r capture.pcap -q -z io,phs  # Protocol hierarchy
```

**Filter for common protocols**:
```
# HTTP traffic
http

# DNS queries
dns

# FTP
ftp or ftp-data

# Suspicious traffic
tcp.port == 4444 or tcp.port == 1337

# Search for keywords
frame contains "flag"
frame contains "password"
```

**Export objects**:
```
File > Export Objects > HTTP
File > Export Objects > SMB
File > Export Objects > FTP-DATA
```

**Follow streams**:
```bash
# TCP stream (shows conversation)
# Right-click packet > Follow > TCP Stream

# Command line
tshark -r capture.pcap -z follow,tcp,ascii,0
```

### Tshark Command Examples

```bash
# Extract HTTP requests
tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri

# Extract files from HTTP
tshark -r capture.pcap --export-objects http,extracted/

# DNS queries
tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name

# Extract credentials
tshark -r capture.pcap -Y "http.request.method == POST" -T fields -e http.file_data

# Search for specific strings
tshark -r capture.pcap -Y 'frame contains "flag"'
```

### Zeek (Bro) Analysis

```bash
# Process PCAP
zeek -r capture.pcap

# Creates log files:
# - conn.log (connections)
# - http.log (HTTP)
# - dns.log (DNS)
# - files.log (file transfers)

# Analyze HTTP log
cat http.log | zeek-cut method host uri | grep -i flag

# Extract files
zeek -r capture.pcap extract-all-files.bro
```

## Step 5: Disk Forensics

### Mounting Disk Images

```bash
# Mount raw disk image
mkdir /mnt/evidence
mount -o ro,loop disk.img /mnt/evidence

# For E01/EWF (EnCase)
ewfmount image.E01 /mnt/ewf
mount -o ro,loop /mnt/ewf/ewf1 /mnt/evidence
```

### Autopsy (GUI Forensics)

```bash
# Launch Autopsy
autopsy

# Create case
# Add data source (disk image)
# Run ingest modules
# Review artifacts
```

### File System Timeline

```bash
# Create timeline
fls -r -m / disk.img > timeline.body
mactime -b timeline.body -d > timeline.csv

# Search timeline
grep "flag\|secret\|password" timeline.csv
```

### Registry Analysis (Windows)

```bash
# Extract registry from disk
# Look in: /Windows/System32/config/

# SAM (user accounts)
# SYSTEM (system config)
# SOFTWARE (installed programs)
# SECURITY (security policy)

# Use RegRipper
rip.pl -r SOFTWARE -p soft_run
```

## Step 6: Document/PDF Forensics

### PDF Analysis

```bash
# PDF structure
pdfinfo document.pdf
pdffonts document.pdf
pdfimages document.pdf -all images/

# JavaScript in PDF
pdf-parser.py --search javascript document.pdf
pdf-parser.py -f -w document.pdf

# Embedded files
pdfdetach -list document.pdf
pdfdetach -saveall document.pdf
```

### Office Document Analysis

```bash
# Extract XML from Office docs (.docx, .xlsx)
unzip document.docx -d extracted/
# Check extracted/word/document.xml

# Check for macros
olevba document.docm
olevba -a document.xlsm  # Analyze all

# Extract VBA code
olevba -c document.docm > vba_code.vb
```

## Common CTF Forensics Patterns

### Pattern 1: Multi-Layer Hiding
- ZIP inside image
- Encrypted archive with password hint
- Steganography in extracted file

```bash
# Check for ZIP magic bytes in any file
xxd file | grep "504b 0304"  # PK header

# Try to extract as ZIP regardless of extension
unzip file.jpg
7z x file.png
```

### Pattern 2: Deleted/Hidden Data
- Slack space in file system
- Deleted but recoverable files
- Hidden partitions

```bash
# Check file size vs allocated
ls -lh file
du -h file

# Hexdump the end
tail -c 5000 file | xxd
```

### Pattern 3: Password Hints
- Check image EXIF for password
- Check PDF metadata
- Look in other challenge files

### Pattern 4: Network Exfiltration
- Data in DNS queries
- Base64 in HTTP headers
- Unusual protocols (ICMP data)

```bash
# Extract DNS queries
tshark -r capture.pcap -Y dns -T fields -e dns.qry.name | sort -u

# Decode if base64
echo "BASE64STRING" | base64 -d
```

## Specialized Tools

```bash
# Bulk Extractor (fast carving)
bulk_extractor -o output/ disk.img

# Photorec (GUI file recovery)
photorec disk.img

# TestDisk (partition recovery)
testdisk disk.img

# Rekall (memory analysis alternative to Volatility)
rekall -f memory.dmp

# NetworkMiner (PCAP analysis GUI)
NetworkMiner
```

## Checklist

- [ ] Identified file type and checked for mismatches
- [ ] Extracted metadata (EXIF, pdfinfo, etc.)
- [ ] Checked for embedded/appended files (binwalk)
- [ ] Tried steganography tools appropriate for file type
- [ ] Analyzed strings output for keywords
- [ ] For memory dumps: ran volatility plugins (pslist, netscan, filescan)
- [ ] For PCAP: filtered protocols, followed streams, exported objects
- [ ] Checked for password hints in metadata or other files
- [ ] Carved deleted or hidden files
- [ ] Verified flag format before submission

## Resources

- Volatility cheat sheet: https://github.com/sans-dfir/sift-cheatsheet
- Wireshark display filters: https://wiki.wireshark.org/DisplayFilters
- File signatures: https://en.wikipedia.org/wiki/List_of_file_signatures
