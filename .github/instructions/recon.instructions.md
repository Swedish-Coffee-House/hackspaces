# Reconnaissance & OSINT Instructions

Systematic approach to reconnaissance, information gathering, and Open Source Intelligence (OSINT) challenges.

## Initial Setup

```bash
mkdir -p ~/ctf/recon/[challenge_name]
cd ~/ctf/recon/[challenge_name]
touch findings.md targets.txt services.txt
```

## Step 1: Network Reconnaissance

### Host Discovery

```bash
# Ping sweep (find live hosts)
nmap -sn 10.0.0.0/24
nmap -sn -T4 192.168.1.0/24 -oG live_hosts.txt

# Extract live IPs
grep "Up" live_hosts.txt | cut -d" " -f2 > targets.txt

# TCP SYN ping (bypass ICMP filtering)
nmap -sn -PS22,80,443 10.0.0.0/24

# ARP scan (local network)
sudo arp-scan -l
sudo arp-scan 192.168.1.0/24
```

### Port Scanning

**Quick scan** (most common ports):
```bash
nmap -F TARGET_IP
nmap -T4 --top-ports 1000 TARGET_IP
```

**Comprehensive scan**:
```bash
# All TCP ports
nmap -p- TARGET_IP -T4 -oA full_tcp_scan

# Version detection
nmap -p 80,443,22,21 -sV TARGET_IP

# OS detection
sudo nmap -O TARGET_IP

# Aggressive scan (OS + version + scripts + traceroute)
sudo nmap -A TARGET_IP
```

**Stealth scanning**:
```bash
# SYN scan (stealth)
sudo nmap -sS TARGET_IP

# Fragmented packets
sudo nmap -f TARGET_IP

# Decoy scan
sudo nmap -D RND:10 TARGET_IP
```

**UDP scanning**:
```bash
sudo nmap -sU --top-ports 100 TARGET_IP
sudo nmap -sU -p 53,67,68,69,123,161 TARGET_IP
```

### Service Enumeration

```bash
# Banner grabbing
nc -v TARGET_IP 80
nc -v TARGET_IP 22

# Detailed version scan
nmap -sV --version-intensity 5 -p 80,443,22 TARGET_IP

# NSE scripts for service enum
nmap --script=banner TARGET_IP
nmap --script=ssh2-enum-algos -p 22 TARGET_IP
nmap --script=ssl-enum-ciphers -p 443 TARGET_IP
```

## Step 2: Web Application Reconnaissance

### Manual Reconnaissance

**Initial checks**:
```bash
# Fetch page
curl -i http://target.com/

# Check headers
curl -I http://target.com/

# Follow redirects
curl -L http://target.com/

# Custom User-Agent
curl -H "User-Agent: Mozilla/5.0" http://target.com/

# Check robots.txt
curl http://target.com/robots.txt

# Check sitemap
curl http://target.com/sitemap.xml
```

**View source code**:
- Right-click → View Page Source
- Look for comments: `<!-- secret -->`
- Check JavaScript files for endpoints/secrets
- Look for hardcoded credentials

**Technology fingerprinting**:
```bash
# WhatWeb
whatweb http://target.com/

# Wappalyzer (browser extension)
# Shows: CMS, frameworks, web server, programming language

# Check HTTP headers
curl -I http://target.com/ | grep Server
curl -I http://target.com/ | grep X-Powered-By
```

### Directory & File Discovery

**Gobuster** (fast):
```bash
# Directory brute force
gobuster dir -u http://target.com/ -w /usr/share/wordlists/dirb/common.txt

# With file extensions
gobuster dir -u http://target.com/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,js

# DNS subdomain enumeration
gobuster dns -d target.com -w /usr/share/wordlists/dnsmap.txt

# Vhost discovery
gobuster vhost -u http://target.com -w /usr/share/wordlists/subdomains.txt
```

**Dirb**:
```bash
dirb http://target.com/
dirb http://target.com/ /usr/share/wordlists/dirb/big.txt
```

**FFuf** (fast and flexible):
```bash
# Directory fuzzing
ffuf -u http://target.com/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# Parameter fuzzing
ffuf -u http://target.com/index.php?FUZZ=test -w params.txt

# Subdomain fuzzing
ffuf -u http://FUZZ.target.com/ -w /usr/share/wordlists/subdomains.txt
```

**Nikto** (vulnerability scanner):
```bash
nikto -h http://target.com/
nikto -h http://target.com/ -Tuning 123456789 -o nikto_results.txt
```

### Using Playwright MCP for Web Recon

**Navigate and screenshot**:
```
#mcp playwright navigate to http://target.com
#mcp playwright take screenshot

#mcp playwright snapshot
(Shows interactive elements and text)
```

**Form discovery**:
```
#mcp playwright snapshot
(Look for forms, input fields, buttons)

#mcp playwright click on "Login" button
#mcp playwright fill form with username="admin" password="test"
```

**JavaScript analysis**:
```
#mcp playwright evaluate JavaScript: document.scripts

Extract all script sources:
#mcp playwright evaluate [...document.scripts].map(s => s.src)
```

## Step 3: DNS Reconnaissance

### DNS Enumeration

```bash
# Basic lookup
nslookup target.com
nslookup target.com 8.8.8.8

# Dig (more detailed)
dig target.com
dig target.com ANY
dig target.com MX
dig target.com TXT
dig target.com NS

# Reverse lookup
dig -x IP_ADDRESS

# Zone transfer attempt (often blocked)
dig axfr @ns1.target.com target.com
```

### Subdomain Enumeration

**Sublist3r**:
```bash
# Note: May need to install
# pip3 install sublist3r
sublist3r -d target.com -o subdomains.txt
```

**DNSRecon**:
```bash
dnsrecon -d target.com -t std
dnsrecon -d target.com -t brt -D /usr/share/wordlists/subdomains.txt
```

**Amass** (comprehensive):
```bash
amass enum -d target.com
amass enum -d target.com -o amass_output.txt
```

**Manual brute force**:
```bash
# Using custom wordlist
for sub in $(cat subdomains.txt); do
    dig $sub.target.com | grep -v "NXDOMAIN"
done
```

## Step 4: SMB Enumeration

### SMB/NetBIOS Scanning

```bash
# Scan for SMB
nmap -p 139,445 --script smb-protocols TARGET_IP

# List shares
smbclient -L //TARGET_IP/ -N
smbclient -L //TARGET_IP/ -U username

# Check for null session
smbclient //TARGET_IP/share -N

# Enum4linux (comprehensive)
enum4linux -a TARGET_IP

# SMBMap
smbmap -H TARGET_IP
smbmap -H TARGET_IP -u guest -p ''
```

### Accessing SMB Shares

```bash
# Connect to share
smbclient //TARGET_IP/share -U username

# Download all files
smbclient //TARGET_IP/share -U username -c "prompt OFF; recurse ON; mget *"

# Mount SMB share
sudo mount -t cifs //TARGET_IP/share /mnt/smb -o username=user,password=pass
```

## Step 5: OSINT Techniques

### Domain/Organization OSINT

**WHOIS lookup**:
```bash
whois target.com
whois IP_ADDRESS

# Historical WHOIS
# Use: https://whois-history.whoisxmlapi.com/
```

**Certificate transparency**:
```bash
# Search CT logs for subdomains
# Use: https://crt.sh/?q=%25.target.com

# Or command line
curl "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u
```

**Shodan** (IoT/device search):
```bash
# Install shodan CLI
pip3 install shodan

# Search
shodan search "hostname:target.com"
shodan host IP_ADDRESS

# Web interface: https://www.shodan.io/
```

**The Wayback Machine**:
```bash
# View historical versions
# https://web.archive.org/web/*/target.com

# Command line
waybackurls target.com > wayback_urls.txt
```

### Email/Username OSINT

**Email harvesting**:
```bash
# TheHarvester
theHarvester -d target.com -b google,bing,linkedin

# Manual Google dorking
site:target.com email
site:target.com contact
site:target.com @target.com
```

**Username enumeration**:
```bash
# Sherlock (find usernames across platforms)
# pip3 install sherlock-project
sherlock USERNAME

# Check specific services
# - GitHub: https://github.com/USERNAME
# - Twitter: https://twitter.com/USERNAME
# - Reddit: https://reddit.com/user/USERNAME
```

**Email validation**:
```bash
# Check if email exists
# Use: https://hunter.io/email-verifier

# SMTP verification (manual)
telnet mail.target.com 25
VRFY user@target.com
```

### Social Media OSINT

**LinkedIn**:
- Search for employees: `site:linkedin.com "target company"`
- Extract email patterns: firstname.lastname@target.com
- Identify technologies/tools used

**GitHub**:
```bash
# Search code
# site:github.com "target.com" password
# site:github.com "target.com" api_key

# GitHub dorking
filename:.env "target.com"
filename:config.php "database"
extension:sql password
```

**Google Dorking**:
```
site:target.com filetype:pdf
site:target.com inurl:admin
site:target.com intitle:"index of"
site:target.com filetype:log
site:target.com inurl:login
site:target.com "powered by"
cache:target.com
```

## Step 6: Metadata Analysis

### Document Metadata

```bash
# EXIF data from images
exiftool image.jpg
exiftool -a -G1 document.pdf

# Extract creator, software, GPS coordinates
exiftool -Creator -Software -GPS* image.jpg

# Batch analysis
exiftool -csv -r directory/ > metadata.csv
```

### Image Reverse Search

- Google Images: https://images.google.com/ (upload image)
- TinEye: https://tineye.com/
- Yandex Images: https://yandex.com/images/

## Step 7: Network Traffic Analysis

### Passive Reconnaissance

**tcpdump**:
```bash
# Capture traffic
sudo tcpdump -i eth0 -w capture.pcap

# Specific port
sudo tcpdump -i eth0 port 80 -w http_traffic.pcap

# Specific host
sudo tcpdump -i eth0 host TARGET_IP -w target_traffic.pcap
```

**Wireshark**:
- Open capture file
- Apply filters: `http`, `dns`, `tcp.port == 80`
- Follow TCP streams
- Export objects

## Common Recon Patterns

### Pattern 1: Hidden Subdomains
- Check DNS records (TXT, MX, NS)
- Certificate transparency logs
- Brute force common names (dev, staging, admin, test)

### Pattern 2: Forgotten Files
- .git directory exposure
- Backup files (.bak, .old, .backup)
- Configuration files (.env, config.php)
- Database dumps (.sql, .db)

### Pattern 3: Information Leakage
- Error messages revealing versions
- Directory listings
- Comments in source code
- Metadata in documents

### Pattern 4: Default Credentials
- After finding service, try default creds
- admin/admin, admin/password, root/toor
- Check vendor documentation

## Tools Quick Reference

```bash
# Network scanning
nmap --help
masscan --help

# Web scanning
gobuster --help
nikto --help
whatweb --help

# DNS
dig --help
dnsrecon --help

# SMB
enum4linux --help
smbclient --help

# OSINT
theHarvester --help
sherlock --help
```

## Checklist

- [ ] Identified all live hosts
- [ ] Scanned all TCP/UDP ports
- [ ] Enumerated all services and versions
- [ ] Discovered web directories and files
- [ ] Checked robots.txt and sitemap.xml
- [ ] Performed subdomain enumeration
- [ ] Attempted DNS zone transfer
- [ ] Enumerated SMB shares (if applicable)
- [ ] Harvested emails and usernames
- [ ] Performed Google dorking
- [ ] Checked certificate transparency logs
- [ ] Analyzed document metadata
- [ ] Searched for historical data (Wayback Machine)
- [ ] Documented all findings

## Resources

- OSINT Framework: https://osintframework.com/
- Nmap reference: https://nmap.org/book/man.html
- Google hacking database: https://www.exploit-db.com/google-hacking-database
- Shodan: https://www.shodan.io/
