# **Active Directory (AD) Penetration Testing Methodology List**

## **Scenario:**
This methodology lists techniques for Active Directory (AD) penetration testing. The structure follows **pentesting steps** with **comprehensive enumeration methods**, covering every possible attack path. This document does **not** include commands, only methodologies.
This document should be used in conjuction with supporting material for study and research purposes only. 
Please refer to the following for more info on each method:
- MITRE ATTACK AND DEFEND
- Hacktricks
- GTFOBins
- (check the main resources document for more)
---

# **🛠 Step 1: Reconnaissance & Information Gathering**
**Objective:** Identify domain, users, network layout, and AD-related assets.

### **1.1 External Recon (Public & Passive Discovery)**
- **Enumerate Domain via Public Records** (WHOIS, crt.sh, DNS records)
- **Gather Information via OSINT** (LinkedIn scraping, Data leaks, Pastebin dumps)
- **Check for Public GitHub Exposures** (Hardcoded credentials, `.git` repositories)
- **Search for Leaked Credentials** (HaveIBeenPwned, RockYou2024 password lists)
- **Check for Exposed SMB or LDAP Services on Internet** (Shodan, Censys, GreyNoise)

### **1.2 Internal Recon (Unauthenticated Enumeration)**
- **Identify Live Hosts** (ARP Scanning, ICMP Sweeps, Nmap)
- **Enumerate Domain Controllers (DCs)** (NetBIOS, Kerberos, LDAP queries)
- **Enumerate Open Ports & Services** (Nmap, CrackMapExec, Masscan)
- **Extract Domain Name & Trust Relationships** (LDAP queries, `nltest` discovery)
- **Identify Domain Policies & Group Policy Objects (GPOs)** (SYSVOL browsing)
- **Enumerate Windows Update KBs for Missing Patches**

---

# **📡 Step 2: AD Enumeration (No Credentials / Low-Privileged User)**
**Objective:** Gather user lists, groups, shares, and domain structure.

### **2.1 User & Group Enumeration**
- **Enumerate Users via LDAP Queries** (Anonymous Binds, `ldapsearch`, BloodHound)
- **Extract Users via Kerberos Pre-Auth Disabled (AS-REP Roasting)**
- **Enumerate Groups and Group Memberships** (`net group /domain`, `gpresult`)
- **Identify High-Privilege Accounts (DA, Server Admins, SQL Admins)**

### **2.2 SMB & File Share Enumeration**
- **List Available SMB Shares** (`smbclient`, `enum4linux`, CrackMapExec)
- **Access SYSVOL & NETLOGON for Credentials & Scripts**
- **Check for Open File Shares with Credentials (Config Files, Backup Scripts)**
- **Enumerate Share Permissions & ACLs for Misconfigurations**

### **2.3 Kerberos Enumeration**
- **SPN Discovery (Kerberoasting Candidates)** (`GetUserSPNs`, BloodHound)
- **Identify Users with Unconstrained Delegation Enabled**
- **Enumerate Kerberos Tickets without Authentication (Pass-the-Ticket Candidates)**

### **2.4 Privilege Discovery via GPOs**
- **Extract Group Policy Preferences (GPP) Passwords**
- **Identify Mapped Drives & Startup Scripts with Potential Credentials**
- **Identify Misconfigured GPO Policies for Privilege Escalation**

---

# **🔑 Step 3: Initial Access & Credential Attacks**
**Objective:** Obtain valid user credentials or execute remote code.

### **3.1 Credential Attacks**
- **Password Spraying on SMB, LDAP, WinRM, RDP, Kerberos**
- **AS-REP Roasting for Hash Extraction**
- **Kerberoasting (Extracting Service Account Hashes)**
- **Enumerate and Crack NTLM Hashes (Responder, MITM Attacks)**
- **Pass-the-Hash (PTH) and Over-Pass-the-Hash (Pass-the-Ticket)**
- **Brute Force Attacks on AD Accounts with Common Passwords**

### **3.2 Exploiting AD Vulnerabilities for Initial Access**
- **Zero-Day & N-Day Exploits Against AD Components (MS08-067, MS17-010)**
- **NTLM Relay Attacks (SMB Signing Disabled, ADIDNS, Exchange Relaying)**
- **PrinterBug Exploitation for NTLM Hash Capture**
- **Exploiting Kerberos Delegation Issues (Resource-Based Constrained Delegation)**
- **LLMNR & NBT-NS Poisoning with Responder**

### **3.3 Phishing & Social Engineering (Targeted Attacks)**
- **Spear Phishing for Credential Harvesting (Office Macros, HTA Payloads)**
- **Malicious DLL Injection in Network Shares**
- **Embedding Payloads in GPO Deployed Scripts**
- **Using Evilginx for MFA Bypass (Token Theft via Reverse Proxy)**

---

# **📡 Step 4: Privilege Escalation & Lateral Movement**
**Objective:** Move from a low-privileged account to Domain Admin.

### **4.1 Privilege Escalation**
- **Local Privilege Escalation (Token Impersonation, Sticky Keys, DLL Hijacking)**
- **Enumerate Local Admin Rights on Workstations & Servers**
- **Extract LSASS Memory for Cached Credentials (Mimikatz, Procdump)**
- **DCSync Attack (Replicating AD Password Database)**
- **Abusing AD CS (Active Directory Certificate Services Exploitation)**

### **4.2 Lateral Movement Techniques**
- **Pass-the-Hash / Pass-the-Ticket (PtH, PtT)**
- **Overpass-the-Hash (Using NTLM Hash for Kerberos Tickets)**
- **Mimikatz ‘Pass-the-Key’ with AES Kerberos Keys**
- **SMB Lateral Movement (PSExec, CrackMapExec, Invoke-SMBExec)**
- **Abusing Remote Desktop Protocol (RDP Session Hijacking)**
- **SSH Tunneling / Proxying to Move Stealthily**

---

# **🏆 Step 5: Domain Compromise & Persistence**
**Objective:** Gain Domain Admin, persist, and exfiltrate data stealthily.

### **5.1 Domain Admin Takeover**
- **Dumping NTDS.dit for Complete Credential Theft**
- **Golden Ticket Attack (Forging Kerberos TGTs for DA Access)**
- **Silver Ticket Attack (Impersonating a Service for Lateral Movement)**
- **Skeleton Key Attack (Injecting a Master Key for All Users)**

### **5.2 Persistence & Stealthy Backdoors**
- **Create Hidden Admin Accounts via `dsadd user`**
- **Modify GPOs to Deploy Backdoor Access Scripts**
- **Modify `AdminSDHolder` to Maintain Admin Rights**
- **Using WMI Event Subscription for Persistent Execution**
- **Adding Malicious Scheduled Tasks on Domain Controllers**
- **Backdooring AD Certificate Services for Long-Term Persistence**

### **5.3 Exfiltration & Data Collection**
- **Extracting Emails & Files from Exchange (EWS Abuse, Outlook COM Hijack)**
- **Stealing Azure AD & Cloud SSO Tokens (AzureHound, AADInternals)**
- **Copying All AD Objects to External Database (BloodHound Ingest)**
- **Using Covert Tunneling & DNS Exfiltration for Data Theft**

---

# **🛑 Step 6: Covering Tracks & Log Manipulation**
**Objective:** Remove evidence and maintain stealth.

### **6.1 Clearing Event Logs**
- **Delete Security, System, and Powershell Logs (`wevtutil cl Security`)**
- **Tamper With SIEM & Detection Logs (EDR Bypass Techniques)**
- **Use Kerberos Ticket Expiry to Reduce Log Retention Impact**

### **6.2 Stealthy Persistence**
- **Hiding in AD Replication (AdminSDHolder TTPs)**
- **Covert C2 Channels (DNS, ICMP, HTTPS)**
- **Obfuscate Windows Defender & AMSI Logs**

---
