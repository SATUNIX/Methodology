# **Active Directory Reconnaissance & Information Gathering**

## **Scenario:**
This document outlines **reconnaissance and information gathering techniques** for **Active Directory (AD) penetration testing**. The goal is to **identify domain information, user accounts, network structure, and AD-related assets** before proceeding to exploitation.

### **References for Further Study:**
- **MITRE ATT&CK – Reconnaissance Techniques (T1595, T1590, T1589, T1213)**
- **Red Team Field Manual (RTFM)**
- **Microsoft Active Directory Security Best Practices**
- **OSINT & Public Data Gathering Resources (Shodan, Censys, GitHub Dorking)**

---

# **🛠 Step 1: Reconnaissance & Information Gathering**
**Objective:** Identify **domain names, users, network layout, and exposed AD-related assets**.

## **1.1 External Recon (Public & Passive Discovery)**

### **Enumerate Domain via Public Records (WHOIS, crt.sh, DNS Records)**
- **Why?** Many organizations expose domain details that can be leveraged for attack.
- **Techniques:**
  - **WHOIS Lookups:**
    - `whois <domain>` (Linux built-in command)
    - `whoisxmlapi.com` (Online WHOIS database)
    - `rdap.arin.net` (Regional WHOIS lookup)
    - `host -t ns <domain>` (Find authoritative DNS servers)
  - **Certificate Transparency Logs:**
    - `https://crt.sh/?q=<domain>` (Search for SSL/TLS certificates revealing subdomains)
    - `certspotter.com` (Alternative certificate search engine)
  - **DNS Enumeration:**
    - `dig any <domain>` (Find name servers, mail servers, and subdomains)
    - `nslookup -type=ANY <domain>` (Query DNS records for exposure)
    - `host -a <domain>` (List all DNS records)
    - `dnsrecon -d <domain> -t axfr` (Check for DNS zone transfers)

### **Gather Information via OSINT (LinkedIn Scraping, Data Leaks, Pastebin Dumps)**
- **Why?** Employee profiles may reveal **internal email formats, AD naming conventions, and exposed credentials**.
- **Techniques:**
  - **LinkedIn Scraping (Finding Employees & Naming Conventions):**
    - `theHarvester -d <company>.com -b linkedin`
    - `linkedin2username -c <company_name>`
    - `recon-ng marketplace install recon/domains-contacts/Linkedin_Crawler`
  - **Finding Email Formats:**
    - Use `hunter.io` or `email-format.com`
    - `googling "*@company.com"`
  - **Leaked Data Dumps (Checking for Credential Exposures):**
    - `HaveIBeenPwned API` (Search leaked emails/passwords)
    - `dehashed.com` (Dark web credential leaks)
    - `leak-lookup.com` (Credential database searching)

### **Check for Public GitHub Exposures (Hardcoded Credentials, .git Repositories)**
- **Why?** Developers often mistakenly upload secrets in repositories.
- **Techniques:**
  - **GitHub Dorks:**
    - `github.com/search?q="company.com"+password&type=code`
    - `github.com/search?q="AWS_ACCESS_KEY_ID"+"company"`
    - `trufflehog --regex --entropy=False --json -i <repo>` (Scan repo for secrets)
  - **Exposed `.git` repositories:**
    - `https://target.com/.git/config` (Check if `.git` folder is exposed)
    - `git-dumper <URL> <output>` (Dump exposed .git repositories)

### **Search for Leaked Credentials (HaveIBeenPwned, RockYou2024 Password Lists)**
- **Why?** Many users **recycle passwords**, and leaked credentials **may still be valid**.
- **Techniques:**
  - **Use HaveIBeenPwned API to check leaks:**
    - `curl -s "https://api.pwnedpasswords.com/range/F81A1"`
    - `holehe -t <domain>` (Check emails across multiple services)
    - `pwndb.py -q "company.com"` (Search underground leaked databases)

### **Check for Exposed SMB or LDAP Services on the Internet (Shodan, Censys, GreyNoise)**
- **Why?** Misconfigured services **expose authentication endpoints**.
- **Techniques:**
  - **Shodan Queries:**
    - `shodan search "port:445 country:US"`
    - `shodan search "port:389 Active Directory"`
  - **Censys Queries:**
    - `censys.io/ipv4?q=ldap+Active Directory`
    - `censys.io/ipv4?q=port:445 smb` (Find exposed SMB servers)
  - **GreyNoise for filtering noisy servers:**
    - `https://viz.greynoise.io/table`
  - **Alternative Queries:**
    - `zoomeye.org` (Chinese alternative to Shodan)
    - `hunter.horizon.ai` (Enterprise threat hunting tool)

---

## **1.2 Internal Recon (Unauthenticated Enumeration)**

### **Identify Live Hosts (ARP Scanning, ICMP Sweeps, Nmap)**
- **Techniques:**
  - `nmap -sn 192.168.1.0/24`
  - `fping -a -g 192.168.1.0/24`
  - `netdiscover -r 192.168.1.0/24`
  - `ping sweep: for i in {1..254}; do ping -c 1 192.168.1.$i | grep 'bytes from'; done`

### **Enumerate Domain Controllers (NetBIOS, Kerberos, LDAP Queries)**
- **Techniques:**
  - `nbtscan 192.168.1.0/24`
  - `crackmapexec smb 192.168.1.0/24` (Find Domain Controllers)
  - `ldapsearch -x -h <DC_IP> -s base namingContexts`
  - `kerbrute userenum -d <domain> --dc <DC_IP> usernames.txt`

### **Enumerate Open Ports & Services (Nmap, CrackMapExec, Masscan)**
- **Techniques:**
  - `masscan -p445,389,88 --rate 10000 192.168.1.0/24`
  - `nmap -p 88,445,389,636,3268,5985 --script smb-enum-shares,smb-os-discovery <target>`
  - `cme smb 192.168.1.0/24 --shares`
  - `rpcclient -U "" <target>` (Check available RPC services)

