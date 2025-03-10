# **Network Penetration Testing Methodology List**

## **Scenario:**
This methodology lists techniques for **Network Penetration Testing**. The structure follows **pentesting steps** with **comprehensive enumeration methods**, covering **every possible attack path**. This document does not include commands, only methodologies. It should be used in conjunction with supporting material for study and research purposes only.

### **References for Further Reading on each method..:**
- **MITRE ATT&CK**
- **HackTricks**
- **Red Team Field Manual (RTFM)**
- **NIST SP 800-115 (Network Security Testing)**
- **(Check the main resources document for more references)**

---

# **🛠 Step 1: Reconnaissance & Information Gathering**
**Objective:** Identify **live hosts, services, network topology, firewall rules, and potential entry points**.

### **1.1 Passive Recon (External Discovery & OSINT)**
- **WHOIS & DNS Enumeration** (Domain records, subdomains, name servers)
- **Public Network Scanning (Shodan, Censys, FOFA, GreyNoise)**
- **Social Media & OSINT (LinkedIn, Pastebin, GitHub, Data Breaches)**
- **TLS Certificate Analysis for Hidden Subdomains & Internal Hosts**
- **BGP & ASN Reconnaissance for Organization-Owned IP Ranges**

### **1.2 Active Recon (Network Mapping & Host Discovery)**
- **Identifying Live Hosts (ARP Scans, ICMP Sweeps, Passive Sniffing)**
- **Firewall & IDS/IPS Detection (Decoy Scans, Fragmented Probes)**
- **Enumerating Network Ranges via DHCP Snooping & DNS Requests**
- **IPv6 Recon (Discovering Hidden Hosts via Neighbor Discovery Protocol)**

---

# **📡 Step 2: Network Enumeration & Service Fingerprinting**
**Objective:** Identify open ports, network services, and vulnerabilities.

### **2.1 Network & Port Scanning**
- **Stealthy Scanning (SYN/FIN Scans, Decoys, DNS-based Scanning)**
- **Enumerating Network Devices (SNMP, Cisco Smart Install, IPMI)**
- **Mapping Internal Network via NetBIOS & mDNS Discovery**
- **Identifying Misconfigured VLANs & Subnet Isolation Weaknesses**

### **2.2 Service Enumeration & Fingerprinting**
- **Enumerating SMB, NFS, RDP, VNC, and Other Enterprise Protocols**
- **Identifying Running Services & Versions (Banner Grabbing, WAF Detection)**
- **Detecting Load Balancers & Proxy Servers via Response Analysis**
- **Discovering Hidden Web Apps (vHost Enumeration, Virtual Hosting)**

### **2.3 Credential & Privilege Enumeration**
- **Checking for Default Credentials on Network Devices**
- **Password Spraying for VPN, SSH, SMB, and Web Panels**
- **Enumerating User Accounts via Kerberos Pre-Auth Bypass (AS-REP Roasting)**
- **Enumerating Open RDP Sessions & Active Users (Windows TermService)**

---

# **🔑 Step 3: Initial Access & Exploitation**
**Objective:** Gain access via exposed services, misconfigurations, or stolen credentials.

### **3.1 Exploiting Network Services**
- **Targeting Misconfigured SMB Shares & NFS Mounts**
- **Exploiting SSH Key-based Authentication Flaws**
- **VPN Exploitation (Split Tunneling, Password Leaks, MFA Bypasses)**
- **Attacking Printers & IoT Devices via LLMNR/NBT-NS Poisoning**
- **Identifying Weak Encryption in Telnet, FTP, SNMP, and RADIUS**

### **3.2 Man-in-the-Middle (MITM) Attacks**
- **ARP Spoofing to Intercept Traffic**
- **MITM on SMB to Capture NTLMv2 Hashes (Responder, Inveigh)**
- **Exploiting Proxy Auto-Config (WPAD) to Intercept Traffic**
- **Abusing DHCP Starvation & Rogue DHCP Servers**
- **TLS Downgrade Attacks & Session Hijacking**

### **3.3 Exploiting Wireless Networks**
- **Capturing WPA2 Handshakes & Cracking PSK**
- **Evil Twin Attacks & Rogue Access Points**
- **De-authentication & Beacon Flooding Attacks**
- **Exploiting Bluetooth & IoT Wireless Protocols (Zigbee, LoRa, BLE)**

---

# **📡 Step 4: Lateral Movement & Privilege Escalation**
**Objective:** Escalate privileges and move laterally across the network.

### **4.1 Windows & Active Directory Lateral Movement**
- **Pass-the-Hash & Overpass-the-Hash (PtH, PtT)**
- **Stealing Kerberos Tickets (Golden & Silver Ticket Attacks)**
- **Exploiting Misconfigured GPO Policies & Startup Scripts**
- **Lateral Movement via PsExec, WMI, and RDP Session Hijacking**

### **4.2 Unix & Linux Lateral Movement**
- **Exploiting SSH Key Trust Relationships**
- **Reusing Credentials via SSH Agent Hijacking**
- **Abusing Sudo & Misconfigured Cron Jobs for PrivEsc**

### **4.3 Network-Based Lateral Movement**
- **Compromising Network Devices (Cisco, Juniper, MikroTik)**
- **BGP Hijacking & Route Injection Attacks**
- **DNS Hijacking for Network-wide Credential Theft**
- **Exploiting IPv6 Tunnels for Stealthy Lateral Movement**

---

# **🏆 Step 5: Network Persistence & Data Exfiltration**
**Objective:** Maintain access and extract sensitive information.

### **5.1 Persistence in Enterprise Networks**
- **Backdooring Network Devices via Firmware Patching**
- **Abusing VLAN Hopping to Maintain Hidden Access**
- **Compromising Network Monitoring Systems for Covert Persistence**
- **Deploying Covert C2 Channels (DNS, ICMP, HTTPS Tunnels)**

### **5.2 Data Exfiltration Techniques**
- **Exfiltrating Data via Steganography & Covert Channels**
- **Leveraging Cloud Storage for Exfil (AWS S3, Google Drive, Dropbox Abuse)**
- **Exfiltrating Large Data Sets via Network Tunneling**
- **Using DNS & ICMP Exfiltration to Bypass Firewalls**

---

# **🛑 Step 6: Covering Tracks & Log Manipulation**
**Objective:** Remove evidence and maintain stealth.

### **6.1 Clearing Network & System Logs**
- **Disabling Syslog & SIEM Monitoring Alerts**
- **Tampering with NetFlow Logs & DNS Query Records**
- **Modifying Firewall & IDS/IPS Logs to Hide Traffic Anomalies**
- **Clearing Authentication Logs for VPN & RADIUS Sessions**

### **6.2 Network OPSEC & Anti-Forensics**
- **Using Encrypted & Obfuscated C2 Channels**
- **Rotating Source IPs via Proxy Chains & Tor Relays**
- **Leveraging Legitimate Network Protocols for Persistence (WMI, RPC, SNMP)**
- **Deploying Self-Destructing Payloads & Ephemeral Containers for Evasion**

---

> “All warfare is based on deception.” – Sun Tzu, The Art of War
