# **Basic Wireless Network Penetration Testing Methodology**

## **Scenario:**
You are conducting a **full wireless network penetration test** with minimal initial information (e.g., a target SSID or an open frequency spectrum). This guide includes **multiple redundant techniques for each step** and maps to **MITRE ATT&CK Techniques (TTPs)** where applicable.

---

# **🛠 Step 1: Information Gathering (Reconnaissance) (T1595, T1590, T1596)**
**Objective:** Identify available wireless networks, security configurations, and potential entry points.

### **1.1 Passive Wireless Reconnaissance**
**Primary Method:** Wi-Fi Sniffing (T1596.002)  
*Capture beacon frames, probe requests, and network broadcast data.*  
- Alternative Methods:
  - Kismet (Passive Wireless Capture)
  - Airodump-ng (802.11 Packet Analysis)
  - Wireshark (Monitoring WPA Handshakes & SSID Probing)

### **1.2 Active Wireless Reconnaissance**
**Primary Method:** SSID Enumeration & Probing (T1590.002)  
*Identifying visible & hidden networks, client associations, and AP vendors.*  
- Alternative Methods:
  - Wifite (Automated SSID Discovery & Probing)
  - Bettercap (Wireless Enumeration & Deauthentication Analysis)
  - EvilTwin SSID Mapping (Cloning Network Names to Identify Client Responses)

---

# **📡 Step 2: Wireless Authentication & Association Attacks (T1595, T1592, T1590)**
**Objective:** Exploit weaknesses in wireless authentication mechanisms.

### **2.1 Exploiting Open & Weakly Secured Networks**
**Primary Method:** Captive Portal Bypass (T1592.001)  
*Spoofing authentication mechanisms & evading restrictions.*  
- Alternative Methods:
  - MAC Spoofing to Bypass Device Authentication
  - DNS Manipulation & Hijacking Captive Portal Responses
  - ARP Poisoning to Redirect Web Traffic for Credential Theft

### **2.2 WPA/WPA2 Cracking & PMKID Attacks**
**Primary Method:** WPA2 Handshake Capture & Cracking (T1600)  
*Intercepting WPA2 handshakes & brute-forcing the Pre-Shared Key (PSK).*  
- Alternative Methods:
  - PMKID Attack (Retrieving Handshakes without Client Interaction)
  - Wordlist & Rule-Based WPA2 Cracking (Hashcat, Aircrack-ng)
  - WPS PIN Bruteforce (Pixie Dust & Reaver Exploitations)

---

# **🔑 Step 3: Wireless Exploitation & MITM Attacks (T1599, T1600)**
**Objective:** Manipulate wireless traffic and compromise network security.

### **3.1 Man-in-the-Middle (MITM) Attacks**
**Primary Method:** Evil Twin AP (T1599.001)  
*Deploying rogue APs to capture client credentials.*  
- Alternative Methods:
  - Deauthentication Attacks (Forcing Clients to Reconnect via Attacker AP)
  - SSL Stripping (Downgrading HTTPS to HTTP for Credential Theft)
  - Intercepting Web Sessions via ARP/DNS Spoofing

### **3.2 Bluetooth, Zigbee, & IoT Wireless Exploitation**
**Primary Method:** Bluetooth Sniffing & PIN Bruteforce (T1599.004)  
*Exploiting insecure Bluetooth pairings & IoT vulnerabilities.*  
- Alternative Methods:
  - Zigbee Packet Injection & Device Hijacking
  - Exploiting Misconfigured Wi-Fi Direct Networks
  - Jamming Bluetooth Devices to Force Re-Pairing Attacks

### **3.3 Bypassing 802.1X Enterprise Wireless Networks**
**Primary Method:** RADIUS Authentication Attacks (T1599.002)  
*Intercepting EAP authentication for WPA2-Enterprise cracking.*  
- Alternative Methods:
  - Certificate Cloning for EAP-TLS Bypass
  - Rogue AP Attacks on WPA2-Enterprise Networks
  - Stealing NTLMv2 Hashes via Forced Authentication Redirects

---

# **📡 Step 4: Wireless Persistence & Lateral Movement (T1565, T1567)**
**Objective:** Maintain long-term network access and pivot internally.

### **4.1 Establishing Covert Wireless Persistence**
**Primary Method:** Rogue AP Deployment (T1565.001)  
*Creating persistent backdoor access via attacker-controlled wireless nodes.*  
- Alternative Methods:
  - Firmware Modification on APs for Backdoored SSH/Telnet Access
  - Persistent Tethering via Wi-Fi Pineapple & Covert Network Bridging
  - Deploying Long-Term Listening Devices (Raspberry Pi, ESP8266 Wi-Fi Beacons)

### **4.2 Wireless Lateral Movement Techniques**
**Primary Method:** VLAN Hopping & Internal Pivoting (T1567.002)  
*Compromising network segmentation to pivot into internal corporate infrastructure.*  
- Alternative Methods:
  - Exploiting Misconfigured VLANs to Gain Wired Network Access
  - Tunneling Network Traffic via Compromised IoT Devices
  - Leveraging Printers & Smart Devices as Stealthy Entry Points

---

# **🛑 Step 5: Covering Tracks & Wireless OPSEC (T1070, T1098)**
**Objective:** Remove traces of wireless network exploitation and maintain stealth.

### **5.1 Wireless Log Manipulation & Evasion Techniques**
**Primary Method:** MAC Address Rotation & Spoofing (T1070.002)  
*Obfuscating attacker presence by changing wireless fingerprints.*  
- Alternative Methods:
  - Clearing Router/AP Logs to Remove Connection Evidence
  - Using Directional Antennas to Minimize Signal Footprint
  - Encrypting C2 Traffic via DNS & ICMP Tunneling for Covert Data Exfiltration

### **5.2 Countermeasures & Defensive Evasion**
**Primary Method:** Wireless IDS/IPS Bypass (T1098)  
*Avoiding detection by evading wireless anomaly detection systems.*  
- Alternative Methods:
  - Mimicking Legitimate Traffic to Avoid Triggering Alarms
  - Deploying Stealth Beacons with Delayed Activation for Long-Term Persistence
  - Self-Destructing Malware & Time-Based Rogue AP Removal

---

# **📌 Summary of Steps**

| **Step** | **Primary Method** | **Alternative Methods** |
|---|---|---|
| **Reconnaissance** | Passive Wi-Fi Sniffing | Kismet, Airodump-ng, Wireshark |
| **Authentication Attacks** | WPA2 Handshake Cracking | PMKID, WPS Exploits, RADIUS Hijacking |
| **Exploitation** | Evil Twin AP | MITM Attacks, SSL Stripping, Rogue AP |
| **Persistence** | Rogue AP Deployment | IoT Compromise, VLAN Hopping |
| **Covering Tracks** | MAC Rotation & Log Clearing | IDS Bypass, Directional Antennas |

---
