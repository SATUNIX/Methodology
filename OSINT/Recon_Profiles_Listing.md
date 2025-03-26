# 🔍 Red Team: Passive OSINT & Reconnaissance Methods

## 📘 Scenario:
This high level methodology outlines **passive, stealth-based OSINT techniques** for reconnaissance and profiling of remote organizations to asses targets, potential bugs, and further flaws. It is used to assess exposure, surface area, and security posture **without triggering detection**, **probing systems**, or **interacting directly with assets**.

All methods here are compliant with responsible, legal, and authorized reconnaissance. This should be used for **defensive risk assessment**, **red team pre-engagement intel gathering**, or **digital footprint discovery**.

Use in conjunction with:
- MITRE ATT&CK
- SpiderFoot, Recon-ng, Amass
- Threat Intel APIs
- Organization-Specific Threat Models

---

## 🧭 Step 1: Scope Definition & Target Profiling
**Objective:** Understand the organization's digital footprint, domains, and operational identifiers.

### 1.1 Define Recon Boundaries
- Root domains and corporate subsidiaries
- IP ranges and ASNs
- Brand names, trademarks, subsidiaries, products
- Social profiles, blogs, dev platforms

### 1.2 Attribution & Identity Profiling
- Registered domains and DNS ownership
- ASN and netblock assignments (ARIN/RIPE/APNIC)
- Public contact details (emails, numbers)
- Employee structure (LinkedIn, ZoomInfo)

---

## 🌐 Step 2: Infrastructure & Domain Intelligence
**Objective:** Map domains, subdomains, servers, and services passively.

### 2.1 DNS & Subdomain Discovery
- Passive DNS record enumeration (A, MX, TXT, NS)
- Use Certificate Transparency logs (crt.sh, CertSpotter)
- Discover subdomains via:
  - Amass (passive mode)
  - SecurityTrails
  - RiskIQ PT
  - DNSDumpster

### 2.2 IPs & Public Services
- Passive correlation of IPs to services
- Public scans via:
  - Censys (API)
  - Shodan (passive search)
  - Netlas / FOFA / ZoomEye

### 2.3 SSL/TLS Certificate Enumeration
- Inspect SAN fields for hidden domains
- Review certificate history, misconfigs
- Detect wildcard, expired, or mismatched certs

---

## 👥 Step 3: Human Attack Surface
**Objective:** Identify social engineering risks and employee exposure.

### 3.1 Employee Enumeration
- LinkedIn / Crunchbase scraping
- GitHub commit authorship
- Email format detection (Hunter.io, manual recon)

### 3.2 Breach & Credential Exposure
- Public credential leaks:
  - HaveIBeenPwned
  - Dehashed
  - IntelligenceX
- Detect roles likely to be targeted (admins, finance, HR, devs)

---

## 🛠 Step 4: Technology Stack & Third-Party Risk
**Objective:** Profile technologies, vendors, integrations.

### 4.1 Web Stack & Frameworks
- BuiltWith / Wappalyzer
- Identify CMS, server tech, JavaScript libraries
- Analyze load balancers, WAFs, CDN providers

### 4.2 Cloud & SaaS Exposure
- Email provider (SPF/DMARC records)
- Cloud buckets (S3/GCP) via pattern enumeration
- Authentication services (Okta, Azure AD)

### 4.3 Third-Party Integrations
- Check for vendor subdomains (e.g., `*.zendesk.target.com`)
- SaaS references in job posts/blogs
- Identify vendor breaches impacting supply chain

---

## 📄 Step 5: Data Leak & Code Exposure
**Objective:** Discover leaked data, credentials, or secrets.

### 5.1 Breach Dumps & Paste Monitoring
- Pastebin (via mirrors)
- Ghostbin, PrivateBin, forums
- Dehashed / IntelligenceX queries

### 5.2 GitHub & Public Repos
- Search for secrets (`filename:.env`, `password=`, etc.)
- Use GitHub dorks or tools like:
  - TruffleHog
  - Gitleaks
- Attribute commits to employees/orgs

---

## 📊 Step 6: Risk Scoring & Threat Correlation
**Objective:** Translate findings into exposure profiles and risk categories.

### 6.1 Threat Actor Overlap
- Search infrastructure on:
  - VirusTotal (IP/domain check)
  - GreyNoise (scanner behavior)
  - AlienVault OTX (threat group overlap)

### 6.2 Risk Indicators
- Leaked credentials or secrets
- Forgotten subdomains, dev environments
- Use of legacy software or vulnerable services

### 6.3 OSINT Risk Matrix

| Category             | Examples                                     | Risk Level |
|----------------------|----------------------------------------------|------------|
| **Exposure**         | Leaked credentials, API tokens, access keys  | High       |
| **Surface Area**     | Excessive subdomains, services, old assets   | Medium     |
| **Tech Stack Risks** | Outdated CMS, public admin panels            | High       |
| **3rd Party Risk**   | Compromised vendors, SaaS misconfigs         | Medium     |
| **Human Risk**       | Breached employees, social engineering paths | Medium     |

---

## 🧰 Passive OSINT Tools & Registration Requirements

| Tool              | Use Case                          | Registration Required |
|-------------------|------------------------------------|------------------------|
| **Amass (Passive)** | Subdomain discovery, DNS history | ❌                      |
| **SpiderFoot**    | Automated passive OSINT scanning  | ❌ (optional for some APIs) |
| **Recon-ng**      | Modular recon framework           | ❌                      |
| **theHarvester**  | Email, domain, and subdomain intel| ❌                      |
| **Maltego CE**    | Link analysis & entity mapping    | ✅ (free account)       |
| **GitLeaks**      | Secret detection in repos         | ❌                      |
| **TruffleHog**    | Git secret scanning               | ❌                      |
| **crt.sh**        | TLS/SSL certificate discovery     | ❌                      |
| **BuiltWith**     | Web stack fingerprinting          | ✅ (limited use free)   |
| **Wappalyzer**    | Tech profiling browser extension  | ❌                      |
| **SecurityTrails**| DNS, IP, WHOIS data               | ✅                      |
| **RiskIQ PT**     | Passive DNS, threat intel         | ✅                      |
| **HaveIBeenPwned**| Breach checks                     | ❌ (API key optional)   |
| **Dehashed**      | Credential & dump search          | ✅                      |
| **IntelligenceX** | Pastebin, dark web leaks          | ✅                      |
| **Censys (search)**| Passive infra recon               | ✅ (free tier available)|
| **GreyNoise**     | IP scanning behavior              | ✅                      |
| **VirusTotal**    | Hash, IP, URL intel               | ✅                      |
| **FOFA / ZoomEye**| Infra fingerprinting (China)      | ✅                      |

---

## ✅ Notes
- All listed techniques and tools are **passive, open-source or OSINT-based**.
- No direct interaction with the target’s assets is performed.
- Data is sourced from **public repositories**, **transparency logs**, and **internet-wide scans** done by third parties.
- Ensure all actions comply with your organization’s legal and ethical standards.
https://cdn-cybersecurity.att.com/blog-content/GoogleHackingCheatSheet.pdf
---
