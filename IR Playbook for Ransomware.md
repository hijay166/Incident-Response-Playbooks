# 🔴 IR Playbook: Ransomware

**Severity:** CRITICAL  
**Target Response Time:** < 15 minutes for initial containment  
**MITRE Techniques:** T1486 (Data Encrypted), T1490 (Inhibit Recovery), T1489 (Service Stop)  
**Last Updated:** 2025  
**Author:** Tobi Bolaji

---

## 🚨 Indicators of Compromise (IOCs)

### Behavioural Indicators
- [ ] Files renamed with unusual extensions (`.locked`, `.encrypted`, `.ransom`, `.crypt`)
- [ ] Ransom note files appearing (`README.txt`, `DECRYPT_INSTRUCTIONS.html`, `HOW_TO_RECOVER.txt`)
- [ ] Shadow copies deleted (`vssadmin delete shadows /all`)
- [ ] Windows backup catalog deleted (`wbadmin delete catalog`)
- [ ] Recovery mode disabled (`bcdedit /set {default} recoveryenabled No`)
- [ ] Mass file read/write operations in short timeframe
- [ ] Unusual process spawning `cmd.exe` or `powershell.exe`

### Network Indicators
- [ ] Outbound connections to unknown IPs on unusual ports
- [ ] DNS queries to newly registered or DGA-based domains
- [ ] Large data transfers before encryption (pre-exfiltration)

---

## 📞 Step 1 — Detection & Triage (0–15 minutes)

```
☐ 1.1  Alert received via SIEM / EDR / user report
☐ 1.2  Confirm it is ransomware (check file extensions, ransom note)
☐ 1.3  Identify affected host(s) — hostname, IP, user, department
☐ 1.4  Determine scope: single host or multiple systems?
☐ 1.5  Escalate to IR Lead / CISO immediately
☐ 1.6  Open incident ticket — assign severity: CRITICAL
☐ 1.7  Do NOT reboot or shut down affected system (preserves memory evidence)
```

---

## 🔒 Step 2 — Containment (15–60 minutes)

### Immediate Network Isolation
```powershell
# Disable NIC on affected Windows host (run on host or via EDR)
Disable-NetAdapter -Name "*" -Confirm:$false

# OR at network level — block host MAC on switch
# Contact network team to port-block the switch port
```

### Isolate via EDR (if available)
```
# CrowdStrike, SentinelOne, Defender for Endpoint
# → Isolate host from console
# → This maintains management connection while blocking all other traffic
```

**Containment checklist:**
```
☐ 2.1  Isolate affected host(s) from network (VLAN/firewall rule/EDR)
☐ 2.2  Disable affected user account(s) in Active Directory
☐ 2.3  Reset service accounts used by the affected system
☐ 2.4  Block C2 IPs/domains on perimeter firewall
☐ 2.5  Identify and isolate any other infected systems
☐ 2.6  Preserve memory dump BEFORE shutdown (if forensics team is ready)
☐ 2.7  Alert backup team — do NOT run automated backup (avoid encrypting backups)
```

---

## 🔬 Step 3 — Investigation (60 min – 4 hours)

### Memory Acquisition
```bash
# Using WinPMem on Windows
winpmem_mini.exe memdump.raw

# Transfer to forensic workstation
```

### Identify Ransomware Family
```bash
# Upload ransom note / sample to:
# https://id-ransomware.malwarehunterteam.com/
# https://www.nomoreransom.org/
# Check extension on https://ransomware.live/
```

### Timeline Analysis
```powershell
# Windows Event Log — find execution start time
Get-WinEvent -LogName Security | Where-Object {$_.Id -eq 4688} | 
  Select-Object TimeCreated, Message | 
  Where-Object {$_.Message -match "ransom|encrypt|vssadmin"}

# Sysmon — process creation
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | 
  Where-Object {$_.Id -eq 1} |
  Select-Object TimeCreated, Message |
  Where-Object {$_.Message -match "vssadmin|bcdedit|wbadmin"}
```

**Investigation checklist:**
```
☐ 3.1  Identify patient zero (first infected host)
☐ 3.2  Identify initial access vector (phishing email, RDP, exploit?)
☐ 3.3  Determine lateral movement path
☐ 3.4  Check for data exfiltration before encryption
☐ 3.5  Identify all affected systems and data
☐ 3.6  Collect all IOCs (IPs, domains, hashes, registry keys)
☐ 3.7  Preserve evidence (disk images, memory dumps, logs)
```

---

## 🧹 Step 4 — Eradication

```
☐ 4.1  Identify and remove all malware artifacts
☐ 4.2  Remove persistence mechanisms (scheduled tasks, registry run keys, services)
☐ 4.3  Patch exploited vulnerabilities
☐ 4.4  Reset ALL compromised credentials (not just affected user)
☐ 4.5  Rotate service account passwords
☐ 4.6  Scan all systems with EDR/AV for residual malware
☐ 4.7  Rebuild systems that cannot be fully cleaned
```

---

## 🔄 Step 5 — Recovery

```
☐ 5.1  Restore from last known-good backup (verify backup integrity first!)
☐ 5.2  Validate restored data is clean (scan before reconnecting)
☐ 5.3  Reconnect systems to network in stages — monitor closely
☐ 5.4  Monitor for reinfection for 72 hours post-recovery
☐ 5.5  Verify all services are functional
☐ 5.6  Notify affected users when systems are restored
```

---

## 📝 Step 6 — Post-Incident (Lessons Learned)

```
☐ 6.1  Document full incident timeline
☐ 6.2  Conduct post-mortem within 5 business days
☐ 6.3  Identify what controls failed / what worked well
☐ 6.4  Update detection rules based on IOCs
☐ 6.5  Report to management / legal / regulatory if required (GDPR 72-hour rule)
☐ 6.6  Update this playbook with lessons learned
```

---

## ⚠️ Decision: Pay or Not Pay Ransom?

> **Recommendation: Do NOT pay.** Payment does not guarantee recovery, funds criminal operations, and may violate sanctions laws. Always exhaust recovery options first.

1. Check [No More Ransom](https://www.nomoreransom.org/) for free decryptors
2. Consult legal team before any payment decision
3. If critical data at stake — involve law enforcement (Action Fraud UK: 0300 123 2040)

---

## 📞 Escalation Contacts

| Role | Action |
|------|--------|
| IR Lead | Immediate notification |
| CISO | Within 30 minutes |
| Legal | If data exfiltration suspected |
| ICO (UK) | Within 72 hours if personal data affected (GDPR) |
| Action Fraud | Law enforcement reporting |

---

## 🛡️ Prevention Controls

- Offline backups (3-2-1 rule)
- Endpoint Detection & Response (EDR)
- Email filtering / anti-phishing
- Disable RDP where not needed / use MFA
- Network segmentation
- Regular patching
- User awareness training