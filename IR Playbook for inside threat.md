# 🟠 IR Playbook: Insider Threat

**Severity:** HIGH  
**MITRE Techniques:** T1078 (Valid Accounts), T1052 (Exfil over Physical Medium), T1530 (Data from Cloud Storage)  
**Author:** Tobi Bolaji

---

## 🚨 Indicators

- Abnormal data access patterns (large downloads, off-hours access)
- USB/removable media activity on sensitive systems
- Mass file access or download from SharePoint/OneDrive
- Unusual printing of sensitive documents
- Access to systems outside normal job function
- Login outside business hours from office network
- Resignation notice followed by data hoarding

---

## 📞 Step 1 — Triage

```
☐ 1.1  Receive alert (DLP, SIEM, manager report, HR tip-off)
☐ 1.2  Identify the individual (role, access level, employment status)
☐ 1.3  Do NOT confront the individual — this is a covert investigation initially
☐ 1.4  Notify HR and Legal immediately
☐ 1.5  Open incident ticket with restricted access (need-to-know only)
☐ 1.6  Determine if malicious or accidental
```

---

## 🔬 Step 2 — Investigation (Covert Phase)

```
☐ 2.1  Pull DLP alerts for the user (email, USB, print, cloud upload)
☐ 2.2  Review SIEM for anomalous data access (volume, timing, type)
☐ 2.3  Check SharePoint/OneDrive download history
☐ 2.4  Review email for forwarding to personal accounts
☐ 2.5  Check USB device insertion logs (Sysmon EventCode 6/7)
☐ 2.6  Preserve all evidence in read-only forensic copies
☐ 2.7  Do not alert the user — evidence preservation is critical
```

### Detect USB Activity (Sysmon)

```spl
index=sysmon EventCode=6 OR EventCode=7
| search ImageLoaded="*\\USB*" OR ImageLoaded="*\\USBSTOR*"
| stats count by host, User, ImageLoaded, _time
| table _time, host, User, ImageLoaded
```

### Detect Large Downloads from SharePoint (M365)

```powershell
# Unified Audit Log search
Search-UnifiedAuditLog -StartDate "2025-01-01" -EndDate "2025-12-31" `
  -UserIds "suspect@company.com" `
  -Operations "FileDownloaded","FileSyncDownloadedFull" |
  Select-Object CreationDate, UserIds, Operations, AuditData |
  Export-Csv insider_audit.csv
```

---

## 🔒 Step 3 — Containment (After Legal Approval)

```
☐ 3.1  Coordinate with HR / Legal before taking visible action
☐ 3.2  Silently revoke access to sensitive systems
☐ 3.3  Disable cloud sync (OneDrive, Dropbox) on endpoint
☐ 3.4  Block outbound email to personal addresses
☐ 3.5  Prepare for account termination (coordinate with HR)
☐ 3.6  Preserve full forensic image of endpoint before termination
```

---

## 📝 Post-Incident

```
☐ 4.1  Conduct exit interview (if not terminated for cause)
☐ 4.2  Revoke all access immediately on departure
☐ 4.3  Review and recover any stolen data if possible
☐ 4.4  Assess legal action with legal team
☐ 4.5  Report to ICO if personal data exfiltrated (GDPR)
☐ 4.6  Review access controls — principle of least privilege audit
☐ 4.7  Implement DLP improvements based on gaps found
```