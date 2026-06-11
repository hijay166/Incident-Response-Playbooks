# 🟠 IR Playbook: Phishing / Business Email Compromise (BEC)

**Severity:** HIGH  
**Target Response Time:** < 1 hour  
**MITRE Techniques:** T1566 (Phishing), T1078 (Valid Accounts), T1534 (Internal Spearphishing)  
**Author:** Tobi Bolaji

---

## 🚨 Indicators of Compromise

- Suspicious email reported by user
- Email with malicious attachment (macro-enabled doc, zip, ISO)
- Email with credential-harvesting link
- User clicked link / opened attachment
- Inbox rules created (forward all mail externally)
- Unusual login from foreign IP / outside business hours
- Password reset requests user didn't initiate
- Unexpected MFA prompts

---

## 📞 Step 1 — Detection & Triage

```
☐ 1.1  Receive phishing report (user / SIEM / email gateway alert)
☐ 1.2  Obtain a copy of the suspicious email (as .eml if possible)
☐ 1.3  Determine: did the user click? Did they enter credentials?
☐ 1.4  Check email gateway for other recipients of same email
☐ 1.5  Open incident ticket — assign severity (HIGH if credentials entered)
☐ 1.6  Escalate to IR lead if credentials compromised or malware executed
```

---

## 🔬 Step 2 — Email Analysis

### Extract and Analyse Email Headers

```bash
# View full headers in Outlook: File > Properties > Internet headers
# Key fields to check:
# - Return-Path (does it match From?)
# - Received-SPF (pass/fail/softfail?)
# - DKIM-Signature (valid?)
# - X-Originating-IP (where did it really come from?)
# - Reply-To (different from From? Red flag)
```

### Analyse URLs / Attachments (SAFELY — in sandbox)

```bash
# URL analysis
curl -s "https://urlscan.io/api/v1/scan/" -H "Content-Type: application/json" \
  -d '{"url":"SUSPICIOUS_URL","visibility":"private"}'

# File hash check
sha256sum suspicious_attachment.docx
# Look up on VirusTotal: https://www.virustotal.com/

# Sandbox detonation
# → Any.run: https://any.run/
# → Hybrid Analysis: https://www.hybrid-analysis.com/
```

**Email analysis checklist:**
```
☐ 2.1  Check SPF / DKIM / DMARC records
☐ 2.2  Analyse sender domain (WHOIS — registration date, lookalike?)
☐ 2.3  Analyse URLs — destination, redirects, landing page
☐ 2.4  Detonate attachment in sandbox
☐ 2.5  Extract all IOCs (IPs, URLs, hashes, domains)
☐ 2.6  Block IOCs on email gateway, proxy, and firewall
```

---

## 🔒 Step 3 — Containment

```
☐ 3.1  Pull / quarantine the email from ALL mailboxes (purge from Exchange/M365)
☐ 3.2  Block sender domain and IP on email gateway
☐ 3.3  Block malicious URLs on web proxy
☐ 3.4  If credentials entered: reset user password IMMEDIATELY
☐ 3.5  If credentials entered: revoke all active sessions (M365: Revoke Sessions)
☐ 3.6  Enable MFA if not already active
☐ 3.7  Search SIEM for other users who received / clicked the same email
```

### M365 — Purge Phishing Email from All Mailboxes

```powershell
# Connect to Exchange Online
Connect-ExchangeOnline

# Search and purge
New-ComplianceSearch -Name "PhishingPurge" -ExchangeLocation all `
  -ContentMatchQuery "Subject:'PHISHING SUBJECT LINE'"
Start-ComplianceSearch -Identity "PhishingPurge"

# Purge (SoftDelete = moves to Recoverable Items)
New-ComplianceSearchAction -SearchName "PhishingPurge" -Purge -PurgeType SoftDelete
```

---

## 🔬 Step 4 — Investigation (if credentials compromised)

```
☐ 4.1  Pull Azure AD / M365 sign-in logs for affected user
☐ 4.2  Check for impossible travel (login from UK and Nigeria in same hour?)
☐ 4.3  Check for inbox rules created (forwarding to external address?)
☐ 4.4  Check sent items for internal phishing (spearphishing from compromised account)
☐ 4.5  Check for new MFA methods added (adversary adding their own phone)
☐ 4.6  Check for OAuth app consent grants
☐ 4.7  Review file access / SharePoint / OneDrive downloads
☐ 4.8  Determine if financial transactions were requested (BEC)
```

### Check M365 Inbox Rules

```powershell
Get-InboxRule -Mailbox "user@company.com" | 
  Select-Object Name, Enabled, ForwardTo, ForwardAsAttachmentTo, RedirectTo, DeleteMessage |
  Format-List
```

---

## 🧹 Step 5 — Eradication & Recovery

```
☐ 5.1  Remove malicious inbox rules
☐ 5.2  Remove any OAuth apps the attacker consented to
☐ 5.3  Remove attacker-added MFA devices
☐ 5.4  Scan endpoint for malware if attachment was opened
☐ 5.5  Re-enable account only after all access is secured
☐ 5.6  Alert finance team if BEC (fraudulent payment requests)
```

---

## 📝 Step 6 — Post-Incident

```
☐ 6.1  Document all IOCs and share with threat intel team
☐ 6.2  Update email gateway blocklist
☐ 6.3  Send awareness notification to all staff
☐ 6.4  Report to ICO if personal data accessed (GDPR)
☐ 6.5  Run targeted phishing simulation to test improvement
```