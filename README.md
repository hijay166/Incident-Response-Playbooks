# Incident-Response-Playbooks
Incident Response Playbooks for several cyber incidents 

# 📋 Incident Response Playbooks

> A collection of structured Incident Response (IR) playbooks for the 5 most common security incidents. Built following NIST SP 800-61 Rev 2 and SANS IR frameworks. Designed for Tier 1/2 SOC analysts.

---

## 📁 Playbooks

| # | Incident Type | Severity | MITRE Coverage |
|---|--------------|----------|----------------|
| 1 | [Ransomware](./playbooks/ransomware.md) | 🔴 Critical | T1486, T1490, T1489 |
| 2 | [Phishing / BEC](./playbooks/phishing.md) | 🟠 High | T1566, T1078, T1534 |
| 3 | [Insider Threat](./playbooks/insider-threat.md) | 🟠 High | T1078, T1052, T1530 |
| 4 | [DDoS Attack](./playbooks/ddos.md) | 🟡 Medium | T1498, T1499 |
| 5 | [Credential Stuffing](./playbooks/credential-stuffing.md) | 🟠 High | T1110.004, T1078 |

---

## 🔄 IR Lifecycle (NIST SP 800-61)

```
┌─────────────┐
│ Preparation │ ← This repo!
└──────┬──────┘
       ▼
┌─────────────────────┐
│ Detection & Analysis│
└──────┬──────────────┘
       ▼
┌──────────────────────────────┐
│ Containment, Eradication     │
│ & Recovery                   │
└──────┬───────────────────────┘
       ▼
┌──────────────────┐
│ Post-Incident    │
│ Activity         │
└──────────────────┘
```

---

## ⚡ Severity Definitions

| Level | Response Time | Description |
|-------|-------------|-------------|
| 🔴 Critical | Immediate (< 15 min) | Active breach, ransomware, data exfil in progress |
| 🟠 High | < 1 hour | Confirmed compromise, lateral movement |
| 🟡 Medium | < 4 hours | Suspicious activity, policy violation |
| 🟢 Low | < 24 hours | Anomaly, single indicator, no confirmed breach |

---

## 📌 Connect

- GitHub: [github.com/hijay166](https://github.com/hijay166)
- LinkedIn: [linkedin.com/in/tobi-bolaji-0861b218b](https://linkedin.com/in/tobi-bolaji-0861b218b/)
