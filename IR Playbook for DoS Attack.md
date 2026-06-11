# 🟡 IR Playbook: DDoS Attack

**Severity:** MEDIUM–HIGH (depending on impact)  
**MITRE Techniques:** T1498 (Network DoS), T1499 (Endpoint DoS)  
**Author:** Tobi Bolaji

---

## 🚨 Indicators

- Sudden spike in inbound traffic (10x+ normal baseline)
- Website / API returning 503 / timeout errors
- Network bandwidth saturated
- CPU/memory exhaustion on web servers
- Large volume of requests from single or distributed IPs
- Firewall drop counters spiking

---

## 📞 Step 1 — Triage

```
☐ 1.1  Confirm attack (rule out legitimate traffic spike — sale, news coverage)
☐ 1.2  Identify attack type: volumetric, protocol, or application layer (L3/L4 or L7)
☐ 1.3  Determine impact: which services are affected?
☐ 1.4  Contact ISP / CDN / DDoS mitigation provider immediately
☐ 1.5  Open incident ticket — notify management of potential outage
```

---

## 🔒 Step 2 — Containment

### Volumetric (L3/L4) Attack
```
☐ 2.1  Enable upstream scrubbing (Cloudflare, Akamai, ISP blackholing)
☐ 2.2  Implement BGP blackhole routing for attack sources
☐ 2.3  Contact ISP for null-route assistance
☐ 2.4  Apply ACLs to block source IP ranges at perimeter
```

### Application Layer (L7 / HTTP Flood)
```
☐ 2.5  Enable WAF rate limiting rules
☐ 2.6  Enable CAPTCHA / JS challenge on affected endpoints
☐ 2.7  Implement IP reputation blocking
☐ 2.8  Tune rate limits on load balancer (nginx, HAProxy)
```

### Quick nginx Rate Limiting
```nginx
# In nginx.conf:
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;

server {
    location /api/ {
        limit_req zone=api burst=20 nodelay;
    }
}
```

---

## 📊 Step 3 — Analysis

```
☐ 3.1  Capture traffic sample for analysis (tcpdump / Wireshark)
☐ 3.2  Identify attack vectors (UDP flood, SYN flood, HTTP GET flood, DNS amplification)
☐ 3.3  Identify attack source (single IP, botnet, reflection)
☐ 3.4  Check if DDoS is a smokescreen for another attack (check other logs!)
☐ 3.5  Document attack timeline, peak volume, affected services
```

---

## 🔄 Recovery & Post-Incident

```
☐ 4.1  Confirm services restored — monitor for repeat attack
☐ 4.2  Review and tune rate limiting rules
☐ 4.3  Evaluate permanent DDoS mitigation solution
☐ 4.4  Document attack profile and update detection thresholds
☐ 4.5  Notify stakeholders of resolution
```

---
---

# 🟠 IR Playbook: Credential Stuffing

**Severity:** HIGH  
**MITRE Techniques:** T1110.004 (Credential Stuffing), T1078 (Valid Accounts)  
**Author:** Tobi Bolaji

---

## 🚨 Indicators

- High volume of failed logins across many different accounts
- Login attempts from same IP / ASN / VPN exit nodes
- Successful logins from unusual geolocations
- Login from IPs associated with residential proxies / Tor
- Spike in account lockouts
- Password reset requests at scale

---

## 📞 Step 1 — Triage

```
☐ 1.1  Alert from SIEM: mass failed logins across multiple accounts
☐ 1.2  Confirm pattern: different accounts, same or few IPs = credential stuffing
☐ 1.3  Identify source IPs / ASNs
☐ 1.4  Determine: have any accounts been successfully compromised?
☐ 1.5  Escalate if any successful logins confirmed
```

### SPL Detection Query

```spl
index=wineventlog EventCode=4625
| stats count as failures, dc(user) as unique_accounts, values(user) as accounts by src_ip
| where failures > 50 AND unique_accounts > 10
| eval alert="Credential Stuffing Detected"
| table src_ip, failures, unique_accounts, accounts, alert
```

---

## 🔒 Step 2 — Containment

```
☐ 2.1  Block attacking IPs / IP ranges on WAF and firewall
☐ 2.2  Enable CAPTCHA on login pages
☐ 2.3  Implement temporary rate limiting on authentication endpoint
☐ 2.4  Force password reset for all accounts with successful logins from suspicious IPs
☐ 2.5  Notify users of suspicious login attempts
☐ 2.6  Enable / enforce MFA for affected accounts
```

---

## 🔬 Step 3 — Investigation

```
☐ 3.1  Identify all successfully compromised accounts
☐ 3.2  Review activity of compromised accounts (what did attacker access?)
☐ 3.3  Check HaveIBeenPwned API for exposed credentials
☐ 3.4  Identify credential source (leaked database, dark web)
☐ 3.5  Check if credentials are in known breach dumps
```

### Check HaveIBeenPwned API

```python
import requests, hashlib

def check_pwned(password):
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    resp = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
    for line in resp.text.splitlines():
        h, count = line.split(":")
        if h == suffix:
            return int(count)
    return 0
```

---

## 📝 Post-Incident

```
☐ 4.1  Force password reset for all compromised accounts
☐ 4.2  Mandatory MFA rollout for all users
☐ 4.3  Implement breached password detection (check against HIBP on login)
☐ 4.4  Review and update WAF rules
☐ 4.5  Report to ICO if personal data accessed (GDPR)
☐ 4.6  Notify affected users
```