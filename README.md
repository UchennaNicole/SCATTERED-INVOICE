
<p align="center">
  <img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/9fea0925-21ba-4ca7-adf0-89cb14ae2d18" />

</p>




# 🛡️ Threat Hunt Report – <Hunt Name>

---

## 📌 Executive Summary

<Brief, high-level overview of the threat hunt.  
Answer what happened, why it matters, and what was discovered in 3–4 sentences.>

---

## 🎯 Hunt Objectives

- Identify malicious activity across endpoints and network telemetry  
- Correlate attacker behavior to MITRE ATT&CK techniques  
- Document evidence, detection gaps, and response opportunities  

---

## 🧭 Scope & Environment

- **Environment:** Microsoft Sentinel (law-cyber-range workspace) – Finance department, LogN Pacific Financial Services   
- **Data Sources:**
- SigninLogs  
- CloudAppEvents  
- EmailEvents   
- **Timeframe:** 2026-02-25 → 2026-02-26 

---

## 📚 Table of Contents

- [🧠 Hunt Overview](#-hunt-overview)
- [🧬 MITRE ATT&CK Summary](#-mitre-attck-summary)
- [🔍 Flag Analysis](#-flag-analysis)
  - [🚩 Flag 1](#-flag-1)
  - [🚩 Flag 2](#-flag-2)
  - [🚩 Flag 3](#-flag-3)
  - [🚩 Flag 4](#-flag-4)
  - [🚩 Flag 5](#-flag-5)
  - [🚩 Flag 6](#-flag-6)
  - [🚩 Flag 7](#-flag-7)
  - [🚩 Flag 8](#-flag-8)
  - [🚩 Flag 9](#-flag-9)
  - [🚩 Flag 10](#-flag-10)
  - [🚩 Flag 11](#-flag-11)
  - [🚩 Flag 12](#-flag-12)
  - [🚩 Flag 13](#-flag-13)
  - [🚩 Flag 14](#-flag-14)
  - [🚩 Flag 15](#-flag-15)
  - [🚩 Flag 16](#-flag-16)
  - [🚩 Flag 17](#-flag-17)
  - [🚩 Flag 18](#-flag-18)
  - [🚩 Flag 19](#-flag-19)
  - [🚩 Flag 20](#-flag-20)
  - [🚩 Flag 21](#-flag-21)
  - [🚩 Flag 22](#-flag-22)
  - [🚩 Flag 23](#-flag-23)
  - [🚩 Flag 24](#-flag-24)
  - [🚩 Flag 25](#-flag-25)
  - [🚩 Flag 26](#-flag-26)
  - [🚩 Flag 27](#-flag-27)
  - [🚩 Flag 28](#-flag-28)
  - [🚩 Flag 29](#-flag-29)
- [🚨 Detection Gaps & Recommendations](#-detection-gaps--recommendations)
- [🧾 Final Assessment](#-final-assessment)
- [📎 Analyst Notes](#-analyst-notes)

---

## 🧠 Hunt Overview

<High-level narrative describing the attack lifecycle, key behaviors observed, and why this hunt matters.>

---

## 🧬 MITRE ATT&CK Summary

| Flag | Technique Category | MITRE ID | Priority |
|-----:|-------------------|----------|----------|
| 1 | MMITRE ATT&CK: T1621 – Multi-Factor Authentication Request Generation (MFA Fatigue / Push Bombing)| T1078 -Valid Accounts & T1114.003 – Email Forwarding Rule & T1564.008 – Hide Artifacts: Email Hiding Rules & T1657 – Financial Theft | 🔴 MITRE Priority: P1 (Critical)|
| 2 | MMITRE ATT&CK: T1078 – Valid Accounts | T1621 – Multi-Factor Authentication Request Generation | 🟠 MITRE Priority: P2 (High) |
| 3 | <Placeholder> | <Placeholder> | <Placeholder> |
| 4 | <Placeholder> | <Placeholder> | <Placeholder> |
| 5 | <Placeholder> | <Placeholder> | <Placeholder> |
| 6 | <Placeholder> | <Placeholder> | <Placeholder> |
| 7 | <Placeholder> | <Placeholder> | <Placeholder> |
| 8 | <Placeholder> | <Placeholder> | <Placeholder> |
| 9 | <Placeholder> | <Placeholder> | <Placeholder> |
| 10 | <Placeholder> | <Placeholder> | <Placeholder> |
| 11 | <Placeholder> | <Placeholder> | <Placeholder> |
| 12 | <Placeholder> | <Placeholder> | <Placeholder> |
| 13 | <Placeholder> | <Placeholder> | <Placeholder> |
| 14 | <Placeholder> | <Placeholder> | <Placeholder> |
| 15 | <Placeholder> | <Placeholder> | <Placeholder> |
| 16 | <Placeholder> | <Placeholder> | <Placeholder> |
| 17 | <Placeholder> | <Placeholder> | <Placeholder> |
| 18 | <Placeholder> | <Placeholder> | <Placeholder> |
| 19 | <Placeholder> | <Placeholder> | <Placeholder> |
| 20 | <Placeholder> | <Placeholder> | <Placeholder> |
| 21 | <Placeholder> | <Placeholder> | <Placeholder> |
| 22 | <Placeholder> | <Placeholder> | <Placeholder> |
| 23 | <Placeholder> | <Placeholder> | <Placeholder> |
| 24 | <Placeholder> | <Placeholder> | <Placeholder> |
| 25 | <Placeholder> | <Placeholder> | <Placeholder> |
| 26 | <Placeholder> | <Placeholder> | <Placeholder> |
| 27 | <Placeholder> | <Placeholder> | <Placeholder> |
| 28 | <Placeholder> | <Placeholder> | <Placeholder> |
| 29 | <Placeholder> | <Placeholder> | <Placeholder> |
---

## 🔍 Flag Analysis

_All flags below are collapsible for readability._

---

<details>
<summary id="-flag-1">🚩 <strong>Flag 1: <Technique Name></strong></summary>

### 🎯 Objective
The attacker was trying to take over Mark Smith’s Microsoft 365 account, impersonate a trusted employee, and redirect a legitimate vendor payment to attacker-controlled banking details.

### 📌 Finding
This was a Business Email Compromise driven by MFA fatigue. The attacker spammed Mark Smith with MFA prompts until one was approved, gained access to his account, created unauthorized inbox rules, and used the compromised mailbox to support a fraudulent wire transfer request.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | N/A — cloud identity / Microsoft 365 account |
| Timestamp | 2026-02-25 evening UTC |
| Process | MFA approval leading to cloud sign-in |
| Parent Process | Account takeover / suspicious sign-in activity |
| Command Line | N/A — cloud-based activity, not endpoint process execution |

### 💡 Why it matters
This matters because the attacker abused a legitimate user account, which makes the activity blend in with normal business operations. Once inside, they were able to manipulate trust, evade quick detection with inbox rules, and trigger real financial impact. Even though the £24,500 transfer was frozen, the incident confirms control failure around identity protection, user awareness, and mailbox monitoring.

### 🔧 KQL Query Used
SigninLogs
| where UserDisplayName has "Mark"
| distinct UserPrincipalName, UserDisplayName

### 🖼️ Screenshot
<img width="972" height="690" alt="image" src="https://github.com/user-attachments/assets/81c52283-b4c0-424b-883f-b6d296ba3244" />

### 🛠️ Detection Recommendation
Detect repeated MFA denials followed by a single approval from unusual IP addresses, devices, or geolocations. Correlate successful sign-ins with new inbox rule creation, suspicious mailbox access, and outbound messages involving payment changes, banking updates, or vendor redirection. Prioritize alerts where finance users are involved.

**Hunting Tip:**  
Start with the compromised identity in `SigninLogs`, then pivot to the source IP, MFA result, device details, and app used. From there, check `CloudAppEvents` for inbox rule creation and mailbox access, then use `EmailEvents` to trace who received the fraudulent payment update.

</details>

---

<details>
<summary id="-flag-2">🚩 <strong>Flag 2: <Technique Name></strong></summary>

### 🎯 Objective
The attacker aimed to gain unauthorized access to Mark Smith’s account by bypassing MFA controls, enabling account takeover to support downstream Business Email Compromise and financial fraud.

### 📌 Finding
Successful sign-ins to Mark Smith’s account originated from an anomalous IP address (205.147.16.190) in the Netherlands during the evening, deviating from his normal usage patterns. This indicates MFA fatigue was successfully exploited, resulting in unauthorized access.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | Azure AD / Microsoft 365 (cloud identity) |
| Timestamp | 2026-02-25 ~22:12–22:25 UTC |
| Process | Azure AD Sign-in (interactive authentication) |
| Parent Process | External authentication request (MFA push) |
| Command Line | N/A — cloud-based authentication event |

### 💡 Why it matters
This confirms the initial access vector of the attack. The use of a foreign IP and successful MFA authentication shows the attacker bypassed identity protections using social engineering (MFA fatigue). This allowed them to operate as a legitimate user, making detection harder and enabling high-impact actions like inbox rule creation and financial fraud.

### 🔧 KQL Query Used
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| project TimeGenerated, IPAddress, Location, ResultType, AuthenticationRequirement
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="2120" height="1134" alt="image" src="https://github.com/user-attachments/assets/6156c910-9427-4c6b-a155-d98af768b636" />

### 🛠️ Detection Recommendation
Implement detections for anomalous sign-ins based on geolocation, impossible travel, and unfamiliar IP addresses. Alert on multiple MFA requests followed by a success from a new location or device. Enforce number matching or phishing-resistant MFA methods to mitigate MFA fatigue attacks.

**Hunting Tip:**  
Query `SigninLogs` for successful authentications (`ResultType == 0`) and compare IP addresses, locations, and authentication methods against a known baseline. Look for sudden geographic shifts, repeated MFA attempts, and new IPs associated with the same user account.

</details>

---

<details>
<summary id="-flag-3">🚩 <strong>Flag 3: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| project TimeGenerated, IPAddress, Location, ResultType, AuthenticationRequirement
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="2120" height="1134" alt="image" src="https://github.com/user-attachments/assets/59dec488-082c-4a09-9392-4e0ce5e706ee" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>


---

<details>
<summary id="-flag-4">🚩 <strong>Flag 4: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| project TimeGenerated, IPAddress, Location, ResultType, AuthenticationRequirement
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="1884" height="902" alt="image" src="https://github.com/user-attachments/assets/aa72d50f-6cd4-4149-8b81-d0af4e1b6fd9" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

<details>
<summary id="-flag-5">🚩 <strong>Flag 5: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| project TimeGenerated, IPAddress, Location, ResultType, AuthenticationRequirement
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="1898" height="742" alt="image" src="https://github.com/user-attachments/assets/b8936703-697d-4a7e-8201-4113989b4388" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

<details>
<summary id="-flag-6">🚩 <strong>Flag 6: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
SigninLogs
| where IPAddress == "205.147.16.190"
| where ResultType == "0"
| project TimeGenerated, AppDisplayName, AppId
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="1400" height="694" alt="image" src="https://github.com/user-attachments/assets/e453845e-acce-4d81-882c-12b1b44a7b49" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

<details>
<summary id="-flag-7">🚩 <strong>Flag 7: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == "205.147.16.190"
| project TimeGenerated, UserAgent, DeviceDetail, ClientAppUsed
| take 5

### 🖼️ Screenshot
<img width="1540" height="762" alt="image" src="https://github.com/user-attachments/assets/b5e57976-2e13-4ae0-90e1-f2dc1639dc43" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

<details>
<summary id="-flag-8">🚩 <strong>Flag 8: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == "205.147.16.190"
| project TimeGenerated, UserAgent, DeviceDetail, ClientAppUsed
| take 5

### 🖼️ Screenshot
<img width="1540" height="762" alt="image" src="https://github.com/user-attachments/assets/bdb3e260-242a-4143-a02e-6df1d9fd92ec" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

<details>
<summary id="-flag-9">🚩 <strong>Flag 9: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
CloudAppEvents
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-26T00:00:00Z))
| where IPAddress == "205.147.16.190"
| project TimeGenerated, ActionType, AccountDisplayName, ObjectName, ObjectType
| order by TimeGenerated asc
| take 10

### 🖼️ Screenshot
<img width="1808" height="632" alt="image" src="https://github.com/user-attachments/assets/f94636e9-afcf-4f13-8573-9cf019cc11ef" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

<details>
<summary id="-flag-10">🚩 <strong>Flag 10: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
CloudAppEvents
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-26T00:00:00Z))
| where IPAddress == "205.147.16.190"
| project TimeGenerated, ActionType, AccountDisplayName, ObjectName, ObjectType
| order by TimeGenerated asc
| take 10

### 🖼️ Screenshot
<img width="1872" height="636" alt="image" src="https://github.com/user-attachments/assets/3ffbba5b-7502-45c2-9c30-15807aa3f9f3" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

<details>
<summary id="-flag-11">🚩 <strong>Flag 11: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
CloudAppEvents
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-26T00:00:00Z))
| where IPAddress == "205.147.16.190"
| project TimeGenerated, ActionType, AccountDisplayName, ObjectName, ObjectType
| order by TimeGenerated asc
| take 10

### 🖼️ Screenshot
<img width="1192" height="342" alt="image" src="https://github.com/user-attachments/assets/fd1f1310-dbd9-4fbd-ad0e-4c00b65e8b7d" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

<details>
<summary id="-flag-12">🚩 <strong>Flag 12: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
CloudAppEvents
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-26T00:00:00Z))
| where IPAddress == "205.147.16.190"
| where ActionType == "New-InboxRule"
| mv-expand Parameters = todynamic(RawEventData).Parameters
| where Parameters.Name == "ForwardTo"
| project TimeGenerated, ForwardTo = tostring(Parameters.Value), RawEventData

### 🖼️ Screenshot
<img width="2270" height="852" alt="image" src="https://github.com/user-attachments/assets/286c1fc5-56f9-4caa-8df4-13550993ac73" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

<details>
<summary id="-flag-13">🚩 <strong>Flag 13: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
CloudAppEvents
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-26T00:00:00Z))
| where IPAddress == "205.147.16.190"
| where ActionType == "New-InboxRule"
| mv-expand Parameters = todynamic(RawEventData).Parameters
| where Parameters.Name == "ForwardTo"
| project TimeGenerated, ForwardTo = tostring(Parameters.Value), RawEventData

### 🖼️ Screenshot
<img width="2246" height="890" alt="image" src="https://github.com/user-attachments/assets/de155da3-3f88-41bc-9324-2b498e7928ff" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

<details>
<summary id="-flag-14">🚩 <strong>Flag 14: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
CloudAppEvents
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-26T00:00:00Z))
| where IPAddress == "205.147.16.190"
| where ActionType == "New-InboxRule"
| mv-expand Parameters = todynamic(RawEventData).Parameters
| where Parameters.Name == "ForwardTo"
| project TimeGenerated, ForwardTo = tostring(Parameters.Value), RawEventData

### 🖼️ Screenshot
<img width="2260" height="896" alt="image" src="https://github.com/user-attachments/assets/8a186d5e-7c4f-439f-8135-543ac70da242" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

<details>
<summary id="-flag-15">🚩 <strong>Flag 15: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
CloudAppEvents
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-26T00:00:00Z))
| where IPAddress == "205.147.16.190"
| where ActionType == "New-InboxRule"
| mv-expand Parameters = todynamic(RawEventData).Parameters
| where Parameters.Name == "Name"
| project TimeGenerated, RuleName = tostring(Parameters.Value)
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="1546" height="866" alt="image" src="https://github.com/user-attachments/assets/727512bb-87e4-4ac3-803c-cec48e627647" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

<details>
<summary id="-flag-16">🚩 <strong>Flag 16: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
CloudAppEvents
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-26T00:00:00Z))
| where IPAddress == "205.147.16.190"
| where ActionType == "New-InboxRule"
| mv-expand Parameters = todynamic(RawEventData).Parameters
| where Parameters.Name == "SubjectOrBodyContainsWords"
| project TimeGenerated, RuleName = tostring(Parameters.Name), Keywords = tostring(Parameters.Value)
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="1598" height="844" alt="image" src="https://github.com/user-attachments/assets/3ce3a99a-f491-4283-8a88-7aa614f5013a" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

<details>
<summary id="-flag-17">🚩 <strong>Flag 17: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
EmailEvents
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-26T00:00:00Z))
| where SenderFromAddress == "m.smith@lognpacific.org"
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, 
          Subject, SenderIPv4, DeliveryAction, EmailDirection
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="1910" height="688" alt="image" src="https://github.com/user-attachments/assets/490011b8-89a4-4073-b072-df5d946a51fc" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

<details>
<summary id="-flag-18">🚩 <strong>Flag 18: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
EmailEvents
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-26T00:00:00Z))
| where SenderFromAddress == "m.smith@lognpacific.org"
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, 
          Subject, SenderIPv4, DeliveryAction, EmailDirection
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="1934" height="818" alt="image" src="https://github.com/user-attachments/assets/4271ab49-abc2-4640-9a03-f2264272ff41" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

<details>
<summary id="-flag-19">🚩 <strong>Flag 19: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
EmailEvents
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-26T00:00:00Z))
| where SenderFromAddress == "m.smith@lognpacific.org"
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, 
          Subject, SenderIPv4, DeliveryAction, EmailDirection
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="1276" height="976" alt="image" src="https://github.com/user-attachments/assets/289defba-4f99-45d6-8fdd-158d6f7a9b83" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

<details>
<summary id="-flag-20">🚩 <strong>Flag 20: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
EmailEvents
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-26T00:00:00Z))
| where SenderFromAddress == "m.smith@lognpacific.org"
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, 
          Subject, SenderIPv4, DeliveryAction, EmailDirection
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="1140" height="856" alt="image" src="https://github.com/user-attachments/assets/90d97795-b16d-42e4-b387-ed19e9fcf945" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

<details>
<summary id="-flag-21">🚩 <strong>Flag 21: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
CloudAppEvents
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-26T00:00:00Z))
| where IPAddress == "205.147.16.190"
| where ActionType == "FileAccessed"
| project TimeGenerated, ActionType, Application, ObjectName, ObjectType, AccountDisplayName
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="1848" height="664" alt="image" src="https://github.com/user-attachments/assets/739ce2e4-ab12-4252-a8f0-31e7b272b794" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

<details>
<summary id="-flag-22">🚩 <strong>Flag 22: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
CloudAppEvents
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-26T00:00:00Z))
| where IPAddress == "205.147.16.190"
| distinct Application

### 🖼️ Screenshot
<img width="1528" height="756" alt="image" src="https://github.com/user-attachments/assets/6d3f3b0c-a30b-463d-9597-3747ed81c201" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

<details>
<summary id="-flag-23">🚩 <strong>Flag 23: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
CloudAppEvents
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-26T00:00:00Z))
| where IPAddress == "205.147.16.190"
| where ActionType == "New-InboxRule"
| extend AADSessionId = tostring(todynamic(RawEventData).AppAccessContext.AADSessionId)
| project TimeGenerated, AADSessionId
| distinct AADSessionId

### 🖼️ Screenshot
<img width="1576" height="748" alt="image" src="https://github.com/user-attachments/assets/ac3a3a7d-77cf-445d-9d52-8b41755fe58a" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

<details>
<summary id="-flag-24">🚩 <strong>Flag 24: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
SigninLogs
| where IPAddress == "205.147.16.190"
| where ResultType == "0"
| project TimeGenerated, ConditionalAccessStatus, ConditionalAccessPolicies
| order by TimeGenerated asc
| take 5

### 🖼️ Screenshot
<img width="1908" height="818" alt="image" src="https://github.com/user-attachments/assets/55f264a5-6f14-4ac7-bdf5-c789ea035b4e" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

<details>
<summary id="-flag-25">🚩 <strong>Flag 25: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
MFA fatigue / push bombing is a social engineering technique where an attacker repeatedly sends MFA push notifications to overwhelm the victim into approving one. MITRE ATT&CK categorises this under the credential access tactic.

T1621

Multi-Factor Authentication Request Generation — adversaries attempt to bypass MFA by generating repeated authentication requests, exploiting the human tendency to approve prompts to stop the noise. Exactly what happened to Mark Smith on the evening of 25 February.

### 🔧 KQL Query Used
<Add KQL here>

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

<details>
<summary id="-flag-26">🚩 <strong>Flag 26: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
Inbox rules used to hide attacker activity fall under the Email Hiding Rules sub-technique in MITRE ATT&CK under the Defence Evasion tactic.

T1564.008

Hide Artifacts: Email Hiding Rules — adversaries create inbox rules to automatically move, delete, or forward emails to conceal their activity from the victim. Exactly what the attacker did with both the . forwarding rule and the .. deletion rule to hide financial emails and security alerts from Mark.

### 🔧 KQL Query Used
<Add KQL here>

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

<details>
<summary id="-flag-27">🚩 <strong>Flag 27: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
The threat group described — financially motivated, targeting MFA fatigue, BEC, hospitality and retail sectors, known for MGM Resorts and Caesars Entertainment attacks — is Scattered Spider (UNC3944). Their known methodology involves purchasing credentials harvested by a specific malware category sold on dark web marketplaces.

Infostealer

Infostealer malware silently harvests saved passwords, session cookies, browser credentials, and autofill data from infected machines and exfiltrates them to attacker-controlled infrastructure. These logs are then sold on dark web markets like Russian Market and 2easy. Scattered Spider purchases these stealer logs to obtain valid credentials before launching MFA fatigue attacks — meaning Mark's password was likely already compromised long before the evening of 25 February.

### 🔧 KQL Query Used
<Add KQL here>

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

<details>
<summary id="-flag-28">🚩 <strong>Flag 28: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
Disabling the account immediately blocks all access — session, password, everything — in a single action. It's often cited as the single most important first containment step in BEC incidents.

### 🔧 KQL Query Used
<Add KQL here>

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

<details>
<summary id="-flag-29">🚩 <strong>Flag 29: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
Every TTP in this investigation matches their known playbook: MFA fatigue/push bombing, help desk social engineering, BEC targeting finance teams, use of legitimate cloud infrastructure, and high-profile attacks on MGM Resorts and Caesars Entertainment in 2023.

Scattered Spider

Also tracked as UNC3944 and Octo Tempest by various vendors. A financially motivated threat group known for native English speakers, sophisticated social engineering, and living-off-the-land techniques inside Microsoft 365 environments. This investigation matches their signature end-to-end.

### 🔧 KQL Query Used
<Add KQL here>

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

## 🚨 Detection Gaps & Recommendations

### Observed Gaps
- <Placeholder>
- <Placeholder>
- <Placeholder>

### Recommendations
- <Placeholder>
- <Placeholder>
- <Placeholder>

---

## 🧾 Final Assessment

<Concise executive-style conclusion summarizing risk, attacker sophistication, and defensive posture.>

---

## 📎 Analyst Notes

- Report structured for interview and portfolio review  
- Evidence reproducible via advanced hunting  
- Techniques mapped directly to MITRE ATT&CK  

---
