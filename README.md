
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
| 1 | MITRE ATT&CK: T1621 – Multi-Factor Authentication Request Generation (MFA Fatigue / Push Bombing)| T1078 -Valid Accounts & T1114.003 – Email Forwarding Rule & T1564.008 – Hide Artifacts: Email Hiding Rules & T1657 – Financial Theft | 🔴 MITRE Priority: P1 (Critical)|
| 2 | MITRE ATT&CK: T1078 – Valid Accounts | T1621 – Multi-Factor Authentication Request Generation | 🟠 MITRE Priority: P2 (High) |
| 3 | MITRE ATT&CK: T1078 – Valid Accounts | T1078.004 – Valid Accounts: Cloud Accounts | 🟠 MITRE Priority: P2 (High) |
| 4 | MITRE ATT&CK: T1621 – Multi-Factor Authentication Request Generation | T1110 – Brute Force (behavioral overlap) | 🟡 MITRE Priority: P3 (Medium) |
| 5 | MITRE ATT&CK: T1621 – Multi-Factor Authentication Request Generation | T1078 – Valid Accounts | 🔴 MITRE Priority: P1 (Critical) |
| 6 | MITRE ATT&CK: T1114 – Email Collection | T1114.002 – Remote Email Collection | 🔴 MITRE Priority: P1 (Critical) |
| 7 | MITRE ATT&CK: T1078.004 – Valid Accounts: Cloud Accounts | T1204 – User Execution | 🟠 MITRE Priority: P2 (High)|
| 8 | MITRE ATT&CK: T1078.004 – Valid Accounts: Cloud Accounts | T1036 – Masquerading | 🟠 MITRE Priority: P2 (High) |
| 9 | MITRE ATT&CK: T1114 – Email Collection | T1114.002 – Remote Email Collection | 🔴 MITRE Priority: P1 (Critical) |
| 10 | MITRE ATT&CK: T1114.003 – Email Forwarding Rule | T1098 – Account Manipulation | 🔴 MITRE Priority: P1 (Critical) |
| 11 | MITRE ATT&CK: T1114.003 – Email Forwarding Rule | <T1036 – Masquerading & T1098 – Account Manipulation | 🔴 MITRE Priority: P1 (Critical) |
| 12 | MITRE ATT&CK: T1114.003 – Email Forwarding Rule | T1041 – Exfiltration Over C2 Channel & T1098 – Account Manipulation | 🔴 MITRE Priority: P1 (Critical) |
| 13 | MITRE ATT&CK: T1114.003 – Email Forwarding Rule | T1114.001 – Local Email Collection & T1657 – Financial Theft | 🔴 MITRE Priority: P1 (Critical)|
| 14 | MITRE ATT&CK: T1114.003 – Email Forwarding Rule | T1564 – Hide Artifacts & T1098 – Account Manipulation | 🔴 MITRE Priority: P1 (Critical) |
| 15 | MITRE ATT&CK: T1114.003 – Email Forwarding Rule | T1564 – Hide Artifacts & T1098 – Account Manipulation | 🔴 MITRE Priority: P1 (Critical) |
| 16 | MITRE ATT&CK: T1564 – Hide Artifacts | <T1114.003 – Email Forwarding Rule & T1098 – Account Manipulation | 🔴 MITRE Priority: P1 (Critical) |
| 17 | MITRE ATT&CK: T1566.002 – Phishing: Spearphishing Link | T1657 – Financial Theft & T1078 – Valid Accounts | 🔴 MITRE Priority: P1 (Critical) |
| 18 | MITRE ATT&CK: T1566.002 – Phishing: Spearphishing Link | T1657 – Financial Theft & T1078 – Valid Accounts | 🔴 MITRE Priority: P1 (Critical) |
| 19 | MITRE ATT&CK: T1566.002 – Phishing: Spearphishing Link | T1078 – Valid Accounts & T1562 – Impair Defenses | 🔴 MITRE Priority: P1 (Critical)|
| 20 | MITRE ATT&CK: T1078 – Valid Accounts | T1566.002 – Phishing: Spearphishing Link & 1657 – Financial Theft | 🔴 MITRE Priority: P1 (Critical) |
| 21 | MITRE ATT&CK: | <Placeholder> | <Placeholder> |
| 22 | MITRE ATT&CK: | <Placeholder> | <Placeholder> |
| 23 | MITRE ATT&CK: | <Placeholder> | <Placeholder> |
| 24 | MITRE ATT&CK: | <Placeholder> | <Placeholder> |
| 25 | MITRE ATT&CK: | <Placeholder> | <Placeholder> |
| 26 | MITRE ATT&CK: | <Placeholder> | <Placeholder> |
| 27 | MITRE ATT&CK: | <Placeholder> | <Placeholder> |
| 28 | MITRE ATT&CK: | <Placeholder> | <Placeholder> |
| 29 | MITRE ATT&CK: | <Placeholder> | <Placeholder> |
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
The attacker aimed to validate and maintain unauthorized access to the compromised account by authenticating from attacker-controlled infrastructure located outside the user’s normal geographic region.

### 📌 Finding
Successful sign-ins to Mark Smith’s account originated from the Netherlands (NL), which deviates from the user’s expected geographic location. This confirms the use of attacker infrastructure and supports evidence of account compromise via MFA fatigue.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | Azure AD / Microsoft 365 (cloud identity) |
| Timestamp | 2026-02-25 ~22:12–22:25 UTC |
| Process | Azure AD Sign-in (interactive authentication) |
| Parent Process | External authentication request (MFA push) |
| Command Line | N/A — cloud-based authentication event |

### 💡 Why it matters
Geolocation anomalies are a strong indicator of compromise, especially when tied to successful authentication events. A legitimate user operating in one country suddenly authenticating from another (NL) suggests attacker-controlled access. This is a key pivot point to identify attacker infrastructure and confirm unauthorized activity.

### 🔧 KQL Query Used
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| project TimeGenerated, IPAddress, Location, ResultType, AuthenticationRequirement
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="2120" height="1134" alt="image" src="https://github.com/user-attachments/assets/59dec488-082c-4a09-9392-4e0ce5e706ee" />

### 🛠️ Detection Recommendation
Implement detections for impossible travel and anomalous geolocation sign-ins. Correlate successful logins from foreign IPs with MFA events and user behavior baselines. Flag accounts where new countries appear without prior history, especially for high-risk users like finance personnel.

**Hunting Tip:**  
Use `SigninLogs` to compare historical login locations against current activity. Pivot on `IPAddress` and `Location` fields to identify new geographies. Combine with `ResultType == 0` (successful logins) and investigate any first-time country appearances tied to sensitive accounts.

</details>


---

<details>
<summary id="-flag-4">🚩 <strong>Flag 4: <Technique Name></strong></summary>

### 🎯 Objective
The attacker aimed to trigger repeated MFA prompts to fatigue the user into approving a request, enabling unauthorized access to the account.

### 📌 Finding
Multiple authentication attempts from a foreign IP (205.147.16.190 – NL) resulted in error code **50074**, indicating MFA was required but not completed. This pattern is consistent with MFA fatigue/push bombing attempts prior to successful compromise.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | Azure AD / Microsoft 365 (cloud identity) |
| Timestamp | 2026-02-25T22:24:32.869Z |
| Process | Azure AD Sign-in (failed authentication attempt) |
| Parent Process | External authentication request (MFA push attempt) |
| Command Line | N/A — cloud-based authentication event |

### 💡 Why it matters
Error code **50074** is a key indicator of MFA enforcement without completion, often seen during brute-force or MFA fatigue attacks. Repeated occurrences signal an attacker actively attempting to gain access. When followed by a successful login, it confirms the user was eventually coerced into approving MFA, leading to full account compromise.

### 🔧 KQL Query Used
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| project TimeGenerated, IPAddress, Location, ResultType, AuthenticationRequirement
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="1884" height="902" alt="image" src="https://github.com/user-attachments/assets/aa72d50f-6cd4-4149-8b81-d0af4e1b6fd9" />

### 🛠️ Detection Recommendation
Alert on repeated occurrences of **ResultType 50074** for a single user, especially from unfamiliar IP addresses or geolocations. Correlate with subsequent successful logins (**ResultType 0**) to identify potential MFA fatigue success. Implement MFA number matching or phishing-resistant MFA to reduce approval abuse.

**Hunting Tip:**  
Query `SigninLogs` for `ResultType == 50074` and group by `UserPrincipalName` and `IPAddress`. Look for high-frequency attempts followed by a successful authentication from the same IP—this pattern strongly indicates MFA fatigue leading to compromise.

</details>

---

<details>
<summary id="-flag-5">🚩 <strong>Flag 5: <Technique Name></strong></summary>

### 🎯 Objective
The attacker aimed to overwhelm the user with repeated MFA prompts to force an approval, enabling unauthorized access to the account.

### 📌 Finding
The attacker attempted authentication **3 times** from IP **205.147.16.190 (NL)** before achieving a successful login. These failed attempts (MFA not satisfied) followed by a success indicate a classic MFA fatigue/push bombing attack.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | Azure AD / Microsoft 365 (cloud identity) |
| Timestamp | 2026-02-25 ~22:24–22:25 UTC |
| Process | Azure AD Sign-in (failed → successful authentication sequence) |
| Parent Process | External authentication request (MFA push attempts) |
| Command Line | N/A — cloud-based authentication event |

### 💡 Why it matters
A sequence of failed MFA attempts followed by a success is a strong indicator of MFA fatigue. It shows the attacker persisted until the user approved a request, leading directly to account compromise. This pattern is a high-confidence signal of adversary behavior and should trigger immediate response.

### 🔧 KQL Query Used
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| project TimeGenerated, IPAddress, Location, ResultType, AuthenticationRequirement
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="1898" height="742" alt="image" src="https://github.com/user-attachments/assets/b8936703-697d-4a7e-8201-4113989b4388" />


### 🛠️ Detection Recommendation
Detect patterns of repeated failed MFA attempts (e.g., **ResultType 50074 / 50140**) followed by a successful login (**ResultType 0**) from the same IP or location. Alert on rapid authentication attempts from foreign geolocations targeting a single user.

**Hunting Tip:**  
Query `SigninLogs` and filter for failed authentication codes, then sequence events by time. Look for multiple failures from the same IP followed closely by a success. This temporal pattern is a reliable indicator of MFA fatigue leading to compromise.

</details>

---

<details>
<summary id="-flag-6">🚩 <strong>Flag 6: <Technique Name></strong></summary>

### 🎯 Objective
The attacker aimed to access the victim’s mailbox via a web-based application to monitor, manipulate, and send emails for Business Email Compromise activities.

### 📌 Finding
After successfully bypassing MFA, the attacker authenticated to **One Outlook Web**, indicating remote access to the victim’s email via a browser. This aligns with attacker behavior leveraging cloud apps without needing endpoint access.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | Microsoft 365 / Azure AD (cloud application) |
| Timestamp | 2026-02-25 ~21:59–22:01 UTC |
| Process | One Outlook Web (web-based email access) |
| Parent Process | Azure AD successful authentication (ResultType 0) |
| Command Line | N/A — cloud-based application access |

### 💡 Why it matters
Access to Outlook Web gives the attacker full visibility and control over the user’s mailbox. This enables reading conversations, creating inbox rules, and sending fraudulent emails that appear legitimate. It is a critical step in executing Business Email Compromise attacks and financial fraud.

### 🔧 KQL Query Used
SigninLogs
| where IPAddress == "205.147.16.190"
| where ResultType == "0"
| project TimeGenerated, AppDisplayName, AppId
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="1400" height="694" alt="image" src="https://github.com/user-attachments/assets/e453845e-acce-4d81-882c-12b1b44a7b49" />

### 🛠️ Detection Recommendation
Monitor for successful logins to cloud applications like Outlook Web from unfamiliar IPs, locations, or devices. Correlate access to email services with prior suspicious sign-in activity. Alert on first-time application access or abnormal usage patterns for sensitive users.

**Hunting Tip:**  
Query `SigninLogs` and filter for `ResultType == 0`, then review `AppDisplayName`. Pivot on applications like **One Outlook Web** and correlate with IP address and location to identify suspicious access patterns following authentication events.

</details>

---

<details>
<summary id="-flag-7">🚩 <strong>Flag 7: <Technique Name></strong></summary>

### 🎯 Objective
The attacker aimed to access the compromised account from an unmanaged, non-corporate device to avoid detection and maintain stealthy control over the mailbox.

### 📌 Finding
Authentication occurred from a **Linux-based system using Firefox**, which differs from the user’s normal **managed Windows corporate device**. The session was marked as **unmanaged and non-compliant**, confirming attacker-controlled infrastructure.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | Azure AD / Microsoft 365 (cloud identity) |
| Timestamp | 2026-02-25T22:24:32.869Z |
| Process | Browser-based authentication (Firefox 147.0) |
| Parent Process | Azure AD successful sign-in |
| Command Line | N/A — cloud-based authentication event |

### 💡 Why it matters
Device profile anomalies are a strong indicator of compromise. A user who typically logs in from a managed Windows endpoint suddenly authenticating from an unmanaged Linux system suggests unauthorized access. This helps confirm attacker presence and distinguishes legitimate from malicious sessions at scale.

### 🔧 KQL Query Used
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == "205.147.16.190"
| project TimeGenerated, UserAgent, DeviceDetail, ClientAppUsed
| take 5

### 🖼️ Screenshot
<img width="1540" height="762" alt="image" src="https://github.com/user-attachments/assets/b5e57976-2e13-4ae0-90e1-f2dc1639dc43" />


### 🛠️ Detection Recommendation
Implement detections for sign-ins from **unmanaged or non-compliant devices**, especially when paired with new operating systems or browsers. Alert on deviations from known device baselines for users, particularly high-risk roles like finance.

**Hunting Tip:**  
Query `SigninLogs` and compare `DeviceDetail.operatingSystem`, `isManaged`, and `isCompliant` fields against known baselines. Flag sessions where a user shifts from managed Windows devices to unmanaged systems like Linux or unknown browsers.

</details>

---

<details>
<summary id="-flag-8">🚩 <strong>Flag 8: <Technique Name></strong></summary>

### 🎯 Objective
The attacker aimed to access the compromised account using a non-standard browser to blend in as legitimate web traffic while maintaining remote control of the mailbox.

### 📌 Finding
The attacker authenticated using **Firefox 147.0 on Linux**, which differs from the user’s normal browser and corporate device profile. This introduces a third anomaly layer (browser + OS + location), strengthening evidence of account compromise.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | Azure AD / Microsoft 365 (cloud identity) |
| Timestamp | 2026-02-25T22:24:32.869Z |
| Process | Browser-based authentication (Firefox 147.0) |
| Parent Process | Azure AD successful sign-in |
| Command Line | N/A — cloud-based authentication event |

### 💡 Why it matters
Browser fingerprinting is a critical detection signal. A user suddenly switching to a different browser, operating system, and geographic location strongly indicates attacker activity. Layering these anomalies increases confidence in identifying compromised accounts and reduces false positives.

### 🔧 KQL Query Used
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == "205.147.16.190"
| project TimeGenerated, UserAgent, DeviceDetail, ClientAppUsed
| take 5

### 🖼️ Screenshot
<img width="1540" height="762" alt="image" src="https://github.com/user-attachments/assets/bdb3e260-242a-4143-a02e-6df1d9fd92ec" />

### 🛠️ Detection Recommendation
Baseline user browser and device patterns, and alert on deviations such as new browser types or versions. Combine browser anomalies with geolocation and device compliance signals to detect high-confidence compromises.

**Hunting Tip:**  
Query `SigninLogs` and analyze `UserAgent` and `DeviceDetail.browser`. Compare against historical patterns for the user. Look for first-time browser usage combined with new OS and foreign IPs—this multi-layer anomaly is a strong compromise indicator.

</details>

---

<details>
<summary id="-flag-9">🚩 <strong>Flag 9: <Technique Name></strong></summary>

### 🎯 Objective
The attacker aimed to review the victim’s mailbox to gather context, identify financial conversations, and prepare for a targeted Business Email Compromise.

### 📌 Finding
The first post-authentication activity was **MailItemsAccessed**, indicating the attacker immediately began reading emails. This shows reconnaissance within the mailbox rather than immediate persistence or exfiltration.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | Microsoft 365 / Exchange Online |
| Timestamp | 2026-02-25 ~21:56–21:57 UTC |
| Process | MailItemsAccessed (mailbox access activity) |
| Parent Process | Successful Azure AD sign-in (compromised account) |
| Command Line | N/A — cloud-based mailbox activity |

### 💡 Why it matters
Accessing mail items first indicates intent to understand business processes, identify vendors, and locate financial threads. This is a hallmark of BEC attacks, where attackers study communication patterns before impersonating users or initiating fraud.

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
Monitor for **MailItemsAccessed** events from unusual IPs, locations, or devices. Correlate mailbox access immediately following suspicious logins. Flag high-volume or first-time mailbox access from foreign geolocations.

**Hunting Tip:**  
Query `CloudAppEvents` for `ActionType == "MailItemsAccessed"` and correlate with suspicious `SigninLogs`. Focus on first actions after login—early mailbox access is a strong indicator of reconnaissance in BEC scenarios.

</details>

---

<details>
<summary id="-flag-10">🚩 <strong>Flag 10: <Technique Name></strong></summary>

### 🎯 Objective
The attacker aimed to establish persistence within the compromised mailbox by creating inbox rules to monitor, redirect, or hide email communications.

### 📌 Finding
The attacker created **New-InboxRule** entries shortly after gaining access, indicating deliberate persistence. These rules allow the attacker to maintain visibility into communications and potentially forward or conceal emails without user awareness.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | Microsoft 365 / Exchange Online |
| Timestamp | 2026-02-25 ~22:02–22:03 UTC |
| Process | New-InboxRule (mailbox rule creation) |
| Parent Process | Compromised account session via Outlook Web |
| Command Line | N/A — cloud-based mailbox configuration change |

### 💡 Why it matters
Inbox rules are a stealthy persistence mechanism in BEC attacks. They allow attackers to automatically forward emails, delete evidence, or monitor conversations long-term without re-authenticating. This ensures continued access even if the user regains control of the account.

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
Alert on creation of new inbox rules, especially from unfamiliar IPs, devices, or geolocations. Monitor for rules that forward emails externally, move messages to hidden folders, or delete financial communications.

**Hunting Tip:**  
Query `CloudAppEvents` for `ActionType == "New-InboxRule"` and correlate with suspicious sign-in activity. Focus on rules created shortly after anomalous logins—this is a strong indicator of persistence setup in BEC attacks.

</details>

---

<details>
<summary id="-flag-11">🚩 <strong>Flag 11: <Technique Name></strong></summary>

### 🎯 Objective
The attacker aimed to create a stealthy persistence mechanism by configuring an inconspicuous inbox rule that would avoid user detection while maintaining control over email flow.

### 📌 Finding
The attacker created an inbox rule named **"." (single period)**—a minimal, non-descriptive name designed to blend in and evade casual inspection. This indicates deliberate effort to hide persistence within the mailbox.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | Microsoft 365 / Exchange Online |
| Timestamp | 2026-02-25T22:02:33Z |
| Process | New-InboxRule (mailbox rule creation) |
| Parent Process | Compromised Outlook Web session |
| Command Line | N/A — cloud-based mailbox configuration |

### 💡 Why it matters
Attackers often use subtle naming (e.g., ".", "-", or blank-like values) to hide malicious rules. These rules can silently forward, delete, or move emails—allowing long-term persistence and enabling BEC without alerting the user. This is a strong indicator of deliberate evasion and attacker maturity.

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
Alert on inbox rules with suspicious or minimal names (e.g., ".", "-", blank, or random strings). Monitor for rule creation events from anomalous IPs or devices, especially when paired with recent suspicious sign-ins.

**Hunting Tip:**  
Query `CloudAppEvents` for `ActionType == "New-InboxRule"` and inspect rule metadata (e.g., name, actions). Flag rules with non-descriptive names and correlate with foreign IP addresses or unmanaged devices to identify hidden persistence.

</details>

---

<details>
<summary id="-flag-12">🚩 <strong>Flag 12: <Technique Name></strong></summary>

### 🎯 Objective
The attacker aimed to exfiltrate and monitor the victim’s email communications by forwarding messages to an attacker-controlled external email account.

### 📌 Finding
An inbox rule was configured to forward emails to **insights@duck.com**, confirming external data exfiltration and persistent monitoring of the mailbox. This indicates the attacker established a covert channel to receive sensitive communications.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | Microsoft 365 / Exchange Online |
| Timestamp | 2026-02-25T22:02:33Z |
| Process | New-InboxRule (email forwarding rule creation) |
| Parent Process | Compromised Outlook Web session |
| Command Line | N/A — cloud-based mailbox configuration |

### 💡 Why it matters
Forwarding rules to external addresses are a high-confidence indicator of BEC activity. This allows attackers to silently receive all incoming emails, including financial communications, without needing continuous access. It enables long-term surveillance and fraud execution while evading detection.

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
Block or alert on inbox rules that forward to external domains. Implement controls to restrict auto-forwarding outside the organization. Monitor for rule creation events involving external recipients, especially following suspicious sign-ins.

**Hunting Tip:**  
Query `CloudAppEvents` for `ActionType == "New-InboxRule"` and expand rule parameters. Look specifically for `ForwardTo` values containing external domains. Correlate with anomalous IPs, geolocations, and unmanaged devices to confirm malicious persistence and exfiltration.

</details>

---

<details>
<summary id="-flag-13">🚩 <strong>Flag 13: <Technique Name></strong></summary>

### 🎯 Objective
The attacker aimed to selectively capture high-value financial communications (invoices, payments, wire transfers) to facilitate Business Email Compromise and fraudulent fund redirection.

### 📌 Finding
The inbox rule was configured with keywords **"invoice, payment, wire, transfer"**, indicating targeted monitoring and forwarding of financial emails. This shows clear intent to intercept sensitive transactions and execute invoice fraud.

### 🔍 Evidence

|| Field | Value |
|------|-------|
| Host | Microsoft 365 / Exchange Online |
| Timestamp | 2026-02-25T22:02:33Z |
| Process | New-InboxRule (filtered email forwarding rule) |
| Parent Process | Compromised Outlook Web session |
| Command Line | N/A — cloud-based mailbox rule configuration |

### 💡 Why it matters
Keyword-based filtering demonstrates attacker precision. Instead of forwarding all emails, the attacker targets only financially relevant messages, reducing noise and increasing stealth. This is a hallmark of mature BEC operations focused on maximizing financial gain while minimizing detection.

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
Monitor for inbox rules containing financial keywords (e.g., invoice, payment, wire, transfer). Alert on rules combining keyword filters with external forwarding. Implement policies to restrict or review keyword-based forwarding rules.

**Hunting Tip:**  
Query `CloudAppEvents` and expand rule parameters to inspect `SubjectOrBodyContainsWords`. Flag rules that include financial terms, especially when paired with external forwarding addresses and anomalous sign-in activity.

</details>

---

<details>
<summary id="-flag-14">🚩 <strong>Flag 14: <Technique Name></strong></summary>

### 🎯 Objective
The attacker aimed to ensure their malicious inbox rule executed exclusively by preventing any subsequent rules from processing, maximizing stealth and control over targeted emails.

### 📌 Finding
The inbox rule was configured with **StopProcessingRules = True**, ensuring that once the attacker’s rule is triggered, no other mailbox rules (including legitimate user rules) are executed.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | Microsoft 365 / Exchange Online |
| Timestamp | 2026-02-25T22:02:33Z |
| Process | New-InboxRule (mailbox rule configuration) |
| Parent Process | Compromised Outlook Web session |
| Command Line | N/A — cloud-based mailbox rule parameter |

### 💡 Why it matters
This setting ensures complete control over email handling. It prevents legitimate rules (such as alerts, categorization, or forwarding) from executing, allowing the attacker to silently intercept and manipulate sensitive communications without detection. This significantly increases the effectiveness of BEC attacks.

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
Monitor for inbox rules where **StopProcessingRules = True**, especially when combined with external forwarding or keyword filters. Flag such rules as high-risk and review immediately.

**Hunting Tip:**  
Expand `RawEventData.Parameters` in `CloudAppEvents` and search for `StopProcessingRules`. Prioritize rules where this is set to `True` alongside suspicious conditions like external forwarding or financial keywords.

</details>

---

<details>
<summary id="-flag-15">🚩 <strong>Flag 15: <Technique Name></strong></summary>

### 🎯 Objective
The attacker aimed to enhance persistence and concealment by creating an additional stealthy inbox rule to suppress or manipulate sensitive communications, including potential security alerts.

### 📌 Finding
A second inbox rule named **".."** was created shortly after the first. Like the initial rule (“.”), this minimal naming convention is designed to evade detection, indicating layered persistence and defense evasion within the mailbox.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | Microsoft 365 / Exchange Online |
| Timestamp | 2026-02-25T22:03:59Z |
| Process | New-InboxRule (mailbox rule creation) |
| Parent Process | Compromised Outlook Web session |
| Command Line | N/A — cloud-based mailbox configuration |

### 💡 Why it matters
Multiple stealthily named rules indicate a more sophisticated attacker. While one rule forwards financial emails, another may delete alerts or hide evidence. This layered approach increases dwell time, reduces detection, and ensures continued success of the BEC operation.

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
Detect multiple inbox rule creations within a short timeframe, especially with non-descriptive names (e.g., ".", ".."). Flag rules that perform deletion, forwarding, or suppression actions. Monitor for rule stacking behavior after anomalous logins.

**Hunting Tip:**  
Query `CloudAppEvents` for `ActionType == "New-InboxRule"` and group by user and time window. Look for multiple rule creations in quick succession, especially with suspicious naming patterns and actions like forwarding or deleting messages.

</details>

---

<details>
<summary id="-flag-16">🚩 <strong>Flag 16: <Technique Name></strong></summary>

### 🎯 Objective
The attacker aimed to hide evidence of the compromise by automatically suppressing or deleting security-related emails that could alert the user or security team.

### 📌 Finding
A second inbox rule was configured with keywords **"suspicious, security, phishing, unusual, compromised, verify"**, indicating targeted suppression of security alerts and breach notifications.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | Microsoft 365 / Exchange Online |
| Timestamp | 2026-02-25T22:03:59Z |
| Process | New-InboxRule (filtered email rule for suppression) |
| Parent Process | Compromised Outlook Web session |
| Command Line | N/A — cloud-based mailbox rule configuration |

### 💡 Why it matters
This rule demonstrates deliberate defense evasion. By filtering out security-related keywords, the attacker ensures the victim never sees warnings about suspicious activity, password resets, or compromise alerts. This significantly increases dwell time and allows the attacker to operate undetected while executing fraud.

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
Alert on inbox rules containing security-related keywords (e.g., suspicious, phishing, compromised). Monitor for rules that delete or move these messages to hidden folders. Combine this with anomalous sign-in detection for high-confidence compromise alerts.

**Hunting Tip:**  
Query `CloudAppEvents` and expand `SubjectOrBodyContainsWords`. Flag rules targeting security-related terms, especially when paired with external forwarding rules or created from foreign IP addresses and unmanaged devices.

</details>

---

<details>
<summary id="-flag-17">🚩 <strong>Flag 17: <Technique Name></strong></summary>

### 🎯 Objective
The attacker aimed to execute Business Email Compromise by sending a fraudulent invoice from the compromised account to a finance-related employee to initiate unauthorized payment.

### 📌 Finding
A fraudulent email was sent from **m.smith@lognpacific.org** to **j.reynolds@lognpacific.org** from attacker IP **205.147.16.190**, indicating active impersonation and attempted financial fraud.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | Microsoft 365 / Exchange Online |
| Timestamp | 2026-02-25T22:06:39Z |
| Process | Email sent (EmailEvents) |
| Parent Process | Compromised Outlook Web session |
| Command Line | N/A — cloud-based email activity |

### 💡 Why it matters
This confirms the final stage of the attack—fraud execution. The attacker leveraged a trusted internal identity to send a convincing invoice email, increasing the likelihood of payment approval. This is the core objective of BEC attacks and represents direct business risk.

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
Monitor for outbound emails from compromised accounts, especially those sent from unusual IPs or geolocations. Flag emails containing financial language (e.g., invoice, payment) sent shortly after suspicious sign-ins.

**Hunting Tip:**  
Query `EmailEvents` for emails sent from compromised users and correlate with `SigninLogs` using `SenderIPv4`. Look for internal recipients receiving financial-themed emails from anomalous IP addresses.

</details>

---

<details>
<summary id="-flag-18">🚩 <strong>Flag 18: <Technique Name></strong></summary>

### 🎯 Objective
The attacker aimed to increase the success rate of fraud by hijacking an existing email thread and inserting malicious banking details under the guise of a legitimate ongoing conversation.

### 📌 Finding
The attacker sent an email with the subject **"RE: Invoice #INV-2026-0892 - Updated Banking Details"**, indicating **thread hijacking**. Instead of creating a new email, they replied within an existing conversation to appear trusted and legitimate.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | Microsoft 365 / Exchange Online |
| Timestamp | 2026-02-25T22:06:39Z |
| Process | Email sent (thread reply) |
| Parent Process | Compromised Outlook Web session |
| Command Line | N/A — cloud-based email activity |

### 💡 Why it matters
Thread hijacking is a highly effective BEC tactic. By replying within an existing conversation, the attacker bypasses suspicion, inherits trust, and increases the likelihood the recipient will act on the request. This significantly raises the probability of successful financial fraud.

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
Detect reply-chain anomalies, such as emails sent from unusual IPs or devices within existing threads. Monitor for subject lines beginning with "RE:" combined with financial language and sent from anomalous sessions.

**Hunting Tip:**  
Query `EmailEvents` for `Subject startswith "RE:"` and correlate with `SenderIPv4` and `SigninLogs`. Look for replies sent from unfamiliar IPs, locations, or unmanaged devices—especially those containing financial terms like "invoice" or "banking details".

</details>

---

<details>
<summary id="-flag-19">🚩 <strong>Flag 19: <Technique Name></strong></summary>

### 🎯 Objective
The attacker aimed to bypass external email security controls by sending the fraudulent invoice internally, leveraging trust between employees to increase the likelihood of payment approval.

### 📌 Finding
The malicious email was sent with **EmailDirection: Intra-org**, confirming it was delivered internally from one employee to another, avoiding traditional email gateway protections.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | Microsoft 365 / Exchange Online |
| Timestamp | 2026-02-25T22:06:39Z |
| Process | Email sent (internal communication) |
| Parent Process | Compromised Outlook Web session |
| Command Line | N/A — cloud-based email activity |

### 💡 Why it matters
Internal emails are typically trusted and often bypass stricter filtering applied to external messages. This makes BEC attacks significantly more effective, as security controls are weaker and recipients are less suspicious of internal communications.

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
Implement monitoring for anomalous internal email behavior, especially financial requests. Apply conditional access and anomaly detection to flag internal emails sent from unusual IPs, devices, or geolocations.

**Hunting Tip:**  
Query `EmailEvents` for `EmailDirection == "Intra-org"` and correlate with `SigninLogs`. Look for internal emails sent shortly after suspicious logins, particularly those involving financial language or unusual sender behavior.

</details>

---

<details>
<summary id="-flag-20">🚩 <strong>Flag 20: <Technique Name></strong></summary>

### 🎯 Objective
The attacker aimed to execute fraud using the same authenticated session, ensuring continuity between account compromise and malicious email delivery without interruption.

### 📌 Finding
The **SenderIPv4 (205.147.16.190)** on the fraudulent email matches the attacker’s sign-in IP, confirming the same session was used for both authentication and BEC execution.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | Microsoft 365 / Exchange Online |
| Timestamp | 2026-02-25T22:06:39Z |
| Process | Email sent (authenticated session) |
| Parent Process | Compromised Outlook Web session |
| Command Line | N/A — cloud-based email activity |

### 💡 Why it matters
This correlation definitively links the compromise to the fraud activity. It eliminates ambiguity by proving the attacker didn’t just gain access—they actively used that session to execute the attack. This strengthens attribution, accelerates incident response, and supports containment decisions.

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
Correlate `SigninLogs` and `EmailEvents` using IP address, timestamp, and user identity. Flag cases where suspicious sign-in IPs are reused for outbound email activity, especially involving financial or sensitive content.

**Hunting Tip:**  
Join `SigninLogs` and `EmailEvents` on `UserPrincipalName` and IP fields. Look for matching IPs across authentication and email activity within short time windows—this is a strong indicator of active account misuse.

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
