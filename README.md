# Splunk Enterprise Threat Hunting Challenge
## Active Directory Compromise Investigation | Capture the Flag (CTF) 8

## Project Overview

This project documents a multi-stage enterprise intrusion investigation completed as part of a Splunk Capture the Flag (CTF) challenge. Using Splunk Enterprise and the Search Processing Language (SPL), I investigated authentication events, Windows Security logs, Sysmon telemetry, VPN activity, process creation, remote administration, credential dumping, Active Directory compromise, data staging, and exfiltration.

The investigation followed the attack from the initial VPN access through credential theft, lateral movement, domain controller compromise, NTDS extraction, file server compromise, and attempted data exfiltration.

---

# Scenario

A systems administrator reported that the Windows Security Event Log on the domain controller had been cleared under his account. The administrator denied performing the action, indicating possible credential compromise.

As the SOC analyst, I investigated the incident to determine:

- How the attacker initially gained access
- Whether administrator credentials were compromised
- How the attacker moved laterally
- Whether Active Directory was compromised
- What sensitive data was targeted
- Whether data exfiltration occurred
- What containment and remediation actions should be recommended

---

# Investigation Highlights

- Investigated Windows Security Event Log clearing (Event ID 1102).
- Identified compromised administrator credentials.
- Traced attacker activity to the originating workstation.
- Investigated abuse of WMIC for remote execution.
- Identified plaintext credentials exposed in command-line arguments.
- Investigated LSASS credential dumping using `comsvcs.dll` and `MiniDump`.
- Correlated VPN logs to identify unauthorized remote access.
- Distinguished malicious VPN sessions from legitimate user activity.
- Investigated attacker reconnaissance and Active Directory enumeration.
- Traced lateral movement from workstation to domain controller and file server.
- Identified Active Directory database extraction using `ntdsutil`.
- Investigated Volume Shadow Copy creation supporting NTDS extraction.
- Traced archive creation and staging of sensitive engineering documents.
- Identified outbound data exfiltration via HTTP POST.
- Reconstructed the complete enterprise attack timeline.

---

# Investigation Workflow

1. Investigated Windows Security Event Log clearing.
2. Confirmed administrator account misuse.
3. Identified the originating workstation.
4. Investigated remote command execution using WMIC.
5. Identified plaintext credentials exposed in process execution.
6. Investigated LSASS credential dumping.
7. Correlated VPN authentication logs.
8. Distinguished attacker VPN sessions from legitimate user activity.
9. Investigated host reconnaissance.
10. Identified Active Directory group enumeration.
11. Traced lateral movement to the Domain Controller.
12. Investigated NTDS database extraction.
13. Investigated Volume Shadow Copy creation.
14. Traced lateral movement to the file server.
15. Investigated archive creation and data staging.
16. Identified outbound data exfiltration.
17. Reconstructed the complete attack timeline.

---

# MITRE ATT&CK Techniques

| Tactic | Technique |
|---------|-----------|
| Initial Access | T1133 – External Remote Services (VPN) |
| Credential Access | T1003.001 – LSASS Memory |
| Credential Access | T1003.003 – NTDS |
| Credential Access | T1552.001 – Credentials in Files / Command-Line |
| Discovery | T1082 – System Information Discovery |
| Discovery | T1069.002 – Domain Group Discovery |
| Lateral Movement | T1047 – Windows Management Instrumentation (WMI) |
| Lateral Movement | T1021.002 – SMB / Admin Shares |
| Defense Evasion | T1070.001 – Clear Windows Event Logs |
| Collection | T1005 – Data from Local System |
| Collection | T1560.001 – Archive via Utility |
| Exfiltration | T1041 – Exfiltration Over C2 Channel |

---

# Tools Used

- Splunk Enterprise
- Search Processing Language (SPL)
- Windows Event Logs
- Sysmon
- VPN Logs
- MITRE ATT&CK Framework

---

# Learning Outcomes

This investigation strengthened my ability to analyze enterprise attacks by correlating authentication events, endpoint telemetry, VPN activity, and Windows Security logs within Splunk. It reinforced investigative techniques for credential theft, Active Directory compromise, lateral movement, and data exfiltration while improving my proficiency with SPL for enterprise threat hunting.
