# HTB Sherlock: Baggage

| Field       | Details    |
| ----------- | ---------- |
| Difficulty  | Easy       |
| Category    | DFIR       |
| Date Solved | 2026-09-24 |
| Status      | Solved     |

---

## Overview

A Shellbag artifact analysis challenge. Shellbags record evidence of folder access by a specific user including access to network shares and archive contents — and can be used to identify data access, staging, and exfiltration attempts.

The evidence is a KAPE collection (target `RegistryHivesUser`) from host `PROD-WORKSTATIO`: the user registry hives (`NTUSER.DAT`, `UsrClass.dat` and their transaction logs) for the accounts `admin` and `steve`. The compromised account is **steve**.

---

## Investigation

### Tools Used

- **ShellBags Explorer** (Eric Zimmerman) - for parsing Shellbags from `UsrClass.dat` (folder browsing history)
- **Registry Explorer** (Eric Zimmerman) - for `NTUSER.DAT` artifacts: UserAssist (program execution), RecentDocs (recently opened files), TypedPaths (paths typed into Explorer)

> Note: the hives were "dirty", so when loading them say **yes** to replaying the transaction logs (`.LOG1` / `.LOG2`). Otherwise recent activity can be missing.

### Key Findings

- Task 1

    What was the name of the archive file downloaded by the compromised account?

    Opening steve's `UsrClass.dat` in ShellBags Explorer, under the **Downloads** folder there is a zip file that was opened like a folder. It was created at 07:25:48, right after the attacker's session started. The zip also shows up in RecentDocs (`NTUSER.DAT`).

    Note: Shellbags show that the zip was **in Downloads**, not the download itself (that would be browser history, which is not in this collection). The download is an inference from where and when the file appeared.

	1.zip

![Screenshot](images/Pasted%20image%2020260928233617.png)

- Task 2

    What was the name of the utility brought in by the attacker to search for sensitive data?

    Following the opened folders under AppData > Local > Temp > Temp1_1.zip > 1 there is `Everything-1.4.1.1028.x64.zip`. When you open a file inside a zip, Windows extracts it to a `Temp1_<zipname>` folder, so this shows what was inside `1.zip`.

    Everything is a legitimate, very fast file search tool and is officially distributed as a portable zip, so the `.zip` name is normal. The attacker brought it in to quickly find sensitive files.

    Shellbags only prove the folder was browsed, not that the program ran. Execution is confirmed by **UserAssist** in `NTUSER.DAT`, which shows `everything.exe` running from `...\Temp\Temp1_Everything-1.4.1.1028.x64.zip\everything.exe` (UserAssist names are ROT13 encoded, Registry Explorer decodes them).

	Everything (Everything 1.4.1.1028)

- Task 3

    The attacker navigated the filesystem and found sensitive files used by the victim in their day-to-day work. When was the VPN folder accessed by the attacker?

    This question is tricky because the folder `Documents\OT Station 3 internal VPN` has several timestamps:

    | Timestamp | Value | Meaning |
    |---|---|---|
    | Created on | 2025-09-03 07:10:58 | When the folder was created (by the victim) |
    | Last accessed on | 2025-09-03 07:11:50 | Folder's own access time, stored inside the Shellbag entry |
    | Last interacted with | 2025-09-03 07:31:05 | When the Shellbag key was last written = when steve's account last opened the folder |

    07:10:58 and 07:11:50 are before the attacker's session started (~07:24), so they are the victim's activity. The attacker's access is the **Last interacted** time.

	2025-09-03 07:31:05

![Screenshot](images/Pasted%20image%2020260928230558.png)

- Task 4

    What was the name of the directory containing the victim's passwords?

    In the Documents folder tree there is a folder named after a well-known password manager (1Password), where the user was keeping the passwords. The attacker browsed it at 07:28:49.

	OnePassword MasterPass

![Screenshot](images/Pasted%20image%2020260928231002.png)

- Task 5

    The attacker also accessed a network share to pillage network data. What is the UNC path?

    Following the threat actor's footsteps, the Shellbags show a network location. The same path is also in **TypedPaths** (`NTUSER.DAT`), which means it was typed directly into the Explorer address bar.

	\\Prod-ns-2\prodshare

![Screenshot](images/Pasted%20image%2020260928232823.png)

- Task 6

    When is the dam construction planned?

    On the share the attacker opened a folder named after the construction project and its planned year: `Construction 2027`.

	2027

![Screenshot](images/Pasted%20image%2020260928232740.png)

- Task 7

    What was the name of the archive file present on the network share?

    The file name shows up in two places:
    - RecentDocs (`NTUSER.DAT`) under `.zip`, next to `1.zip` and `a.zip`
    - Shellbags: user folder > AppData > Local > Temp > Temp1_a.zip > a. This is inside the attacker's staging archive, which proves the file was copied from the share into the staging folder.

	Dam Construction Engineer Plans.zip

- Task 8

    When was the archive file from the network share accessed?

    Looking at the network share in ShellBags Explorer, the value below is the **Last Interacted** time of the `Construction 2027` folder on the share (the folder that held the zip). The zip itself has no separate Shellbag entry on the share, so the folder's interaction time is the closest evidence of when the zip was accessed.

2025-09-03 07:34:04

![Screenshot](images/Pasted%20image%2020260928232959.png)

- Task 9

    The attacker created a staging folder to prepare for collection and exfiltration. What is the full path of the staging folder?

    What stands out is a folder called just `a` in the **Pictures** folder, an unusual place for work data:
    - Folder `a` was created in Pictures at 07:33:16
    - `a.zip` was created in the same folder at 07:34:24
    - When `a.zip` was opened, Windows extracted it to `Temp\Temp1_a.zip\a\`, which contains `Dam Construction Engineer Plans.zip`. This proves `a` held the stolen share data.

    In the Shellbags, Pictures is stored as a Windows known folder ID `{24AD3AD4-A569-4530-98E1-AB02F9417AA8}` = `C:\Users\steve\Pictures`.

	C:\Users\steve\Pictures\a

![Screenshot](images/Pasted%20image%2020260928235135.png)

- Task 10

    The attacker compressed the staging folder to prepare the data for exfiltration. When was the exfiltration archive file accessed?

    Found by following the path to `Pictures\a.zip` and checking the **Last Interacted** time.

2025-09-03 07:34:30

![Screenshot](images/Pasted%20image%2020260928235755.png)

### Attack Timeline

| Time (UTC) 2025-09-03 | Event |
|---|---|
| ~07:24 | steve's session begins (profile activity starts) |
| 07:25:48 | `1.zip` appears in `Downloads` |
| 07:26:23 | `1.zip` opened; contains `Everything-1.4.1.1028.x64.zip` |
| after 07:26 | Everything run from `Temp\Temp1_Everything-1.4.1.1028.x64.zip` (UserAssist) |
| 07:28:49 | `Documents\OnePassword MasterPass` browsed |
| 07:29:34 | `Documents\Engineers Tab` browsed |
| 07:31:05 | `Documents\OT Station 3 internal VPN` browsed |
| 07:32:23 | Network share `\\Prod-ns-2\prodshare` accessed |
| 07:33:16 | Staging folder `C:\Users\steve\Pictures\a` created |
| 07:34:04 | `\\Prod-ns-2\prodshare\Construction 2027` last browsed |
| 07:34:24 | `C:\Users\steve\Pictures\a.zip` created |
| 07:34:40 | `a.zip` opened (contents checked: `a\Dam Construction Engineer Plans.zip`) |

### Indicators of Compromise (IOCs)

| Type      | Value | Description              |
| --------- | ----- | ------------------------ |
| User      | steve | Compromised user account |
| File Name | 1.zip | Archive brought in by the attacker (Downloads) |
| File Name | Everything-1.4.1.1028.x64.zip | Search utility used to find sensitive files |
| File Path | C:\Users\steve\AppData\Local\Temp\Temp1_Everything-1.4.1.1028.x64.zip\everything.exe | Execution location (UserAssist) |
| UNC Path  | \\Prod-ns-2\prodshare | Network share accessed |
| File Name | Dam Construction Engineer Plans.zip | Data taken from the share |
| Folder    | C:\Users\steve\Pictures\a | Staging folder |
| File Path | C:\Users\steve\Pictures\a.zip | Exfiltration archive |

---

## Root Cause

The attacker used steve's account to bring in a legitimate search tool (Everything), used it to find sensitive files (password folder, VPN folder, engineering files), then pulled data from the network share `\\Prod-ns-2\prodshare`. The data was copied into a staging folder with an innocent name (`a`) inside Pictures and compressed into `a.zip`, ready for exfiltration.

What the Shellbags **can't** tell us: how the attacker got access to steve's account in the first place, and whether `a.zip` actually left the network. For that we would need event logs (logons), browser history, and network or proxy logs, which are not in this collection.

---

## YARA Rule

Not applicable. There is no malicious binary in this challenge: the evidence is registry hives only, and Everything is legitimate software. A YARA rule for it would flag every normal install.

---

## Sigma Rule

Detects a portable search tool (Everything) running from a temp folder that Windows creates when a program is launched from inside a zip. That is unusual for normal users and matches what the attacker did here.

```yaml
title: Everything Search Tool Executed From Zip Temp Folder
id: af347ec9-b546-4b2f-ad2b-e16a1604a523
status: experimental
description: >
    Detects execution of the Everything file search utility from a Temp1_* folder,
    which Windows creates when a program is run directly from inside a zip file.
    Seen in HTB Sherlock Baggage, where the attacker used Everything to find sensitive files.
author: bernardasvai
date: 2026-09-24
references:
    - HTB Sherlock - Baggage
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\Everything.exe'
        Image|contains: '\AppData\Local\Temp\Temp'
    condition: selection
falsepositives:
    - IT staff or power users running the portable version of Everything
level: medium
tags:
    - attack.discovery
    - attack.t1083
    - attack.command_and_control
    - attack.t1105
```

### MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|---|---|---|
| Ingress Tool Transfer | T1105 | `1.zip` with Everything brought in to Downloads |
| File and Directory Discovery | T1083 | Everything used to search for sensitive files |
| Unsecured Credentials: Credentials In Files | T1552.001 | `OnePassword MasterPass` folder browsed |
| Data from Network Shared Drive | T1039 | `\\Prod-ns-2\prodshare\Construction 2027` |
| Data Staged: Local Data Staging | T1074.001 | `C:\Users\steve\Pictures\a` |
| Archive Collected Data | T1560 | `a.zip` |

---

## How to Stop This Attack

### Immediate Actions
- Disable / reset steve's account and revoke active sessions
- Isolate PROD-WORKSTATIO for full forensic collection (disk + memory)
- Rotate every password stored in the `OnePassword MasterPass` folder and the VPN credentials
- Check network / proxy logs for `a.zip` leaving the network

### Detection & Prevention
- Alert on portable tools (like Everything) running from Temp or Downloads (Sigma rule above)
- Audit access to sensitive shares like `\\Prod-ns-2\prodshare` (Windows event ID 5140 / 5145)
- Use Shellbags in investigations to reconstruct what an account browsed. They are useful for forensics, but too noisy to alert on directly

### Hardening Recommendations
- Application control (AppLocker / WDAC) to block unapproved executables from user-writable folders
- Don't store passwords in plain folders; use a proper password manager with MFA
- Least privilege on network shares: only the people who need construction plans should have access
- MFA for user accounts to make account takeover harder

---

## What I Learned

From this Sherlock I learned to use ShellBags Explorer to track the attacker's footsteps: which folders they opened, the network share they accessed, and where they staged the data. The tricky part was timestamps. A folder has Created, Accessed and Last Interacted times, and only Last Interacted showed when the attacker was there. I also learned that shellbags show a folder was opened, but not that a program ran; for that you need UserAssist. I also learned about building an incident timeline, Sigma rules for detection, and MITRE ATT&CK mapping.
