# HTB Sherlock: Baggage

| Field        | Details                     |
|--------------|-----------------------------|
| Difficulty   |                             |
| Category     | DFIR                        |
| Date Solved  | 2026-09-24                  |
| Status       | In Progress                 |

---

## Overview

A Shellbag artifact analysis challenge. Shellbags record evidence of folder access by a specific user — including access to network shares and archive contents — and can be used to identify data access, staging, and exfiltration attempts.

---

## Investigation

### Tools Used

- 

### Key Findings

1. 
2. 
3. 

### Attack Timeline

| Time (UTC) | Event |
|------------|-------|
|            |       |

### Indicators of Compromise (IOCs)

| Type       | Value | Description |
|------------|-------|-------------|
| File Path  |       |             |
| User       |       |             |
| Folder     |       |             |

---

## Root Cause

> What did the Shellbag artifacts reveal? Explained in my own words.

---

## YARA Rule

```yara
rule HTB_Sherlock_Baggage {
    meta:
        description = ""
        author      = "bernardasvai"
        date        = "2026-09-24"
        reference   = "HTB Sherlock - Baggage"
        severity    = "medium"

    strings:
        $s1 = "" ascii
        $s2 = "" wide

    condition:
        any of them
}
```

---

## Sigma Rule

```yaml
title: HTB Sherlock - Baggage Detection
id:
status: experimental
description: >
    Detects suspicious folder access patterns identified in the HTB Sherlock Baggage challenge (Shellbag artifacts).
author: bernardasvai
date: 2026-09-24
references:
    - HTB Sherlock - Baggage
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        TargetObject|contains:
            - 'Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU'
            - 'Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags'
    condition: selection
falsepositives:
    - Normal user folder browsing
level: medium
tags:
    - attack.collection
    - attack.t1074.001
```

---

## How to Stop This Attack

### Immediate Actions
- 

### Detection & Prevention
- Monitor Shellbag registry keys for access to sensitive paths
- 

### Hardening Recommendations
- 

---

## What I Learned

> Personal notes — what was new, what was tricky, what I'd do faster next time.
