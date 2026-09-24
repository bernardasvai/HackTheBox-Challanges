# HTB Sherlock: [Challenge Name]

| Field        | Details                     |
|--------------|-----------------------------|
| Difficulty   | Easy / Medium / Hard        |
| Category     | DFIR / Malware / Threat Hunt |
| Date Solved  | YYYY-MM-DD                  |
| Status       | Solved                      |

---

## Overview

> Short description of the scenario. What happened? What is the analyst's role?

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
| IP         |       |             |
| Domain     |       |             |
| File Hash  |       |             |
| File Name  |       |             |
| Registry   |       |             |

---

## Root Cause

> How did the attacker get in / what did the malware do? Explained in my own words.

---

## YARA Rule

> Detects the malware / artifact from this challenge.

```yara
rule HTB_Sherlock_[ChallengeName] {
    meta:
        description = ""
        author      = "bernardasvai"
        date        = "YYYY-MM-DD"
        reference   = "HTB Sherlock - [Challenge Name]"
        severity    = "high"

    strings:
        // Add strings, hex patterns, or conditions found during analysis
        $s1 = "" ascii
        $s2 = "" wide

    condition:
        uint16(0) == 0x5A4D and // PE file
        any of them
}
```

---

## Sigma Rule

> Detection rule for a SIEM (Splunk, Elastic, etc.) to catch this attack pattern.

```yaml
title: HTB Sherlock - [Challenge Name] Detection
id: # generate with: uuidgen
status: experimental
description: >
    Detects activity related to the HTB Sherlock challenge [Challenge Name].
author: bernardasvai
date: YYYY-MM-DD
references:
    - HTB Sherlock - [Challenge Name]
logsource:
    category:   # process_creation / network_connection / file_event / etc.
    product:    # windows / linux
detection:
    selection:
        # Fill in based on what you found
        EventID:
        CommandLine|contains:
    condition: selection
falsepositives:
    - 
level: high
tags:
    - attack.    # MITRE ATT&CK technique, e.g. attack.t1059.001
```

---

## How to Stop This Attack

### Immediate Actions
- 

### Detection & Prevention
- 

### Hardening Recommendations
- 

---

## What I Learned

> Personal notes — what was new, what was tricky, what I'd do faster next time.
