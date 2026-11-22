# DET-004 — Office Spawning Shell

## Detection Overview

| Field | Value |
|---|---|
| Detection ID | DET-004 |
| Name | Office Spawning Shell |
| Category | Process Execution |
| Platform | Splunk Enterprise |
| Status | Enabled |
| Severity | Not confirmed |
| Data Source | Sysmon |
| Index | `sysmon` |
| Event ID | 1 — Process Creation |
| Monitored Host | `DESKTOP-1BDISO6` |

## Objective

Detect command interpreters and scripting engines launched directly by Microsoft Office applications on the monitored Windows endpoint.

Microsoft Office applications such as Word, Excel, and PowerPoint normally should not need to launch command interpreters during routine document usage. This behavior may indicate malicious document activity, macro abuse, or execution of commands initiated through an Office application.

The detection identifies the parent-child process relationship. It does not independently establish malicious activity.

## Data Sources

- **Log source:** Sysmon
- **Index:** `sysmon`
- **Host:** `DESKTOP-1BDISO6`
- **Event ID:** 1 — Process Creation

### Relevant Fields

- `_time`
- `host`
- `User`
- `ParentImage`
- `Image`
- `CommandLine`

## Detection Logic

The detection searches for Sysmon Process Creation events and applies two conditions:

**1. Parent process identification**

The parent process must be one of the following Microsoft Office applications:

- `WINWORD.EXE` — Microsoft Word
- `EXCEL.EXE` — Microsoft Excel
- `POWERPNT.EXE` — Microsoft PowerPoint

**2. Child process identification**

The process launched by Office must match one of the following interpreters:

- `powershell.exe`
- `pwsh.exe`
- `cmd.exe`
- `wscript.exe`
- `cscript.exe`
- `mshta.exe`

The matching is case-insensitive.

The query displays the event timestamp, hostname, user, parent process, child process, and command line for investigation.

## SPL Query

```spl
index=sysmon host="DESKTOP-1BDISO6" EventCode=1
| where match(ParentImage, "(?i)\\\\(winword|excel|powerpnt)\\.exe$")
| where match(Image, "(?i)\\\\(powershell|pwsh|cmd|wscript|cscript|mshta)\\.exe$")
| table _time host User ParentImage Image CommandLine
| sort - _time
```

### Query Explanation

| SPL Component | Purpose |
|---|---|
| `index=sysmon` | Searches Sysmon events. |
| `host="DESKTOP-1BDISO6"` | Restricts the search to the monitored endpoint. |
| `EventCode=1` | Selects process creation events. |
| `match(ParentImage, ...)` | Identifies Microsoft Word, Excel, and PowerPoint as parent processes. |
| `match(Image, ...)` | Identifies command interpreters and scripting engines launched by Office. |
| `table` | Displays the relevant investigation fields. |
| `sort - _time` | Displays the newest events first. |

## Alert Configuration

| Setting | Value |
|---|---|
| Alert Name | `SOC - Office Spawning Shell` |
| Status | Enabled |
| Search Schedule | Check the configured schedule in Splunk |
| Search Time Range | Check the alert's configured time range |
| Trigger Condition | Check the configured alert trigger condition |
| Alert Actions | Check the configured alert actions |

The SPL does not define the execution frequency, search time range, trigger condition, or notification actions. These settings must be documented from the actual Splunk alert configuration.

## Investigation Guidance

When this detection triggers, the analyst should:

1. Identify the Office application that launched the child process.
2. Review the affected user and timestamp.
3. Examine the complete `CommandLine` to identify executed commands, scripts, URLs, or encoded arguments.
4. Correlate the child process with Sysmon Event ID 1 to identify its descendants.
5. Review related PowerShell, script execution, and network activity.
6. Determine whether the process was associated with a legitimate document or an unexpected activity.
7. Escalate when suspicious execution, payload retrieval, persistence, or other malicious behavior is identified.

## False Positives and Limitations

### Potential False Positives

- Legitimate Office add-ins or integrations.
- Authorized administrative scripts launched from Office workflows.
- Documents that legitimately invoke external applications.
- User-initiated automation or reporting workflows.

### Limitations

- The detection identifies process relationships, not malicious intent.
- It only monitors Word, Excel, and PowerPoint as parent processes.
- It does not detect interpreters launched indirectly through intermediate processes.
- It does not inspect the contents of scripts or documents.
- It depends on Sysmon Event ID 1 collection and the availability of `ParentImage`, `Image`, and `CommandLine`.

## Validation

The alert is enabled in Splunk.

The user reports that the homelab alert rules have been tested. However, a specific test case and corresponding event evidence for this detection have not been documented here.

A complete validation record should include:

- Office application used as the parent process.
- Child interpreter launched.
- Command line observed.
- Expected detection result.
- Actual alert result.
- Event timestamp or screenshot.

## MITRE ATT&CK Mapping

- **T1059 — Command and Scripting Interpreter**

This is a broad mapping covering the execution of commands and scripts through interpreters. More specific sub-techniques should only be assigned when the observed child process and activity support them.

## Related Incidents

No incident currently linked to this detection.

## Analyst Notes

Office applications launching command interpreters is a behavior that deserves investigation, particularly when the child process executes encoded commands, downloads content, or launches additional processes.

A matching event should be treated as a suspicious behavior indicator, not automatic confirmation of compromise.

Correlate process creation with command-line activity, network connections, file creation, and the user's activity before determining the appropriate response.
