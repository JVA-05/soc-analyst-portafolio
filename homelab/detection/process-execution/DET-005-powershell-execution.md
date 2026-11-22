# DET-005 — PowerShell Execution

## Detection Overview

| Field | Value |
|---|---|
| Detection ID | DET-005 |
| Name | PowerShell Execution |
| Category | Process Execution |
| Platform | Splunk Enterprise |
| Status | Enabled |
| Severity | Not confirmed |
| Data Source | Sysmon |
| Index | `sysmon` |
| Event ID | 1 — Process Creation |
| Monitored Host | `DESKTOP-1BDISO6` |

## Objective

Monitor PowerShell process creation on the monitored Windows endpoint to provide visibility into command and script execution activity.

PowerShell is a legitimate Windows administration tool, but it is also frequently used by attackers to execute commands, download payloads, perform reconnaissance, and carry out post-exploitation activities.

This detection provides visibility into PowerShell execution and supports further investigation. It does not classify every PowerShell process as malicious.

## Data Sources

- **Log source:** Sysmon
- **Index:** `sysmon`
- **Host:** `DESKTOP-1BDISO6`
- **Event ID:** 1 — Process Creation

### Relevant Fields

- `_time`
- `host`
- `User`
- `Image`
- `ParentImage`
- `CommandLine`

## Detection Logic

The detection searches for Sysmon Process Creation events on the monitored endpoint.

It identifies processes whose executable name matches either:

- `powershell.exe` — Windows PowerShell
- `pwsh.exe` — PowerShell 7 and later

The matching is case-insensitive.

For each matching event, the query returns the timestamp, hostname, user, executable path, parent process, and complete command line.

These fields provide the initial context needed to investigate PowerShell execution.

## SPL Query

```spl
index=sysmon host="DESKTOP-1BDISO6" EventCode=1
| where match(Image, "(?i)\\\\(powershell|pwsh)\\.exe$")
| table _time host User Image ParentImage CommandLine
| sort - _time
```

### Query Explanation

| SPL Component | Purpose |
|---|---|
| `index=sysmon` | Searches Sysmon events. |
| `host="DESKTOP-1BDISO6"` | Restricts the search to the monitored endpoint. |
| `EventCode=1` | Selects process creation events. |
| `match(Image, ...)` | Identifies Windows PowerShell and PowerShell 7 executables. |
| `table` | Displays the relevant investigation fields. |
| `sort - _time` | Displays the newest events first. |

## Alert Configuration

| Setting | Value |
|---|---|
| Alert Name | `SOC - PowerShell Execution` |
| Status | Enabled |
| Search Schedule | Check the configured schedule in Splunk |
| Search Time Range | Check the alert's configured time range |
| Trigger Condition | Check the configured alert trigger condition |
| Alert Actions | Check the configured alert actions |

The SPL does not define the execution frequency, search time range, trigger condition, or notification actions. These settings must be documented from the actual Splunk alert configuration.

## Investigation Guidance

When reviewing PowerShell execution events, the analyst should:

1. Identify the user who launched PowerShell.
2. Examine the `ParentImage` field to determine which process initiated the execution.
3. Review the complete `CommandLine` for suspicious arguments or commands.
4. Look for encoded commands, hidden execution, download operations, and unusual script execution.
5. Correlate the process with Sysmon Event ID 3 (Network Connection) to identify related network activity.
6. Correlate with Sysmon Event ID 11 (FileCreate) to identify files created during execution.
7. Review related PowerShell Operational logs when available.
8. Determine whether the activity is consistent with legitimate administrative or user activity.

## False Positives and Limitations

### Potential False Positives

- Legitimate system administration.
- Software installation and maintenance.
- Automated scripts and scheduled tasks.
- IT troubleshooting activities.
- Authorized remote administration.

### Limitations

- PowerShell execution alone does not establish malicious intent.
- The detection does not inspect command content or determine whether a command is malicious.
- It does not identify all scripting engines or alternative command interpreters.
- It depends on Sysmon Event ID 1 collection and the availability of the `Image`, `ParentImage`, and `CommandLine` fields.
- PowerShell execution through alternative binaries or indirect execution chains may not match this query.

## Validation

The alert is enabled in Splunk.

The user reports that the homelab alert rules have been tested. However, a specific test case and corresponding alert evidence for this detection have not been documented here.

A complete validation record should include:

- PowerShell executable used (`powershell.exe` or `pwsh.exe`).
- User and parent process.
- Command executed.
- Expected detection result.
- Actual alert result.
- Event timestamp or screenshot.

## MITRE ATT&CK Mapping

- **T1059.001 — PowerShell**

This technique covers the abuse of PowerShell for command execution. However, the detection itself only identifies PowerShell process creation. A matching event does not establish that PowerShell was used maliciously.

## Related Incidents

- **INC-001 — Suspicious PowerShell Execution:** Relevant to investigations involving PowerShell process activity.

## Analyst Notes

This detection is intended to provide baseline visibility into PowerShell execution across the monitored endpoint.

It can support investigations involving suspicious command execution, script downloads, remote administration, and potential post-exploitation activity.

Analysts should correlate PowerShell process creation with command-line arguments, parent processes, network connections, and file creation events before determining whether escalation is necessary.
