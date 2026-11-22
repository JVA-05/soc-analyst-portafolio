# DET-007 — Suspicious PowerShell

## Detection Overview

| Field | Value |
|---|---|
| Detection ID | DET-007 |
| Name | Suspicious PowerShell |
| Category | Process Execution |
| Platform | Splunk Enterprise |
| Status | Enabled |
| Severity | Not confirmed |
| Data Source | Sysmon |
| Index | `sysmon` |
| Event ID | 1 — Process Creation |
| Monitored Host | `DESKTOP-1BDISO6` |

## Objective

Identify potentially suspicious PowerShell execution patterns involving encoded commands and Base64 decoding functionality.

Attackers may use encoded PowerShell commands to obscure command-line activity and make malicious instructions less readable during initial inspection.

This detection searches for selected command-line indicators associated with these behaviors. It does not automatically decode commands or establish malicious intent.

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

The detection identifies Windows PowerShell and PowerShell 7 process creation events.

It then searches the command line for the following indicators:

### 1. Encoded Command Arguments

Detects selected abbreviations and the full parameter name:

- `-e`
- `-en`
- `-enc`
- `-enco`
- `-EncodedCommand`

PowerShell accepts abbreviated parameter names in its command-line interface. These arguments can be used to execute Base64-encoded commands.

### 2. Base64 Decoding

Detects references to:

- `FromBase64String`

This .NET method converts Base64-encoded data into bytes and may appear in scripts that decode concealed content.

The presence of this method alone does not establish malicious activity.

## SPL Query

```spl
index=sysmon host="DESKTOP-1BDISO6" EventCode=1
| where match(Image, "(?i)\\\\(powershell|pwsh)\\.exe$")
| where match(CommandLine, "(?i)(^|\\s)-(e|en|enc|enco|encodedcommand)(\\s|$)|frombase64string")
| table _time host User ParentImage Image CommandLine
| sort - _time
```

### Query Explanation

| SPL Component | Purpose |
|---|---|
| `index=sysmon` | Searches Sysmon events. |
| `host="DESKTOP-1BDISO6"` | Restricts the search to the monitored endpoint. |
| `EventCode=1` | Selects process creation events. |
| `match(Image, ...)` | Identifies Windows PowerShell and PowerShell 7. |
| `match(CommandLine, ...)` | Searches for encoded-command arguments and Base64 decoding references. |
| `table` | Displays the relevant investigation fields. |
| `sort - _time` | Displays the newest events first. |

## Alert Configuration

| Setting | Value |
|---|---|
| Alert Name | `SOC - Suspicious PowerShell` |
| Status | Enabled |
| Search Schedule | Check the configured schedule in Splunk |
| Search Time Range | Check the alert's configured time range |
| Trigger Condition | Check the configured alert trigger condition |
| Alert Actions | Check the configured alert actions |

The SPL does not define the execution frequency, search time range, trigger condition, or notification actions. These settings must be documented from the actual Splunk alert configuration.

## Investigation Guidance

When this detection triggers, the analyst should:

1. Identify the user who launched PowerShell.
2. Review the parent process to understand what initiated the execution.
3. Examine the complete command line and identify the matching indicator.
4. If an encoded command is present, extract and decode its Base64 content in a safe analysis environment.
5. Review decoded content for suspicious commands, URLs, file operations, or additional execution stages.
6. Correlate the process with Sysmon Event ID 3 (Network Connection) to identify related network activity.
7. Correlate with Sysmon Event ID 11 (FileCreate) to identify files created during execution.
8. Review related PowerShell Operational logs when available.
9. Determine whether the activity is authorized and whether escalation is necessary.

## False Positives and Limitations

### Potential False Positives

- Legitimate administrative scripts using encoded commands.
- Authorized automation and deployment tools.
- Scripts using `FromBase64String` for legitimate data processing.
- Security tools and software installers.

### Limitations

- Encoded commands are not necessarily malicious.
- The detection does not decode or inspect Base64 content automatically.
- It only identifies selected command-line patterns.
- Other obfuscation and encoding techniques are not covered.
- PowerShell execution through alternative binaries or indirect execution chains may not match the query.
- The detection depends on Sysmon Event ID 1 collection and the availability of the `Image` and `CommandLine` fields.

## Validation

The alert is enabled in Splunk.

The user reports that the homelab alert rules have been tested. However, specific validation evidence for this detection has not been documented here.

Suggested test cases:

- Launch PowerShell using `-EncodedCommand`.
- Launch PowerShell using an accepted abbreviated encoded-command argument.
- Execute a script containing `FromBase64String`.
- Execute a normal PowerShell command without these indicators to check that it does not match.

For each test, record the expected result, actual result, event timestamp, and relevant evidence.

## MITRE ATT&CK Mapping

- **T1059.001 — PowerShell**

This technique covers the abuse of PowerShell for command execution.

- **T1027 — Obfuscated Files or Information**

Encoded commands may be used to conceal command content. This mapping should be treated as contextual rather than proof of obfuscation or malicious intent.

## Related Incidents

- **INC-001 — Suspicious PowerShell Execution:** Relevant to investigations involving suspicious PowerShell activity.

## Analyst Notes

This detection is more selective than general PowerShell execution monitoring because it focuses on command-line indicators associated with encoded execution and Base64 decoding.

A matching event should be investigated by examining its complete command line, decoding encoded content when appropriate, and correlating it with process, network, and file activity.

The presence of an encoded command or Base64 decoding method alone is not sufficient to classify an event as malicious.
