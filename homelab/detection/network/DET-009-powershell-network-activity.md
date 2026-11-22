# DET-009 — PowerShell Network Activity

## Detection Overview

| Field | Value |
|---|---|
| Detection ID | DET-009 |
| Name | PowerShell Network Activity |
| Category | Network |
| Platform | Splunk Enterprise |
| Status | Enabled |
| Severity | Not confirmed |
| Data Source | Sysmon |
| Index | `sysmon` |
| Event ID | 3 — Network Connection |
| Monitored Host | `DESKTOP-1BDISO6` |

## Objective

Monitor network connections associated with PowerShell processes on the monitored Windows endpoint.

PowerShell can establish network connections for legitimate administrative tasks, software management, remote operations, and automation. However, attackers may also abuse it to communicate with remote infrastructure, retrieve payloads, or transfer data.

This detection provides visibility into PowerShell network activity and supports further investigation. It does not automatically classify every connection as malicious.

## Data Sources

- **Log source:** Sysmon
- **Index:** `sysmon`
- **Host:** `DESKTOP-1BDISO6`
- **Event ID:** 3 — Network Connection

### Relevant Fields

- `_time`
- `host`
- `User`
- `Image`
- `SourceIp`
- `SourcePort`
- `DestinationIp`
- `DestinationPort`
- `Protocol`
- `Initiated`

## Detection Logic

The detection searches for Sysmon Network Connection events associated with Windows PowerShell and PowerShell 7 processes.

It identifies the executable using the `Image` field and returns network connection details for investigation.

The query provides visibility into:

- The user associated with the process.
- The PowerShell executable responsible for the connection.
- The source and destination IP addresses.
- The source and destination ports.
- The network protocol.
- Whether the connection was initiated by the process.

The detection is intended for activity monitoring and network investigation rather than automatic threat classification.

## SPL Query

```spl id="m5n2ds"
index=sysmon host="DESKTOP-1BDISO6" EventCode=3
| where match(Image, "(?i)\\\\(powershell|pwsh)\\.exe$")
| table _time host User Image SourceIp SourcePort
        DestinationIp DestinationPort Protocol Initiated
| sort - _time
```

### Query Explanation

| SPL Component | Purpose |
|---|---|
| `index=sysmon` | Searches Sysmon network telemetry. |
| `host="DESKTOP-1BDISO6"` | Restricts the search to the monitored endpoint. |
| `EventCode=3` | Selects network connection events. |
| `match(Image, ...)` | Identifies Windows PowerShell and PowerShell 7 processes. |
| `table` | Displays process and network connection details. |
| `sort - _time` | Displays the newest events first. |

## Alert Configuration

| Setting | Value |
|---|---|
| Alert Name | `SOC - PowerShell Network Activity` |
| Status | Enabled |
| Search Schedule | Check the configured schedule in Splunk |
| Search Time Range | Check the alert's configured time range |
| Trigger Condition | Check the configured alert trigger condition |
| Alert Actions | Check the configured alert actions |

The SPL does not define the execution frequency, search time range, trigger condition, or notification actions. These settings must be documented from the actual Splunk alert configuration.

## Investigation Guidance

When reviewing PowerShell network activity, the analyst should:

1. Identify the user and PowerShell executable associated with the connection.
2. Examine the destination IP address and port.
3. Determine whether the destination is expected and authorized.
4. Review the `Initiated` field to understand the connection direction.
5. Correlate the event with Sysmon Event ID 1 (Process Creation) to inspect the PowerShell command line and parent process.
6. Correlate with Sysmon Event ID 11 (FileCreate) to identify files created around the same time.
7. Review related PowerShell Operational logs when available.
8. Determine whether the network activity is consistent with legitimate administrative operations or requires escalation.

## False Positives and Limitations

### Potential False Positives

- Authorized PowerShell scripts connecting to internal services.
- Administrative remote management.
- Software installation and update operations.
- Automated monitoring and maintenance scripts.
- Legitimate API requests and web service communication.

### Limitations

- PowerShell network connections are not inherently malicious.
- The detection does not inspect network payloads or HTTP requests.
- It does not determine whether a file was downloaded or whether data was exfiltrated.
- It does not classify destination IP addresses or domains by reputation.
- It depends on Sysmon Event ID 3 collection and the availability of the relevant process and network fields.
- Network activity performed through child processes or other executables may not be attributed to PowerShell by this query.

## Validation

The alert is enabled in Splunk.

The user reports that the homelab alert rules have been tested. However, specific validation evidence for this detection has not been documented here.

A complete validation record should include:

- PowerShell command or script used to generate network activity.
- Destination IP address and port.
- Expected detection result.
- Actual event and alert result.
- Event timestamp or screenshot.

## MITRE ATT&CK Mapping

No specific adversary technique is assigned to this detection.

PowerShell network activity alone does not establish a particular adversary behavior. Additional evidence is required before assigning techniques such as:

- **T1105 — Ingress Tool Transfer**, when evidence supports downloading or transferring tools.
- **T1041 — Exfiltration Over C2 Channel**, when evidence supports data exfiltration through a command-and-control channel.

These techniques should not be inferred from a network connection alone.

## Related Incidents

- **INC-001 — Suspicious PowerShell Execution:** Relevant to investigations involving PowerShell process activity.
- **INC-005 — Suspicious PowerShell Download:** Relevant to investigations involving PowerShell network retrieval activity.

## Analyst Notes

This detection provides baseline visibility into network connections associated with PowerShell processes.

Its main value is correlating process execution with network behavior. Analysts should examine the command line, parent process, destination, and related file activity before determining whether the connection is suspicious.

A matching event should be treated as an investigation lead rather than confirmation of compromise.
