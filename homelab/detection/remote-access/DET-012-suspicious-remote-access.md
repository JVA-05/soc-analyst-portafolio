# DET-012 — Suspicious Remote Access

## Detection Overview

| Field | Value |
|---|---|
| Detection ID | DET-012 |
| Detection Name | Suspicious Remote Access |
| Category | Remote Access |
| Status | Not confirmed |
| Severity | Not confirmed |
| Platform | Splunk Enterprise |
| Data Source | Windows Security Event Log |
| Index | `wineventlog` |
| Event ID | 4624 |
| Monitored Host | `DESKTOP-1BDISO6` |
| Target Account | `SOC_Lab` |

## Objective

Identify successful network and remote interactive logons involving the monitored `SOC_Lab` account.

This detection helps an analyst identify remote authentication activity that may require further investigation, particularly when the source IP, authentication package, or subsequent process execution is unexpected.

A successful logon does not automatically indicate malicious activity.

## Detection Logic

The detection monitors Windows Security Event ID 4624, which records successful logons.

It focuses on two logon types:

- **Logon Type 3 — Network:** Network-based authentication, including activity associated with services such as SMB and WinRM.
- **Logon Type 10 — RemoteInteractive:** Interactive remote sessions, commonly associated with Remote Desktop.

The query also collects the source IP address, workstation name, authentication package, and target logon ID to support investigation and event correlation.

## SPL Query

```spl
index=wineventlog host="DESKTOP-1BDISO6" EventCode=4624 TargetUserName="SOC_Lab" earliest=-24h latest=now
| where LogonType=3 OR LogonType=10
| eval LogonTypeDescription=case(
    LogonType=3, "Network",
    LogonType=10, "Remote Interactive",
    true(), "Other"
)
| table _time host TargetUserName IpAddress WorkstationName
        LogonType LogonTypeDescription AuthenticationPackageName TargetLogonId
| sort - _time
```

## Data Sources and Fields

| Field | Description |
|---|---|
| `_time` | Timestamp of the successful logon |
| `host` | Windows endpoint that generated the event |
| `TargetUserName` | Account used for authentication |
| `IpAddress` | Source IP address associated with the logon |
| `WorkstationName` | Source workstation name, when available |
| `LogonType` | Windows logon type |
| `LogonTypeDescription` | Human-readable logon type |
| `AuthenticationPackageName` | Authentication package used |
| `TargetLogonId` | Identifier used to correlate related Windows events |

## Alert Configuration

| Setting | Value |
|---|---|
| Alert Name | Suspicious Remote Access |
| Alert Status | Not confirmed |
| Search Window | 24 hours in the documented SPL |
| Execution Schedule | Not documented |
| Trigger Condition | Check the configured alert in Splunk |
| Trigger Actions | Not documented |

The search window and alert execution schedule must be configured consistently. Verify the actual alert settings in Splunk before treating these documented values as the production configuration.

## Investigation Procedure

When this detection returns an event:

1. Review the source IP address and determine whether it belongs to an expected system.
2. Identify the logon type and authentication package.
3. Check whether the account was expected to authenticate remotely at that time.
4. Correlate the `TargetLogonId` with other Windows Security events when available.
5. Review Sysmon Event ID 1 for processes created around the same time.
6. For suspected WinRM activity, look for `wsmprovhost.exe` and its child processes.
7. Determine whether the activity was authorized, suspicious, or confirmed malicious.

## False Positives and Limitations

- Authorized remote administration can generate these events.
- Logon Type 3 is not exclusive to WinRM; SMB and other network services can also generate it.
- Logon Type 10 identifies remote interactive logons but does not independently establish malicious intent.
- Event ID 4624 records successful authentication, not proof of subsequent command execution or resource access.
- Some events may contain missing or unavailable source workstation information.
- The detection monitors only the `SOC_Lab` account. Remote logons involving other accounts are outside its current scope.
- Correlation with process creation and additional Windows events is necessary to identify the remote access method with greater confidence.

## Validation Evidence

**Related Investigation:** INC-004 — Suspicious WinRM Remote Access

During the INC-004 laboratory investigation, a connection was initiated from Kali Linux (`192.168.1.103`) to the monitored Fujitsu endpoint (`192.168.1.102`) using Evil-WinRM.

The investigation identified:

- A successful Windows logon (Event ID 4624).
- Target account: `SOC_Lab`.
- Logon Type: 3 (Network).
- Authentication package: NTLM.
- Source IP: `192.168.1.103`.
- Subsequent process creation involving `wsmprovhost.exe` and `whoami.exe`.

The process evidence provided additional context supporting the identification of WinRM activity.

**Validation result:** The remote access behavior was confirmed during the INC-004 investigation. This does not, by itself, establish that the revised SPL query or its alert configuration has been independently validated.

## Related Incidents

- [INC-004 — Suspicious WinRM Remote Access](../../incidents/INC-004-suspicious-winrm-remote-access.md)

## MITRE ATT&CK Mapping

| Technique | Name | Context |
|---|---|---|
| T1021.006 | Windows Remote Management | Applicable to the INC-004 investigation, where WinRM activity was corroborated through process evidence. |

The technique mapping describes the investigated WinRM behavior. Event ID 4624 alone is insufficient to establish this technique.

## Analyst Notes

This detection provides visibility into successful remote authentication involving the monitored laboratory account.

It should be treated as an investigation starting point rather than a standalone indicator of compromise. Source IP analysis, logon type review, and process correlation are important before escalating an alert.
