# DET-010 — Suspicious Outbound Network Connection

## Detection Overview

| Field | Value |
|---|---|
| Detection ID | DET-010 |
| Name | Suspicious Outbound Network Connection |
| Category | Network |
| Platform | Splunk Enterprise |
| Status | Enabled |
| Severity | Not confirmed |
| Data Source | Sysmon |
| Index | `sysmon` |
| Event ID | 3 — Network Connection |
| Monitored Host | `DESKTOP-1BDISO6` |

## Objective

Identify outbound network connections initiated by processes on the monitored Windows endpoint to destination TCP or UDP port `4444`.

Port 4444 is commonly associated with security testing tools and remote access or command-and-control scenarios. However, its use is not inherently malicious.

This detection provides visibility into outbound connections involving this port so that analysts can investigate the responsible process, user, destination, and connection frequency.

## Data Sources

- **Log source:** Sysmon
- **Index:** `sysmon`
- **Host:** `DESKTOP-1BDISO6`
- **Event ID:** 3 — Network Connection

### Relevant Fields

- `_time`
- `host`
- `SourceIp`
- `DestinationIp`
- `DestinationPort`
- `Protocol`
- `Image`
- `User`
- `Initiated`

## Detection Logic

The detection searches for Sysmon Network Connection events matching the following conditions:

1. The event originates from the monitored endpoint.
2. The connection was initiated by the local process (`Initiated=true`).
3. The destination port is `4444`.

The results are grouped by host, source IP, destination IP, destination port, protocol, executable image, and user.

This grouping preserves the relationship between the process and the destination instead of combining unrelated connections into a single host-level result.

The query also counts matching connections for each combination of these fields.

## SPL Query

```spl
index=sysmon host="DESKTOP-1BDISO6" EventCode=3 Initiated=true DestinationPort=4444
| stats count AS connections
    by host SourceIp DestinationIp DestinationPort Protocol Image User
| sort - connections
```

### Query Explanation

| SPL Component | Purpose |
|---|---|
| `index=sysmon` | Searches Sysmon network telemetry. |
| `host="DESKTOP-1BDISO6"` | Restricts the search to the monitored endpoint. |
| `EventCode=3` | Selects network connection events. |
| `Initiated=true` | Selects connections initiated by the local process. |
| `DestinationPort=4444` | Filters connections targeting destination port 4444. |
| `stats count` | Counts matching connections. |
| `by ...` | Preserves the relationship between the host, destination, process, and user. |
| `sort - connections` | Displays the most frequent connection combinations first. |

## Alert Configuration

| Setting | Value |
|---|---|
| Alert Name | `Suspicious Outbound Network Connection` |
| Status | Enabled |
| Search Schedule | Check the configured schedule in Splunk |
| Search Time Range | Check the alert's configured time range |
| Trigger Condition | Check the configured alert trigger condition |
| Alert Actions | Check the configured alert actions |

The SPL does not define the execution frequency, search time range, trigger condition, or notification actions. These settings must be documented from the actual Splunk alert configuration.

## Investigation Guidance

When this detection triggers, the analyst should:

1. Identify the process responsible for initiating the connection.
2. Identify the associated user.
3. Review the destination IP address and destination port.
4. Determine whether the destination is expected and authorized.
5. Examine the connection frequency and timing.
6. Correlate the event with Sysmon Event ID 1 (Process Creation) to inspect the process command line and parent process.
7. Review related network activity to identify additional destinations or communication patterns.
8. Determine whether the connection is associated with an authorized security test, administrative activity, or potentially unauthorized remote access.
9. Escalate when additional evidence supports suspicious or unauthorized activity.

## False Positives and Limitations

### Potential False Positives

- Authorized penetration-testing exercises.
- Security tools and remote administration utilities.
- Legitimate applications configured to use port 4444.
- Controlled lab simulations.
- Authorized remote access services.

### Limitations

- Port 4444 is not exclusively associated with malicious activity.
- The detection only monitors destination port 4444.
- Connections using other ports are not covered.
- The detection does not inspect network payloads or identify the application protocol.
- It does not establish whether a remote session was successfully created.
- It does not determine whether the destination is malicious.
- The query aggregates matching events instead of displaying every individual connection.
- It depends on Sysmon Event ID 3 collection and the availability of the relevant network and process fields.

## Validation

The alert is enabled in Splunk.

The user reports that the homelab alert rules have been tested. However, specific validation evidence for this detection has not been documented here.

A complete validation record should include:

- Test scenario used to generate an outbound connection to port 4444.
- Source and destination IP addresses.
- Process and user responsible for the connection.
- Expected detection result.
- Actual alert result.
- Event timestamp or screenshot.

## MITRE ATT&CK Mapping

No specific adversary technique is assigned.

An outbound connection to port 4444 alone does not establish command-and-control activity, exploitation, or unauthorized remote access.

Additional evidence, such as the process behavior, protocol, payload, and remote session activity, would be required before assigning a specific ATT&CK technique.

## Related Incidents

- **INC-004 — Suspicious WinRM Remote Access:** Relevant to investigations involving potentially unauthorized remote access from the lab network.

The incident is related to remote access investigation, but it is not evidence that port 4444 was involved.

## Analyst Notes

This detection focuses on outbound connections to a specific destination port that may warrant investigation.

The presence of port 4444 should be treated as an investigation lead rather than confirmation of compromise.

Analysts should correlate the destination, process, user, command line, and surrounding network activity before determining whether escalation is necessary.
