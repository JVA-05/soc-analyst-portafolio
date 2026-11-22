# Suspicious Network Activity Playbook

## Objective

Investigate unusual network connections involving the monitored Windows endpoint and identify potentially unauthorized communication.

**Related detections:** DET-008, DET-009, DET-010  
**Log source:** Sysmon Event ID 3  
**Monitored host:** `DESKTOP-1BDISO6`

## Investigation Procedure

### 1. Review Network Events

Run:

```spl
index=sysmon host="DESKTOP-1BDISO6" EventCode=3 earliest=-24h
| table _time User Image SourceIp SourcePort DestinationIp DestinationPort Protocol Initiated
| sort -_time
```

### 2. Inspect the Connection

Determine:

- Which process initiated or received the connection.
- Source and destination IP addresses.
- Source and destination ports.
- Whether the connection was initiated locally.
- Whether the destination is expected for that process.

### 3. Correlate Related Events

Check for:

- PowerShell or other suspicious process execution (Event ID 1).
- File creation near the connection timestamp (Event ID 11).
- Repeated connections to the same destination.
- Unusual connections involving unexpected applications.

For incoming HTTP activity, remember that Sysmon Event ID 3 records network connection metadata. It does not reveal the HTTP method, URL, or request body.

## Classification

**Likely benign**
- The connection belongs to an expected application or service.
- The destination and communication pattern are consistent with normal activity.

**Suspicious**
- An unexpected process communicates with an unknown destination.
- The connection is associated with suspicious command-line activity.
- Repeated or unusual connections occur without a clear business purpose.

## Escalation Criteria

Escalate when network activity cannot be explained and is supported by suspicious process execution, unexpected file creation, or other indicators of compromise.

## Evidence to Record

- Timestamp and hostname.
- Process and username.
- Source and destination IP addresses.
- Ports, protocol, and connection direction.
- Related events and investigation conclusion.
