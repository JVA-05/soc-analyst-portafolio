# Suspicious Remote Access Playbook

## Objective

Investigate potentially unauthorized remote access to the monitored Windows endpoint.

**Related detection:** DET-012  
**Log source:** Windows Security Event ID 4624  
**Monitored host:** `DESKTOP-1BDISO6`

## Investigation Procedure

### 1. Review Successful Logons

Search for successful authentication events:

```spl
index=* host="DESKTOP-1BDISO6" EventCode=4624 earliest=-24h
| table _time host TargetUserName Logon_Type IpAddress Authentication_Package
| sort -_time
```

Review the available fields and identify:

- Account used.
- Logon type.
- Source IP address.
- Authentication package.
- Timestamp.

### 2. Identify Remote Access Indicators

Pay particular attention to:

- Logon Type 3: network logon.
- Logon Type 10: RemoteInteractive, commonly associated with RDP.
- Unexpected source IP addresses.
- Accounts that do not normally access the endpoint remotely.

### 3. Correlate the Session

Search for processes associated with the authentication:

- `wsmprovhost.exe` may support a WinRM investigation.
- `mstsc.exe` may provide context about RDP activity.
- Unexpected command interpreters or administrative commands may indicate post-authentication activity.

Correlate timestamps, accounts, and source addresses. Do not identify a session as WinRM or RDP based only on Event ID 4624.

## Classification

**Likely benign**
- The account, source address, and remote access activity are authorized.
- The activity matches an expected administrative task.

**Suspicious**
- An unexpected account or source address accesses the endpoint.
- Remote authentication is followed by unexplained command execution.
- The activity cannot be linked to an authorized user or task.

## Escalation Criteria

Escalate when remote access is unauthorized or unexplained, especially when followed by suspicious process execution or other indicators of compromise.

## Evidence to Record

- Timestamp and account.
- Logon type and authentication package.
- Source IP address.
- Related processes and commands.
- Supporting authentication events.
- Investigation conclusion.
