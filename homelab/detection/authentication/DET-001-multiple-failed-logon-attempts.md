# DET-001 — Multiple Failed Logon Attempts

## Overview

**Detection ID:** DET-001  
**Detection Name:** Multiple Failed Logon Attempts  
**Category:** Authentication  
**Severity:** High  
**Platform:** Splunk Enterprise  
**Status:** Enabled  
**Data Source:** Windows Security Event Logs  
**Event ID:** 4625  
**Monitored Host:** `DESKTOP-1BDISO6`

## Objective

This detection identifies repeated failed Windows logon attempts originating from the same source IP address against the monitored endpoint.

It is designed to identify authentication patterns that may indicate brute-force attempts, password guessing, or other suspicious login activity.

The detection groups failed logon events by source IP address and destination host within a five-minute time window.

An alert is generated when the number of failed logon attempts reaches or exceeds five events within the same group.

## Data Sources

- **Index:** `wineventlog`
- **Host:** `DESKTOP-1BDISO6`
- **Event ID:** `4625` — An account failed to log on.
- **Event Source:** Windows Security Event Log

### Relevant Fields

| Field | Description |
|---|---|
| `IpAddress` | Source IP address associated with the failed logon. |
| `TargetUserName` | Account targeted by the authentication attempt. |
| `WorkstationName` | Source workstation reported in the event. |
| `host` | Windows endpoint where the event was collected. |
| `EventCode` | Windows Security event identifier. |

## Detection Logic

The search identifies Windows Security Event ID 4625 records generated during the last five minutes.

Events are grouped by:

- Source IP address (`IpAddress`)
- Destination host (`host`)

For each group, Splunk calculates:

- Total failed authentication attempts.
- Number of distinct targeted accounts.
- List of targeted usernames.
- List of reported source workstations.

The detection filters the results and retains only groups with five or more failed logon attempts.

This approach helps identify repeated authentication failures from a common source while providing additional context about the targeted accounts.

## SPL Query

```spl
index=wineventlog host="DESKTOP-1BDISO6" EventCode=4625 earliest=-5m latest=now
| stats count AS failed_attempts
        dc(TargetUserName) AS targeted_accounts
        values(TargetUserName) AS targeted_users
        values(WorkstationName) AS source_workstations
        by IpAddress host
| where failed_attempts >= 5
| rename IpAddress AS source_ip
| sort - failed_attempts
```

## Alert Configuration

- **Search Type:** Scheduled Search
- **Execution Frequency:** Every 5 minutes
- **Search Window:** Previous 5 minutes
- **Trigger Condition:** Number of failed logon attempts greater than or equal to 5.
- **Trigger Action:** Splunk alert trigger.

## Investigation Guidance

When this alert triggers, the SOC L1 analyst should:

1. Identify the source IP address responsible for the failed authentication attempts.
2. Review the number of failed attempts and targeted accounts.
3. Examine the source workstation information when available.
4. Investigate the corresponding Windows Security events.
5. Search for successful logon events (Event ID 4624) from the same source IP and against the same accounts.
6. Determine whether the activity is consistent with legitimate user errors or potentially malicious authentication attempts.
7. Document the evidence and escalate the incident when suspicious activity is confirmed or requires further investigation.

## False Positives and Limitations

Potential false positives include:

- Users repeatedly entering incorrect passwords.
- Applications or services attempting authentication with outdated credentials.
- Misconfigured systems generating repeated authentication failures.
- Legitimate administrative activity involving incorrect credentials.

Limitations:

- The detection relies on the source IP address reported by Windows Security events.
- Events without a usable source IP may not provide meaningful source attribution.
- The five-event threshold may not identify low-and-slow password attacks.
- The detection does not independently confirm successful account compromise.
- The search groups events by source IP and destination host, not by individual username.

## Validation

**Validation Status:** Tested

The detection was tested through controlled SMB authentication attempts in the lab environment.

During the INC-003 investigation, the monitored Fujitsu endpoint recorded 52 failed authentication attempts originating from `192.168.1.103` against the `SOC_Lab` account.

The detection generated an alert after the configured threshold was reached.

A successful authentication event (Event ID 4624) was subsequently identified from the same source IP and account.

**Validation Result:** Successful

## MITRE ATT&CK Mapping

- **T1110 — Brute Force**

This technique is relevant when repeated failed authentication attempts are consistent with password guessing or brute-force activity.

## Related Incidents

- **INC-003 — SMB Brute Force with Successful Authentication**

The incident investigation contains the supporting evidence, event correlation, analyst findings, classification, and L2 escalation details.

## Analyst Notes

This detection provides an initial authentication monitoring mechanism for the Windows endpoint.

A high number of failed logon attempts should be treated as suspicious activity requiring investigation rather than automatic confirmation of a brute-force attack.

The analyst should correlate failed logons with successful authentication events and additional endpoint activity before determining the incident classification.
