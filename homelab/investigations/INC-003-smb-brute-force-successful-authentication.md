# INC-003 — SMB Brute-Force with Successful Authentication

## Incident Overview

| Field | Details |
|---|---|
| Incident ID | INC-003 |
| Title | SMB Brute-Force with Successful Authentication |
| Date | 2026-11-17 |
| Detection Alert | Multiple Failed Logon Attempts |
| Severity | High (simulated environment) |
| Status | Escalated |
| Analyst Role | SOC Analyst L1 |
| Affected Host | DESKTOP-1BDISO6 |
| Target Account | SOC_Lab |
| Source IP | 192.168.1.103 |
| Source Hostname | KALI |

## 1. Incident Summary

A series of repeated failed SMB authentication attempts against the local account `SOC_Lab` was detected by Splunk Enterprise.

The detection alert identified 52 failed authentication attempts originating from `192.168.1.103`, identified as `KALI`, within approximately 49 seconds.

Windows Security logs recorded multiple Event ID 4625 entries, followed by a successful authentication event (Event ID 4624) for the same account and source address.

The successful authentication occurred immediately after the failed attempts, indicating that valid credentials were eventually accepted.

The incident was classified as a True Positive and escalated for further investigation.

This is a controlled SOC homelab simulation. The source IP is a private address belonging to the lab network, but represents a host external to the simulated organization's monitored environment.

## 2. Detection Details

**Detection Rule:** Multiple Failed Logon Attempts

**Detection Logic:**
- Five or more failed logon attempts.
- Same source IP address.
- Within a five-minute detection window.

**Alert Output:**

| Field | Value |
|---|---|
| Source IP | 192.168.1.103 |
| Host | DESKTOP-1BDISO6 |
| Failed Attempts | 52 |
| Targeted Accounts | 1 |
| Targeted User | SOC_Lab |
| Source Workstation | KALI |

## 3. Investigation Timeline

| Timestamp | Event ID | Description |
|---|---:|---|
| 16:26:56.722 | 4625 | First observed failed authentication |
| 16:27:45.775 | 4625 | Last observed failed authentication |
| 16:27:45.780 | 4624 | Successful authentication |
| 16:27:45.928 | 4634 | Logon session termination event observed |

The 52 failed authentication attempts occurred over approximately 49.053 seconds.

The successful authentication was recorded approximately 5 milliseconds after the last observed failed attempt.

The 4634 event was recorded approximately 148 milliseconds after the successful authentication. Its Logon ID has not yet been correlated with the 4624 session.

## 4. Technical Evidence

### 4.1 Failed Authentication — Event ID 4625

Repeated Windows Security events contained the following values:

| Field | Value |
|---|---|
| Event ID | 4625 |
| Target User | SOC_Lab |
| Source IP | 192.168.1.103 |
| Workstation | KALI |
| Logon Type | 3 |
| Authentication Package | NTLM |
| Status | 0xc000006d |
| SubStatus | 0xc000006a |

The SubStatus `0xc000006a` indicates an incorrect password.

Logon Type 3 indicates a network logon, consistent with the SMB authentication scenario.

### 4.2 Successful Authentication — Event ID 4624

A successful authentication was recorded with these values:

| Field | Value |
|---|---|
| Event ID | 4624 |
| Target User | SOC_Lab |
| Source IP | 192.168.1.103 |
| Workstation | KALI |
| Logon Type | 3 |
| Authentication Package | NTLM |
| Target Logon ID | 0x55476be |

This event confirms that Windows accepted the authentication credentials for the targeted account.

### 4.3 Session Termination — Event ID 4634

A subsequent Event ID 4634 was observed:

| Field | Value |
|---|---|
| Event ID | 4634 |
| Target User | SOC_Lab |
| Timestamp | 16:27:45.928 |

The available search output did not include the Logon ID, so correlation with the successful 4624 session remains unconfirmed.

### 4.4 Shared Resource Access Investigation

Additional searches were performed for:

- Event ID 5140 — Network share access.
- Event ID 5145 — Detailed network share access check.

No matching events were returned during the investigated time window.

Therefore, access to files or specific shared resources has not been confirmed. The absence of results does not establish that no access occurred, because the relevant audit policies and collection configuration have not yet been verified.

## 5. Analysis

The combination of repeated failed authentication attempts, a single targeted account, a consistent source address, and a subsequent successful authentication strongly supports a brute-force or password-guessing scenario.

The successful Event ID 4624 is particularly significant because it demonstrates that authentication was accepted after the repeated failures.

However, successful authentication alone does not establish that the source performed additional actions on the host.

No evidence of file access, command execution, persistence, or lateral movement has been established during this investigation.

## 6. Verdict

**Classification: TRUE POSITIVE**

**Incident Type:** SMB Brute Force / Password Guessing

**Severity:** High (within the simulated enterprise scenario)

**Escalation:** Required

The evidence confirms repeated failed authentication attempts followed by successful authentication against the same account from the same source.

The incident requires further investigation by SOC L2 to determine the scope and impact of the successful authentication.

## 7. Recommended L2 Actions

1. Validate the successful authentication and correlate the 4624 and 4634 events using their Logon IDs.
2. Investigate whether the authenticated session accessed the `SOC-Lab` share or other network resources.
3. Verify the Windows audit policies for network share access.
4. Review subsequent process creation, file activity, and other relevant security events.
5. Determine whether the source host was authorized to access the monitored environment.
6. Assess the need to disable or reset the affected account and revoke active sessions.
7. Determine whether additional systems or accounts were targeted.

## 8. Investigation Limitations

- The source address is a private IP used as an external host within the simulated enterprise scenario.
- The successful authentication is confirmed, but subsequent access to files or execution of commands is not established.
- The 4634 event has not yet been correlated to the 4624 session through its Logon ID.
- No matching 5140 or 5145 events were returned. Audit configuration has not been verified.
- The investigation was conducted in a controlled homelab environment.

## 9. Final Assessment

The SOC Analyst L1 investigation identified a true-positive authentication attack and confirmed successful authentication following repeated failures.

The incident was escalated to SOC L2 for further investigation of session activity, access scope, and potential impact.

**Final Status: ESCALATED — Pending L2 Investigation**
