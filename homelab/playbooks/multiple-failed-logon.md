# Multiple Failed Logons Playbook

## Objective

Investigate repeated failed authentication attempts and determine whether they indicate brute-force activity, password guessing, or legitimate user error.

**Related detection:** DET-001  
**Log source:** Windows Security Event ID 4625  
**Monitored host:** `DESKTOP-1BDISO6`

## Investigation Procedure

### 1. Review Failed Logons

Run:

```spl
index=* host="DESKTOP-1BDISO6" EventCode=4625 earliest=-24h
| stats count min(_time) as FirstAttempt max(_time) as LastAttempt
    values(TargetUserName) as TargetUsers
    by host IpAddress
| convert ctime(FirstAttempt) ctime(LastAttempt)
| sort -count
```

### 2. Identify the Pattern

Determine:

- Number of failed attempts.
- Source IP address.
- Target account or accounts.
- Time range and frequency.
- Whether several accounts were targeted.

### 3. Check for Successful Authentication

Search for Event ID 4624 around the same time.

Determine whether a successful login occurred after the failures and whether the account and source address match the suspicious activity.

### 4. Assess the Context

Consider legitimate explanations such as:

- Incorrectly entered passwords.
- Outdated saved credentials.
- Misconfigured services or scheduled tasks.
- Authorized authentication testing.

## Classification

**Likely benign**
- Failures are consistent with user error or a known service configuration.
- No unexplained successful authentication follows the attempts.

**Suspicious**
- Numerous failures occur within a short period.
- Multiple accounts are targeted from the same source.
- A successful authentication follows the failures without a clear explanation.

## Escalation Criteria

Escalate when repeated failures suggest password guessing or brute-force activity, particularly if followed by a successful login or other suspicious behavior.

## Evidence to Record

- Source IP address.
- Target accounts.
- Number and time range of failures.
- Related successful logons.
- Relevant event records.
- Investigation conclusion.
