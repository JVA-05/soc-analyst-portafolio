# Suspicious Process Execution Playbook

## Objective

Investigate unusual process execution on the monitored Windows endpoint and determine whether the activity is legitimate or potentially malicious.

**Related detections:** DET-004, DET-005, DET-006, DET-007  
**Log source:** Sysmon Event ID 1  
**Monitored host:** `DESKTOP-1BDISO6`

## Investigation Procedure

### 1. Review the Alert

Identify the process, timestamp, username, and affected endpoint.

### 2. Inspect Process Details

Run the following Splunk search:

```spl
index=sysmon host="DESKTOP-1BDISO6" EventCode=1 earliest=-24h
| table _time User Image ParentImage CommandLine ProcessId
| sort -_time
```

Review:

- Executable path and process name.
- Parent process and parent-child relationship.
- Command-line arguments.
- User account running the process.
- Whether the execution matches expected user activity.

### 3. Look for Suspicious Behavior

Pay particular attention to:

- Office applications launching command interpreters.
- PowerShell or command prompt launched by unexpected parent processes.
- LOLBins executing unusual commands.
- Encoded or obfuscated command lines.
- Processes running from temporary or user-writable directories.

### 4. Correlate Events

Search for related file creation, network connections, or subsequent process executions involving the same host, user, or process.

## Classification

**Likely benign**
- The process is associated with expected administrative or user activity.
- The parent process and command line are consistent with the task being performed.

**Suspicious**
- The process has an unusual parent-child relationship.
- The command line contains unexpected or obfuscated instructions.
- The process is followed by unexplained file or network activity.

## Escalation Criteria

Escalate when process execution is unexplained, involves suspicious command-line behavior, or is correlated with additional indicators of compromise.

## Evidence to Record

- Timestamp, hostname, and username.
- Process and parent process.
- Full command line.
- Related file or network events.
- Investigation conclusion and recommended action.
