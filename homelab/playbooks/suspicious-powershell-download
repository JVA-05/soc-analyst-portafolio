# Suspicious PowerShell Download Playbook

## Objective

Investigate PowerShell commands that may download files or retrieve content from remote systems.

**Related detection:** DET-011  
**Log source:** Sysmon Event ID 1  
**Monitored host:** `DESKTOP-1BDISO6`

## Investigation Procedure

### 1. Review the Detection

Run:

```spl
index=sysmon host="DESKTOP-1BDISO6" EventCode=1 earliest=-24h
| where match(Image, "(?i)\\\\powershell\.exe$|\\\\pwsh\.exe$")
| where match(CommandLine, "(?i)Invoke-WebRequest|DownloadFile|DownloadString|Start-BitsTransfer|Invoke-RestMethod")
| table _time User Image ParentImage CommandLine ProcessId
| sort -_time
```

### 2. Inspect the Command

Determine:

- Which download-related command was used.
- Whether a remote URL or IP address appears.
- Which user executed the command.
- Whether the parent process is expected.
- Whether the command appears encoded or obfuscated.

### 3. Search for Follow-up Activity

Correlate the event with:

- Sysmon Event ID 3 for network connections.
- Sysmon Event ID 11 for file creation.
- Sysmon Event ID 1 for subsequent execution of downloaded files.

A download-related command does not automatically prove that a download succeeded.

## Classification

**Likely benign**
- The command is part of an authorized administrative or testing activity.
- The destination and downloaded content are expected.

**Suspicious**
- The command retrieves content from an unexplained destination.
- The execution is unexpected or obfuscated.
- Download activity is followed by suspicious file creation or execution.

## Escalation Criteria

Escalate when the download cannot be justified or when additional evidence suggests unauthorized payload delivery or execution.

## Evidence to Record

- Full PowerShell command line.
- User, parent process, and timestamp.
- Remote destination, if available.
- Related network and file events.
- Whether download success was independently confirmed.
