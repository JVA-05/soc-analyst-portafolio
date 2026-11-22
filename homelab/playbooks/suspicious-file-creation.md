# Suspicious File Creation Playbook

## Objective

Investigate newly created files that may indicate malware delivery, unauthorized downloads, or suspicious user activity.

**Related detections:** DET-002, DET-003  
**Log source:** Sysmon Event ID 11  
**Monitored host:** `DESKTOP-1BDISO6`

## Investigation Procedure

### 1. Review File Creation Events

Start with the following search:

```spl
index=sysmon host="DESKTOP-1BDISO6" EventCode=11 earliest=-24h
| table _time User Image TargetFilename
| sort -_time
```

For executable files created in Downloads:

```spl
index=sysmon host="DESKTOP-1BDISO6" EventCode=11 earliest=-24h
| where match(TargetFilename, "(?i)\\\\Downloads\\\\[^\\\\]+\.exe$")
| table _time User Image TargetFilename
| sort -_time
```

### 2. Inspect the File

Review:

- Full file path and filename.
- File extension.
- Process responsible for creating the file.
- User account and creation timestamp.
- Whether the file location is expected.

### 3. Correlate Activity

Search for:

- Process execution involving the created file (Sysmon Event ID 1).
- Network connections around the creation time (Sysmon Event ID 3).
- Related PowerShell or browser activity.

A file creation event does not prove that the file was executed.

## Classification

**Likely benign**
- The file is associated with an expected installation, download, or user action.
- Its creation process and location are consistent with normal activity.

**Suspicious**
- An unexpected executable appears in a user-writable directory.
- The creating process is unusual.
- The file is followed by unexplained execution or network activity.

## Escalation Criteria

Escalate when an unexpected executable is created and additional evidence suggests execution, unauthorized delivery, or malicious behavior.

## Evidence to Record

- Filename and full path.
- Creation timestamp and username.
- Creating process.
- Related process and network events.
- Investigation conclusion.
