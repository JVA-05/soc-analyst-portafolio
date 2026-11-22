# DET-003 — Executable Created in Downloads

## Detection Overview

| Field | Value |
|---|---|
| Detection ID | DET-003 |
| Name | Executable Created in Downloads |
| Category | Process Execution |
| Platform | Splunk Enterprise |
| Status | Enabled |
| Severity | Not confirmed |
| Data Source | Sysmon |
| Index | `sysmon` |
| Event ID | 11 — FileCreate |
| Monitored Host | `DESKTOP-1BDISO6` |

## Objective

Identify executable files (`.exe`) created directly inside a user's `Downloads` directory on the monitored Windows endpoint.

Executable files created in download directories may require investigation because they can be associated with manually downloaded tools, installers, scripts, or potentially unwanted software.

This detection identifies file creation activity. It does not determine whether the executable is malicious.

## Data Sources

- **Log source:** Sysmon
- **Index:** `sysmon`
- **Host:** `DESKTOP-1BDISO6`
- **Event ID:** 11 — FileCreate
- **Relevant fields:**
  - `_time`
  - `host`
  - `User`
  - `Image`
  - `TargetFilename`

## Detection Logic

The detection searches for Sysmon Event ID 11 events on the monitored endpoint.

It filters file creation events using the `TargetFilename` field and identifies executable files located directly inside a directory named `Downloads`.

The matching is case-insensitive, so filenames ending in `.exe`, `.EXE`, or other capitalization variations are included.

The query returns:

- Event timestamp.
- Hostname.
- User associated with the event.
- Process image responsible for the file creation.
- Full path of the created executable.

## SPL Query

```spl
index=sysmon host="DESKTOP-1BDISO6" EventCode=11
| where match(TargetFilename, "(?i)\\\\Downloads\\\\[^\\\\]+\\.exe$")
| table _time host User Image TargetFilename
| sort - _time
```

### Query Explanation

| SPL Component | Purpose |
|---|---|
| `index=sysmon` | Searches Sysmon events. |
| `host="DESKTOP-1BDISO6"` | Restricts the search to the monitored endpoint. |
| `EventCode=11` | Selects file creation events. |
| `match()` | Filters executable files created directly inside a Downloads directory, regardless of extension capitalization. |
| `table` | Displays the relevant investigation fields. |
| `sort - _time` | Displays the newest events first. |

**Important:** The regular expression matches executables directly inside `Downloads`. It does not match executables located in nested subdirectories.

## Alert Configuration

| Setting | Value |
|---|---|
| Alert Name | `SOC - Executable Created in Downloads` |
| Status | Enabled |
| Search Schedule | Check the configured schedule in Splunk |
| Search Time Range | Check the alert's configured time range |
| Trigger Condition | Check the configured alert trigger condition |
| Alert Actions | Check the configured alert actions |

The SPL itself does not define the execution frequency, search time range, trigger condition, or notification actions. These settings are controlled by the Splunk alert configuration.

## Investigation Guidance

When an executable is detected in a Downloads directory, the analyst should:

1. Identify the user associated with the file creation event.
2. Review the complete file path and executable filename.
3. Examine the `Image` field to identify the process responsible for creating the file.
4. Correlate the event with Sysmon Event ID 1 (Process Creation) to determine whether the executable was subsequently launched.
5. Review related network activity and download events when available.
6. If necessary, calculate the file hash and submit it to an approved malware analysis service.
7. Determine whether the activity was authorized and expected.

## False Positives and Limitations

### Potential False Positives

- Legitimate software installers downloaded by users.
- Portable administrative utilities.
- Authorized troubleshooting or diagnostic tools.
- Software updates and manually downloaded applications.

### Limitations

- File creation does not establish malicious intent.
- Event ID 11 does not independently prove that the executable was downloaded from the internet.
- The detection does not inspect file contents or determine file reputation.
- Executables created in directories other than `Downloads` are not included.
- Executables inside nested subdirectories are not included by the current regular expression.
- The detection depends on Sysmon Event ID 11 collection and the availability of the `TargetFilename` field.

## Validation

The alert is enabled in Splunk.

The user reports that the alert rules in the homelab have been tested. A specific test case, event timestamp, and resulting alert evidence for this detection have not been documented here.

For a complete validation record, include:

- Test scenario.
- Created executable and destination path.
- Expected detection result.
- Actual alert result.
- Relevant event timestamp or screenshot.

## MITRE ATT&CK Mapping

No direct technique mapping is assigned.

The creation of an executable in a Downloads directory is not sufficient by itself to establish a specific adversary technique. Additional evidence, such as network transfer or execution activity, is required for a more precise mapping.

## Related Incidents

No incident currently linked to this detection.

## Analyst Notes

This detection is intended to provide visibility into executable file creation in user download directories.

A matching event should be treated as an investigation lead rather than confirmation of malware infection. Analysts should correlate file creation with process execution, network activity, file reputation, and user activity before determining the appropriate response.
