# DET-006 — Suspicious LOLBins Execution

## Detection Overview

| Field | Value |
|---|---|
| Detection ID | DET-006 |
| Name | Suspicious LOLBins Execution |
| Category | Process Execution |
| Platform | Splunk Enterprise |
| Status | Enabled |
| Severity | Not confirmed |
| Data Source | Sysmon |
| Index | `sysmon` |
| Event ID | 1 — Process Creation |
| Monitored Host | `DESKTOP-1BDISO6` |

## Objective

Identify potentially suspicious usage patterns involving selected Windows Living-off-the-Land Binaries (LOLBins).

LOLBins are legitimate Windows utilities that can be abused by attackers to download files, execute scripts, load libraries, or perform other actions without relying exclusively on custom malware.

This detection focuses on suspicious command-line patterns rather than alerting on every execution of these utilities.

## Data Sources

- **Log source:** Sysmon
- **Index:** `sysmon`
- **Host:** `DESKTOP-1BDISO6`
- **Event ID:** 1 — Process Creation

### Relevant Fields

- `_time`
- `host`
- `User`
- `ParentImage`
- `Image`
- `CommandLine`

## Detection Logic

The detection monitors five Windows utilities and looks for command-line patterns associated with potentially suspicious behavior.

### 1. Certutil

Detects:
- URL cache operations involving HTTP or HTTPS URLs.
- File decoding operations.

These behaviors may be associated with payload retrieval or file decoding.

### 2. Mshta

Detects:
- Remote HTTP or HTTPS content.
- JavaScript execution.
- VBScript execution.

These patterns may indicate execution of remote or embedded script content.

### 3. Rundll32

Detects:
- JavaScript-based execution.
- DLL paths located in user-writable directories such as `AppData`, `Temp`, or `Downloads`.

These patterns may indicate abuse of a legitimate Windows library-loading utility.

### 4. Regsvr32

Detects:
- References to `scrobj.dll`.
- Registration operations using remote HTTP or HTTPS URLs.

These patterns may indicate abuse of the Windows scriptlet execution mechanism.

### 5. Bitsadmin

Detects:
- Transfer operations using `/transfer` or `/addfile`.
- Command lines containing HTTP or HTTPS URLs.

These patterns may indicate the use of a legitimate background transfer utility to retrieve files.

## SPL Query

```spl
index=sysmon host="DESKTOP-1BDISO6" EventCode=1
| where (
    match(Image, "(?i)\\\\certutil\\.exe$")
    AND match(CommandLine, "(?i)(-urlcache.*https?://|-decode(hex)?\\s+)")
)
OR (
    match(Image, "(?i)\\\\mshta\\.exe$")
    AND match(CommandLine, "(?i)(https?://|javascript:|vbscript:)")
)
OR (
    match(Image, "(?i)\\\\rundll32\\.exe$")
    AND match(CommandLine, "(?i)(javascript:|\\\\(appdata|temp|downloads)\\\\.*\\.dll)")
)
OR (
    match(Image, "(?i)\\\\regsvr32\\.exe$")
    AND match(CommandLine, "(?i)(scrobj\\.dll|/i:\\s*https?://)")
)
OR (
    match(Image, "(?i)\\\\bitsadmin\\.exe$")
    AND match(CommandLine, "(?i)(/transfer|/addfile).*https?://")
)
| table _time host User ParentImage Image CommandLine
| sort - _time
```

### Query Explanation

| SPL Component | Purpose |
|---|---|
| `index=sysmon` | Searches Sysmon events. |
| `host="DESKTOP-1BDISO6"` | Restricts the search to the monitored endpoint. |
| `EventCode=1` | Selects process creation events. |
| `match(Image, ...)` | Identifies the executable being investigated. |
| `match(CommandLine, ...)` | Identifies selected command-line patterns. |
| `AND` | Requires the executable and its corresponding suspicious pattern to match. |
| `OR` | Allows any of the five LOLBin detection conditions to trigger a result. |
| `table` | Displays the relevant investigation fields. |
| `sort - _time` | Displays the newest events first. |

## Alert Configuration

| Setting | Value |
|---|---|
| Alert Name | `SOC - Suspicious LOLBins Execution` |
| Status | Enabled |
| Search Schedule | Check the configured schedule in Splunk |
| Search Time Range | Check the alert's configured time range |
| Trigger Condition | Check the configured alert trigger condition |
| Alert Actions | Check the configured alert actions |

The SPL does not define the execution frequency, search time range, trigger condition, or notification actions. These settings must be documented from the actual Splunk alert configuration.

## Investigation Guidance

When this detection triggers, the analyst should:

1. Identify the LOLBin involved.
2. Review the complete command line and determine which operation was attempted.
3. Identify the user and parent process responsible for launching the utility.
4. Examine referenced URLs, file paths, DLLs, or script content.
5. Correlate the event with Sysmon Event ID 3 (Network Connection) to identify related network activity.
6. Correlate with Sysmon Event ID 11 (FileCreate) to identify files created during the activity.
7. Review subsequent process creation events to identify additional execution activity.
8. Determine whether the behavior is authorized and consistent with legitimate system administration.

## False Positives and Limitations

### Potential False Positives

- Authorized administrative use of Certutil.
- Legitimate script or HTML application execution.
- Software installers and registration utilities.
- Applications loading DLLs from user-writable directories.
- Authorized background file transfers.

### Limitations

- The detection only covers five selected LOLBins.
- It identifies specific command-line patterns, not every possible abuse technique.
- Suspicious activity using alternative arguments may not match the current conditions.
- Legitimate administrative activity may still match the selected patterns.
- The detection does not inspect downloaded files or determine their reputation.
- The detection does not establish whether a command completed successfully.
- It depends on Sysmon Event ID 1 collection and the availability of the `Image` and `CommandLine` fields.

## Validation

The alert is enabled in Splunk.

The user reports that the homelab alert rules have been tested. However, specific validation evidence for this revised detection logic has not been documented here.

Because the detection logic is more selective than the original version, its updated SPL should be tested against representative scenarios before its results are considered validated.

Suggested test cases:

- Certutil URL cache operation involving a remote URL.
- Mshta execution involving a remote URL or script protocol.
- Rundll32 loading a DLL from a user-writable directory.
- Regsvr32 referencing `scrobj.dll`.
- Bitsadmin transfer involving an HTTP or HTTPS URL.

For each test, record the expected result, actual result, event timestamp, and relevant evidence.

## MITRE ATT&CK Mapping

Potential mappings, depending on the observed behavior:

- **T1218.005 — Mshta**
- **T1218.010 — Regsvr32**
- **T1218.011 — Rundll32**
- **T1105 — Ingress Tool Transfer**, when evidence supports file transfer activity.

These mappings describe potential behaviors covered by the detection. A matching command line does not independently prove that an adversary technique was successfully performed.

## Related Incidents

No incident currently linked to this detection.

## Analyst Notes

This detection uses behavior-based filtering to reduce the noise generated by monitoring every execution of common Windows utilities.

A matching event should be investigated using its command line, parent process, user context, related network connections, and file activity.

The presence of a LOLBin alone is not sufficient to classify an event as malicious.

The detection should be periodically tuned based on observed legitimate activity and investigation results.
