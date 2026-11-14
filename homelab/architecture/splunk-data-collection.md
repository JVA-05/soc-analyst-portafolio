# Splunk Data Collection

## 1. Overview

This document describes how Windows Sysmon events are collected from a Fujitsu endpoint using Splunk Universal Forwarder and delivered to a centralized Splunk Enterprise instance for monitoring and security investigations.

## 2. Lab Architecture

| Component | Details |
|---|---|
| Endpoint | Fujitsu Laptop |
| Hostname | DESKTOP-1BDISO6 |
| Log Source | Microsoft Sysmon |
| Collection Agent | Splunk Universal Forwarder |
| Centralized SIEM | Splunk Enterprise on Dell |
| Splunk Index | sysmon |
| Receiving Port | TCP 9997 |

## 3. Data Collection Configuration

The Universal Forwarder collects events from the following Windows Event Log channel:

`Microsoft-Windows-Sysmon/Operational`

The input configuration is located at:

`C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`

Verified configuration:

```ini
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = sysmon
renderXml = true
source = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

### Configuration details

- `disabled = 0`: enables the input.
- `index = sysmon`: directs collected events to the `sysmon` index.
- `renderXml = true`: enables XML rendering of Windows Event Log events.
- `source`: identifies the Sysmon event source.

## 4. Data Reception Verification

The following search was executed in Splunk Enterprise:

```spl
index=sysmon host="DESKTOP-1BDISO6"
| stats count by source sourcetype host
```

Observed result:

| Field | Value |
|---|---|
| Host | DESKTOP-1BDISO6 |
| Source | XmlWinEventLog:Microsoft-Windows-Sysmon/Operational |
| Sourcetype | XmlWinEventLog |
| Index | sysmon |
| Events returned | 2,588 |

This confirms that Sysmon events from the Fujitsu endpoint are reaching the centralized Splunk instance.

## 5. Sysmon Event Types Collected

The following search was used to identify the received Sysmon Event IDs:

```spl
index=sysmon host="DESKTOP-1BDISO6"
| stats count by EventCode
| sort 0 + EventCode
```

Observed results:

| Event ID | Event Type | Count |
|---:|---|---:|
| 1 | Process Create | 2,023 |
| 2 | File Creation Time Changed | 2 |
| 3 | Network Connection | 24 |
| 5 | Process Terminated | 9 |
| 6 | Driver Loaded | 2 |
| 11 | File Create | 61 |
| 12 | Registry Object Create/Delete | 4 |
| 13 | Registry Value Set | 199 |
| 22 | DNS Query | 273 |

These counts represent the results of the search at the time it was executed. They are not permanent totals.

## 6. Field Extraction Verification

To verify that useful process information is available for investigation, the following search was executed:

```spl
index=sysmon host="DESKTOP-1BDISO6" EventCode=1
| head 1
| table _time EventCode Image CommandLine ParentImage User ProcessId
```

The returned event exposed the following fields:

- `_time`: event timestamp.
- `EventCode`: Sysmon event identifier.
- `Image`: executable path.
- `CommandLine`: process execution arguments.
- `ParentImage`: parent process executable.
- `User`: account associated with the process.
- `ProcessId`: process identifier.

The test confirmed that Splunk can extract and display process creation information from Sysmon events.

Sensitive values contained in command-line arguments should be redacted before sharing investigation evidence publicly.

## 7. Conclusion

The data collection pipeline is operational.

Splunk Universal Forwarder collects events from the Sysmon Operational channel on the Fujitsu endpoint and forwards them to Splunk Enterprise on the Dell laptop.

The received events are stored in the `sysmon` index under the host `DESKTOP-1BDISO6`.

Verification searches confirmed that multiple Sysmon Event IDs are available and that process creation events expose useful fields for SOC investigations, including executable paths, command-line arguments, parent processes, users, and process identifiers.
