# Sysmon Configuration and Splunk Integration

## 1. Overview

This document describes the Sysmon configuration deployed on the Fujitsu Windows endpoint and its integration with Splunk Enterprise.

The objective was to collect Windows endpoint telemetry, forward Sysmon events to a centralized Splunk instance, and ensure that XML-formatted events were correctly interpreted and searchable.

**Environment:**

| Component | Details |
|---|---|
| Endpoint | Fujitsu laptop |
| Hostname | `DESKTOP-1BDISO6` |
| Operating System | Windows |
| Sysmon Version | 15.22 |
| Sysmon Service | `Sysmon64` |
| Configuration File | `D:\Programas\Sysmon\sysmonconfig-export.xml` |
| Splunk Enterprise | Dell laptop |
| Splunk Index | `sysmon` |

## 2. Sysmon Installation and Configuration

Sysmon was installed on the Fujitsu endpoint as a Windows system service.

The service status was verified using PowerShell:

```powershell
Get-Service Sysmon*
```

The service was confirmed to be running.

The active configuration was verified using:

```powershell
C:\Windows\Sysmon64.exe -c
```

The configuration summary reported:

- Hashing algorithms: MD5, SHA256, IMPHASH.
- Network connection monitoring: Enabled.
- DNS lookup: Enabled.
- Image loading monitoring: Disabled.
- CRL checking: Enabled.

**Configuration file SHA256:**

`055FEBC600E6D7448CDF3812307275912927A62B1F94D0D933B64B294BC87162`

## 3. Event Filtering Rules

The active XML configuration contains filtering rules designed to collect selected security-relevant activity while excluding certain expected or benign events.

The following rule sections were identified:

| Rule Section | Configuration | Purpose |
|---|---|---|
| ProcessCreate | Exclude rules | Excludes selected process creation events |
| NetworkConnect | Include and exclude rules | Monitors selected network connections and filters specified traffic |
| FileCreate | Include and exclude rules | Monitors selected file creation activity |

### Network Connection Monitoring

The NetworkConnect inclusion rules contain selected executable paths, security-relevant utilities, and destination ports.

The inspected rules include destination port 8080, among other ports.

This allowed the laboratory to capture a controlled incoming HTTP connection from Kali Linux to the Fujitsu endpoint.

### File Creation Monitoring

The FileCreate inclusion rules cover selected locations and file extensions, including:

- Downloads directory.
- Startup-related locations.
- Executable files (`.exe`).
- Other selected file types.

These rules support monitoring potentially suspicious file creation activity.

## 4. Splunk Universal Forwarder Integration

Sysmon events were collected by the Splunk Universal Forwarder installed on the Fujitsu endpoint.

The events were forwarded to Splunk Enterprise running on the Dell laptop.

The Universal Forwarder input configuration was located at:

`C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`

The following input was configured:

```ini
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = sysmon
renderXml = true
source = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

**Configuration details:**

- Windows Event Log collection was enabled for the Sysmon Operational channel.
- Events were assigned to the `sysmon` index.
- XML rendering was enabled through `renderXml = true`.
- The source was explicitly defined.

## 5. Troubleshooting: Sysmon XML Event Parsing in Splunk

During the integration process, Sysmon events initially presented inconsistencies in how their data was displayed and interpreted in Splunk.

The main objective was to ensure that Splunk could correctly process the XML event structure and expose useful fields for investigation.

### 5.1 XML Event Collection

The Universal Forwarder input was configured with:

```ini
renderXml = true
```

This enabled XML-formatted Windows Event Log data collection.

The original event structure was then inspected using Splunk searches against the `_raw` field.

### 5.2 Source and Sourcetype Configuration

During troubleshooting, differences between the `source` and `sourcetype` fields were investigated to ensure that Sysmon events were correctly identified and interpreted by Splunk.

The final event metadata observed in Splunk was:

| Field | Observed Value |
|---|---|
| Index | `sysmon` |
| Host | `DESKTOP-1BDISO6` |
| Source | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` |
| Sourcetype | `XmlWinEventLog` |

The distinction between these fields is important:

- **Source:** Identifies the Windows Event Log channel from which the events originate.
- **Sourcetype:** Identifies the event format used by Splunk for data interpretation and field extraction.
- **Index:** Determines where the events are stored.
- **Host:** Identifies the endpoint associated with the events.

The Universal Forwarder input explicitly defined the source:

```ini
source = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

The observed sourcetype was `XmlWinEventLog`.

These values were verified directly in Splunk using events from the `sysmon` index.

### 5.3 Splunk Add-on for Microsoft Sysmon

The Splunk Add-on for Microsoft Sysmon (`Splunk_TA_microsoft_sysmon`, version 5.0.1 package) was installed to provide Sysmon-specific field extractions.

After installation, additional Sysmon fields became available in Splunk's field sidebar, improving event inspection and investigation.

The integration was validated by inspecting the original XML events and confirming the availability of structured fields such as `EventID`, `Image`, `ProcessId`, `User`, and other event-specific attributes.### 5.3 Sysmon Add-on Installation

The Splunk Add-on for Microsoft Sysmon was installed:

`Splunk_TA_microsoft_sysmon` (version 5.0.1 package).

The add-on provided Sysmon-specific field extractions and improved the availability of structured fields for investigation.

After installation, Sysmon fields became available in Splunk's field sidebar, allowing more practical searches and analysis.

### 5.4 Validation

The integration was validated by searching the `sysmon` index and inspecting the available event fields.

Example search:

```spl
index=sysmon host="DESKTOP-1BDISO6"
| stats count by EventCode
| sort EventCode
```

The following Sysmon Event IDs were observed:

| Event ID | Event Type | Events Observed |
|---:|---|---:|
| 1 | Process Create | 1644 |
| 2 | File Creation Time Changed | 2 |
| 3 | Network Connection | 22 |
| 5 | Process Terminated | 10 |
| 6 | Driver Loaded | 3 |
| 11 | File Create | 61 |
| 12 | Registry Object Create/Delete | 4 |
| 13 | Registry Value Set | 201 |
| 22 | DNS Query | 257 |

*Counts represent the results observed during the validation search and are not permanent totals.*

## 6. Event Data Validation

Individual events were inspected to confirm that the XML structure and event information were available in Splunk.

For example, Event ID 3 was used to validate network connection monitoring during a controlled HTTP test.

Event ID 22 was also inspected to verify DNS query collection.

One limitation was identified in some DNS events: the `Image` field appeared as `<unknown process>` and `ProcessGuid` contained an all-zero value.

This information was already present in the original XML event, rather than being introduced by Splunk field extraction.

Therefore, process attribution was not always possible using the DNS event alone.

## 7. Verification Commands

The following commands were used during configuration and troubleshooting.

**Check Sysmon service:**

```powershell
Get-Service Sysmon*
```

**Inspect active Sysmon configuration:**

```powershell
C:\Windows\Sysmon64.exe -c
```

**Check Sysmon configuration hash:**

```powershell
Get-FileHash "D:\Programas\Sysmon\sysmonconfig-export.xml" -Algorithm SHA256
```

**Search Sysmon events in Splunk:**

```spl
index=sysmon host="DESKTOP-1BDISO6"
| stats count by EventCode
```

## 8. Conclusion

Sysmon was successfully deployed on the Fujitsu endpoint and integrated with Splunk Enterprise through the Universal Forwarder.

The integration process included troubleshooting XML event collection, investigating source and sourcetype inconsistencies, and installing the Splunk Add-on for Microsoft Sysmon to improve field extraction.

The resulting environment provides endpoint telemetry for process creation, network connections, file creation, registry activity, DNS queries, and other Sysmon events.

This configuration supports hands-on SOC L1 exercises involving event monitoring, alert validation, investigation, and evidence collection.
