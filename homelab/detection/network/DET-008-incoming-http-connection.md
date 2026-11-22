# DET-008 — Incoming HTTP Connection

## Detection Overview

| Field | Value |
|---|---|
| Detection ID | DET-008 |
| Name | Incoming HTTP Connection |
| Category | Network |
| SIEM | Splunk Enterprise |
| Log Source | Sysmon |
| Index | `sysmon` |
| Event ID | 3 — Network Connection |
| Status | Validated |
| Severity | Informational |
| Environment | SOC Home Lab |

## 1. Lab Environment

The detection was tested using the following systems:

- **Source machine:** Kali Linux (`192.168.1.103`)
- **Target machine:** Fujitsu Windows (`192.168.1.102`)
- **Monitoring:** Sysmon and Splunk Universal Forwarder
- **SIEM:** Splunk Enterprise running on Dell Windows

A temporary Python HTTP server was configured on the Fujitsu endpoint, listening on TCP port `8080`.

The Kali machine was used to generate controlled HTTP requests to the server.

## 2. Detection Objective

Identify incoming TCP connections to the monitored Windows endpoint on port `8080`.

In this lab scenario, the destination port was used by a temporary Python HTTP server.

The objective was to verify that Sysmon could record incoming network connections, forward the telemetry to Splunk, and trigger a scheduled alert when matching activity occurred.

**Scope:** This detection identifies connections matching the configured source IP, destination IP, destination port, and connection direction. It is not a general-purpose detector for every incoming HTTP connection.

## 3. Detection Logic

The following SPL query was configured as a scheduled alert:

```spl
index=sysmon host="DESKTOP-1BDISO6" EventCode=3
SourceIp="192.168.1.103"
DestinationIp="192.168.1.102"
DestinationPort=8080
Initiated=false
```

The alert was configured to trigger when the search returned more than zero results.

### Query Explanation

| Condition | Purpose |
|---|---|
| `index=sysmon` | Searches Sysmon network telemetry. |
| `host="DESKTOP-1BDISO6"` | Restricts the search to the monitored endpoint. |
| `EventCode=3` | Selects network connection events. |
| `SourceIp="192.168.1.103"` | Matches the Kali source machine. |
| `DestinationIp="192.168.1.102"` | Matches the Fujitsu destination machine. |
| `DestinationPort=8080` | Matches the Python HTTP server port. |
| `Initiated=false` | Selects connections that were not initiated by the monitored process. |

In Sysmon Event ID 3, `Initiated=false` is consistent with an incoming connection accepted by the monitored endpoint.

## 4. Simulation and Testing

A controlled HTTP request was generated from Kali Linux:

```bash
curl http://192.168.1.102:8080/
```

The server returned the expected response:

```text
SOC-LAB - HTTP connection test
```

The incoming connection was recorded by Sysmon and forwarded to Splunk.

This test confirmed both the network connectivity to the Python HTTP server and the availability of corresponding Sysmon telemetry.

## 5. Observed Evidence

The investigation identified the following network connection:

| Field | Observed Value |
|---|---|
| Source IP | `192.168.1.103` |
| Source Port | `41098` |
| Destination IP | `192.168.1.102` |
| Destination Port | `8080` |
| Protocol | TCP |
| Process | `python.exe` |
| Process ID | `9312` |
| Initiated | `false` |

A second matching connection was also observed, associated with a different Python process ID (`11096`).

The observed process information helped identify the application associated with the listening service.

## 6. Alert Validation

The scheduled alert was tested under two conditions:

**Test 1 — No new HTTP requests**

- No additional HTTP requests were generated.
- No repeated alert activation was observed.

**Test 2 — Incoming HTTP request**

- A new HTTP request was generated from Kali Linux.
- Sysmon recorded the incoming network connection.
- Splunk matched the event and activated the alert.

**Validation Result:** Successful.

The alert correctly identified the controlled incoming connection during the test.

## 7. Investigation and Classification

**Classification:** Benign Lab Activity

The observed connections were intentionally generated as part of a controlled laboratory exercise.

The detection correctly identified incoming network activity associated with the Python HTTP server.

However, an incoming TCP connection to port `8080` is not inherently malicious.

In a real SOC environment, the analyst should investigate:

1. Whether the source IP is expected and authorized.
2. Whether the destination service should be accepting incoming connections.
3. Which process owns or handles the connection.
4. Whether the connection is associated with additional suspicious process or network activity.
5. Whether the activity is consistent with an authorized service or application.

**Important limitation:** Sysmon Event ID 3 records network connection telemetry. It does not provide HTTP methods, requested URLs, headers, or response content. The successful HTTP response was verified separately through the Python server test.

## 8. MITRE ATT&CK Mapping

No specific adversary technique is assigned to this detection.

An incoming network connection alone does not establish malicious activity or a particular ATT&CK technique.

Additional evidence would be required to identify an adversary behavior.

## 9. Lessons Learned

- Collecting endpoint network telemetry using Sysmon.
- Identifying incoming connections through Event ID 3.
- Interpreting the `Initiated` field to distinguish connection direction.
- Correlating source and destination IP addresses, ports, and processes.
- Creating scheduled alerts in Splunk.
- Validating alert behavior through controlled network simulations.
- Distinguishing detected network activity from confirmed malicious behavior.

## 10. Evidence

### 1. SPL Detection Query

![SPL Detection Query](screenshots/DET-008-spl-query.png)

### 2. Triggered Alert

![Triggered Alert](screenshots/DET-008-triggered-alert.png)
