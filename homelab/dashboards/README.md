# SOC — Endpoint Monitoring & Incident Triage

## Dashboard Overview

**Platform:** Splunk Enterprise  
**Dashboard Type:** Dashboard Studio  
**Dashboard ID:** `soc_endpoint_monitoring`  
**Monitored Host:** `DESKTOP-1BDISO6`  
**SIEM Server:** `JVA`  
**Monitoring Period:** Last 24 hours (default)

## 1. Purpose

The SOC — Endpoint Monitoring & Incident Triage dashboard provides a centralized view of security-related activity collected from a monitored Windows endpoint.

It is designed to support Tier 1 SOC analyst activities by organizing endpoint telemetry into functional monitoring sections that facilitate security event review, suspicious behavior identification, alert triage, and incident investigation.

Rather than presenting raw events without context, the dashboard groups relevant information to help analysts understand what is happening on the endpoint, identify unusual activity, and determine when additional investigation is necessary.

## 2. Dashboard Architecture

The dashboard is divided into five functional sections:

| Section | Main Function |
|---|---|
| Overview | General endpoint monitoring and security activity summary. |
| Authentication | Monitoring of successful and failed logon activity. |
| Process & Execution | Investigation of process creation and PowerShell activity. |
| Network & Remote Access | Monitoring of network-related and remote access activity. |
| Investigations | Review and triage of triggered security alerts. |

Each section addresses a different aspect of endpoint security monitoring while contributing to the overall investigation workflow.

## 3. Data Sources

The dashboard uses telemetry collected from the monitored Windows endpoint.

| Data Source | Index | Purpose |
|---|---|---|
| Sysmon | `sysmon` | Process creation and detailed endpoint activity. |
| Windows Event Logs | `wineventlog` | Windows authentication and operating system security events. |

**Monitored endpoint:** `DESKTOP-1BDISO6`

**Collection pipeline:**

`Windows Endpoint → Sysmon / Windows Event Logs → Splunk Universal Forwarder → Splunk Enterprise → Dashboard`

## 4. Dashboard Sections

### 4.1 Overview

Provides a high-level summary of endpoint activity.

Its purpose is to give the analyst an initial understanding of the available telemetry and identify areas that may require closer inspection.

Detailed documentation: [Overview](tabs/01-overview.md)

### 4.2 Authentication

Focuses on Windows authentication activity.

It helps analysts review:

- Successful logons.
- Failed logon attempts.
- Failed authentication patterns by username.
- Source IP addresses associated with failed logons.
- Detailed authentication event records.

The objective is to identify potentially suspicious authentication behavior, including repeated failures and unusual access patterns.

Detailed documentation: [Authentication](tabs/02-authentication.md)

### 4.3 Process & Execution

Focuses on process creation and command execution activity collected through Sysmon.

It helps analysts review:

- PowerShell execution frequency.
- Processes launched by PowerShell.
- Unique child processes and tools.
- Process execution activity.
- Complete PowerShell command lines.
- Suspicious PowerShell command-line indicators.

The objective is to identify unusual execution patterns and provide sufficient context for further investigation.

Detailed documentation: [Process & Execution](tabs/03-process-execution.md)

### 4.4 Network & Remote Access

Focuses on network-related activity and remote access behavior.

It is intended to help analysts review suspicious connections, remote management activity, and other network events relevant to endpoint security.

Detailed documentation: [Network & Remote Access](tabs/04-network-remote-access.md)

### 4.5 Investigations

Provides a dedicated area for reviewing triggered security alerts and supporting the incident triage process.

Its purpose is to help analysts:

- Review triggered detections.
- Identify alert severity.
- Access the associated search results.
- Examine supporting evidence.
- Determine whether escalation is necessary.

Detailed documentation: [Investigations](tabs/05-investigations.md)

## 5. Analyst Workflow

The dashboard is designed around the following SOC L1 workflow:

1. **Monitor:** Review the endpoint's general activity.
2. **Identify:** Recognize unusual authentication, process execution, or network behavior.
3. **Investigate:** Examine the underlying events and correlate relevant evidence.
4. **Triage:** Assess the context and potential security impact.
5. **Escalate:** Document and escalate incidents requiring additional investigation.

The analyst must validate suspicious activity using available telemetry before reaching a conclusion.

## 6. Visualization and Detection Principles

The dashboard combines different visualization types according to the information being analyzed:

- **Single Values:** Summarize important event counts.
- **Bar Charts:** Highlight distributions and activity patterns.
- **Tables:** Provide detailed event records for investigation.
- **Triggered Alert Tables:** Present security detections and provide access to their associated search results.

The visualizations are intended to support investigation and prioritization. A suspicious indicator does not automatically represent malicious activity or a confirmed compromise.

## 7. Screenshots

The `screenshots/` directory contains visual references of the dashboard sections.

These screenshots document the implemented monitoring interface and provide a quick overview of its organization.

## 8. Documentation Structure

```text
soc-endpoint-monitoring/
│
├── README.md
│
├── tabs/
│   ├── 01-overview.md
│   ├── 02-authentication.md
│   ├── 03-process-execution.md
│   ├── 04-network-remote-access.md
│   └── 05-investigations.md
│
└── screenshots/
    ├── dashboard-overview.png
    ├── authentication.png
    ├── process-execution.png
    ├── network-remote-access.png
    └── investigations.png
```

## 9. Scope and Limitations

- Monitoring currently focuses on one Windows endpoint.
- Available monitoring capabilities depend on the telemetry collected by Sysmon and Windows Event Logs.
- Detection searches identify patterns requiring analyst review; they do not independently confirm malicious intent.
- Investigation conclusions must be supported by available event evidence.
- The dashboard is a practical SOC training implementation, not a production enterprise SOC platform.

## Project Information

| Attribute | Value |
|---|---|
| Project | SOC Endpoint Monitoring & Incident Triage |
| Platform | Splunk Enterprise |
| Interface | Dashboard Studio |
| Focus | SOC Analyst L1 / Blue Team |
| Endpoint | Windows |
| Status | Ongoing Development |
