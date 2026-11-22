# SOC Analyst Home Lab — Endpoint Monitoring, Threat Detection & Incident Investigation

## 1. Project Overview

This project documents the development and operation of a personal SOC Analyst home lab designed to simulate essential Tier 1 Security Operations Center (SOC) activities.

The environment provides centralized Windows endpoint monitoring, security event collection, SPL-based detection, alert management, dashboard visualization, incident investigation, and L1-to-L2 escalation exercises.

The main objective is to develop practical skills in SIEM operations, endpoint telemetry analysis, security monitoring, alert triage, and incident investigation using a controlled multi-system environment.

## 2. Lab Architecture

The laboratory consists of two physical computers and a virtualized security testing environment.

| System | Role | Operating System | Main Technologies |
|---|---|---|---|
| Dell Inspiron 15 3535 | Centralized SIEM server | Windows 11 | Splunk Enterprise |
| Fujitsu Laptop | Monitored endpoint | Windows 10 Pro | Sysmon, Splunk Universal Forwarder |
| Kali Linux VM | Security testing system | Kali Linux | Network and controlled security testing tools |

### 2.1 Network Configuration

The systems communicate through a local network.

| System | IP Address | Role |
|---|---|---|
| Dell Inspiron | `192.168.1.104` | Splunk Enterprise |
| Fujitsu | `192.168.1.102` | Monitored Windows endpoint |
| Kali Linux | `192.168.1.103` | Controlled testing system |

**Relevant communication ports:**

- `9997/TCP` — Splunk receiving port for forwarded events.
- `8000/TCP` — Splunk Web interface.

### 2.2 Event Collection Architecture

The Fujitsu endpoint generates security telemetry through Sysmon.

Splunk Universal Forwarder collects the configured Sysmon Operational events and forwards them to Splunk Enterprise running on the Dell workstation.

Splunk Enterprise indexes the received events and provides the platform for security searches, detection rules, scheduled alerts, dashboard monitoring, and incident investigations.

Kali Linux is used to generate controlled testing activity against the laboratory endpoint.

For detailed infrastructure information, see the [Architecture Documentation](./architecture/README.md).

## 3. Technologies & Tools

| Category | Technology | Purpose |
|---|---|---|
| SIEM | Splunk Enterprise 10.6.1.1 | Centralized event collection, searching, alerting, and investigation |
| Endpoint Monitoring | Sysmon | Windows endpoint telemetry generation |
| Log Collection | Splunk Universal Forwarder | Event collection and forwarding |
| Sysmon Integration | Splunk Add-on for Microsoft Sysmon | Sysmon event interpretation and field extraction |
| Security Testing | Kali Linux | Controlled testing and activity simulation |
| Endpoint Analysis | Windows Event Logs and PowerShell | Process, authentication, and endpoint activity investigation |
| Detection Engineering | Splunk Processing Language (SPL) | Detection searches and alert logic |
| Documentation | GitHub and Markdown | Investigation reports, technical documentation, and incident tracking |

## 4. Infrastructure & Log Collection

### 4.1 Splunk Enterprise

Splunk Enterprise is installed on the Dell workstation and acts as the centralized SIEM platform.

It provides:

- Centralized event indexing.
- SPL-based searches.
- Scheduled alert execution.
- Alert management and suppression.
- Dashboard visualization.
- Security investigation capabilities.

### 4.2 Windows Endpoint Monitoring

Sysmon is deployed on the Fujitsu endpoint to generate detailed endpoint telemetry.

The monitored event types include:

- Event ID 1 — Process Creation.
- Event ID 3 — Network Connection.
- Event ID 11 — File Create.
- Additional Sysmon event types available for investigation.

### 4.3 Log Forwarding

Splunk Universal Forwarder collects events from the following Windows Event Log channel:

`Microsoft-Windows-Sysmon/Operational`

The collected events are forwarded to Splunk Enterprise through TCP port `9997`.

The primary Sysmon telemetry is stored in:

`index=sysmon`

Windows authentication events are also used in the laboratory's authentication and remote access investigations.

### 4.4 Data Collection Verification

Data reception and field extraction have been verified using SPL searches.

The verification process includes:

- Confirming events arrive from the Fujitsu endpoint.
- Checking event counts and available Sysmon Event IDs.
- Inspecting process creation fields.
- Verifying executable paths, command lines, users, and parent processes.

Detailed configuration and verification procedures are documented in [Splunk Data Collection](./architecture/splunk-data-collection.md).

## 5. Detection Engineering

The laboratory includes **12 documented detection use cases** developed using Splunk Processing Language (SPL).

The detections are organized into four categories.

| Category | Detection IDs | Focus |
|---|---|---|
| Authentication | DET-001 | Multiple failed logon attempts |
| Process Execution | DET-002 to DET-007 | Executable creation, Office spawning shells, PowerShell, and LOLBins |
| Network | DET-008 to DET-011 | Incoming HTTP connections, PowerShell network activity, suspicious outbound connections, and PowerShell downloads |
| Remote Access | DET-012 | Suspicious remote access activity |

The detection searches are designed to identify potentially suspicious behavior and provide supporting telemetry for further investigation.

Detection alerts are configured in Splunk Enterprise. Alert suppression is used to reduce duplicate notifications.

The presence of a detection match does not automatically establish malicious activity. Alerts require contextual analysis and investigation.

See the [Detection Documentation](./detection/README.md) for the complete detection inventory and SPL logic.

## 6. Security Monitoring Dashboard

A four-tab monitoring dashboard was developed using Splunk Dashboard Studio.

**Dashboard:** SOC — Endpoint Monitoring & Incident Triage

**Dashboard ID:** `soc_endpoint_monitoring`

The dashboard provides visibility into the monitored endpoint and its security activity.

| Dashboard Tab | Monitoring Focus |
|---|---|
| Summary | General endpoint monitoring and security activity overview |
| Authentication | Successful and failed logon activity |
| Process & Execution | Process creation, command-line activity, and suspicious execution indicators |
| Network & Remote Access | Network connections, destination information, and remote access activity |

The dashboard supports initial alert review and investigation by providing relevant event information in a centralized interface.

See the [Dashboard Documentation](./dashboards/README.md) for tab descriptions and screenshots.

## 7. Incident Investigation

The laboratory includes five documented investigations covering different security scenarios.

| Incident ID | Investigation |
|---|---|
| INC-001 | Suspicious PowerShell Execution |
| INC-002 | Executable File Creation |
| INC-003 | SMB Brute-Force with Successful Authentication |
| INC-004 | Suspicious WinRM Remote Access |
| INC-005 | Suspicious PowerShell Download |

The investigations use collected endpoint telemetry, SPL searches, and supporting evidence to examine suspicious activity.

The investigation methodology includes:

1. Alert identification and initial assessment.
2. Identification of affected hosts and accounts.
3. Collection of relevant security events.
4. Process and command-line analysis.
5. Correlation of related endpoint and network events.
6. Evaluation of findings and activity classification.
7. Documentation of evidence and conclusions.
8. Escalation when additional analysis is required.

All cases are documented as controlled laboratory exercises and are not presented as actual compromises of production environments.

See the [Investigation Reports](./investigations/) for individual case documentation.

## 8. Incident Management & Escalation

Incident tracking and escalation exercises are documented using GitHub Issues.

The incident management process provides a way to track investigation progress, preserve evidence, communicate findings, and document L1-to-L2 escalation decisions.

The incident register maintains references to:

- Incident identification.
- Severity and status.
- Associated detection alerts.
- Investigation reports.
- GitHub Issues.

Escalation exercises focus on communicating relevant technical findings and supporting evidence to a higher-level analyst.

See the [Incident Management Documentation](./incident-management/) and [Playbooks](./playbooks/README.md).

## 9. Project Documentation

The laboratory documentation is organized into the following directories:

| Directory | Description |
|---|---|
| `architecture/` | Infrastructure architecture, network configuration, and data collection documentation |
| `configuration/` | Splunk Universal Forwarder and Sysmon configuration |
| `dashboards/` | Dashboard documentation, individual tabs, and screenshots |
| `detection/` | Twelve documented SPL detection use cases |
| `investigations/` | Five security investigation reports and supporting evidence |
| `incident-management/` | Incident register and incident tracking documentation |
| `playbooks/` | Investigation playbooks and operational guidance |

## 10. Skills Practiced

This project provides hands-on practice in:

- SIEM monitoring and event analysis.
- Splunk Enterprise administration and searching.
- SPL query development.
- Windows endpoint monitoring with Sysmon.
- Log collection and forwarding troubleshooting.
- Process execution and PowerShell investigation.
- Authentication event analysis.
- Network connection monitoring.
- Detection engineering fundamentals.
- Alert management and triage.
- Evidence collection and event correlation.
- Incident investigation and classification.
- L1-to-L2 escalation documentation.
- Technical reporting and security documentation.

## 11. Project Status

**Status: Core Lab Infrastructure Operational**

The main laboratory infrastructure is configured and operational.

The project includes:

- Centralized Sysmon event collection.
- Splunk Enterprise indexing and searching.
- Configured detection searches and scheduled alerts.
- Alert suppression to reduce duplicate notifications.
- A four-tab Splunk Dashboard Studio dashboard.
- Twelve documented detection use cases.
- Five documented security investigations.
- Incident tracking and L1-to-L2 escalation exercises.
- Architecture, configuration, and operational documentation.

The current focus is on reviewing documentation quality, maintaining technical consistency, and improving the presentation of the portfolio.

## 12. Security Disclaimer

This is an educational SOC home lab and does not represent a production Security Operations Center.

All security testing activities are conducted within controlled laboratory systems and authorized training environments.

The purpose of this project is to demonstrate practical defensive cybersecurity skills through endpoint monitoring, detection development, alert investigation, and incident documentation.
