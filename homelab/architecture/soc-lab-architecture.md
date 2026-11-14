# SOC Home Lab Architecture

## 1. Project Overview

This project is a small-scale Security Operations Center (SOC) home lab designed to simulate basic security monitoring, detection, investigation, and incident response activities.

The environment uses multiple systems connected through a local network to collect Windows endpoint telemetry, centralize security events, and investigate potentially suspicious activity using Splunk Enterprise.

The main objective is to develop practical SOC Analyst Level 1 skills through hands-on monitoring and investigation exercises.

## 2. Lab Components

The lab consists of three main systems:

### 2.1 SIEM Server — Dell Inspiron

- **Operating System:** Windows 11
- **SIEM Platform:** Splunk Enterprise 10.6.1.1
- **Hostname:** JVA
- **Current IP Address:** 192.168.1.104
- **Primary Role:** Centralized log collection, indexing, searching, and alert monitoring.

The Dell system acts as the central SIEM server. It receives security events forwarded by the monitored Windows endpoint and stores them in Splunk indexes for analysis.

### 2.2 Monitored Endpoint — Fujitsu

- **Operating System:** Windows
- **Hostname:** DESKTOP-1BDISO6
- **Current IP Address:** 192.168.1.102
- **Monitoring Agent:** Sysmon
- **Log Forwarding:** Splunk Universal Forwarder
- **Primary Role:** Endpoint telemetry generation and event forwarding.

Sysmon monitors system activity and generates detailed event logs, including process creation and network connection events.

The Splunk Universal Forwarder collects the configured Sysmon events and forwards them to the central Splunk server.

### 2.3 Testing Machine — Kali Linux

- **Operating System:** Kali Linux
- **Current IP Address:** 192.168.1.103
- **Primary Role:** Controlled generation of network activity for detection and investigation exercises.

Kali Linux is used to generate controlled traffic and simulate activities that can be observed by the monitored endpoint.

## 3. Network Architecture

All three systems communicate through the same local network.

Current lab addressing:

| System | IP Address | Role |
|---|---|---|
| Dell | 192.168.1.104 | Splunk Enterprise |
| Fujitsu | 192.168.1.102 | Sysmon Endpoint |
| Kali Linux | 192.168.1.103 | Testing Machine |

The Splunk Universal Forwarder communicates with the Splunk receiving service on TCP port 9997.

Splunk Web is accessible through TCP port 8000.

## 4. Log Collection and Data Flow

The main telemetry collection process follows these steps:

1. Sysmon monitors activity on the Fujitsu endpoint.
2. Sysmon generates events based on the monitored system activity.
3. The Splunk Universal Forwarder collects the configured Sysmon Operational events.
4. The Universal Forwarder sends the events to the Dell Splunk server over TCP port 9997.
5. Splunk indexes the received events.
6. The analyst searches, correlates, and investigates the collected telemetry.

The current configuration sends Sysmon Operational events to the `sysmon` index.

## 5. Monitoring and Investigation Capabilities

The laboratory currently supports practical exercises involving:

- Process creation monitoring (Sysmon Event ID 1).
- Network connection monitoring (Sysmon Event ID 3).
- File creation monitoring (Sysmon Event ID 11).
- PowerShell activity investigation.
- Suspicious executable creation detection.
- Network connection detection.
- SPL-based searches and scheduled alerts.
- Basic alert triage and investigation documentation.

These capabilities are used to develop and validate detection use cases and investigation procedures.

## 6. Project Scope and Limitations

This is an educational home lab designed for controlled security monitoring and investigation exercises.

It is not a production SOC environment.

The current setup focuses on Windows endpoint telemetry, centralized log collection, basic detection engineering, and manual SOC Analyst L1 investigation workflows.

The environment may be expanded as additional monitoring and investigation capabilities are developed.

## 7. Security and Testing Considerations

All testing activities are performed within the controlled laboratory environment.

The network activity generated for detection validation is intentional and used to verify that endpoint telemetry is correctly collected, forwarded, indexed, and detected.

No production systems or third-party networks are intended to be targeted by these exercises.
## 8. Architecture Diagram

```mermaid
flowchart TB
    K["Kali Linux<br/>192.168.1.103<br/>Controlled Network Activity"]

    F["Fujitsu — Windows Endpoint<br/>192.168.1.102"]

    S["Sysmon<br/>Event Generation"]

    U["Splunk Universal Forwarder<br/>Event Collection"]

    D["Dell — Splunk Enterprise<br/>192.168.1.104"]

    I[("Splunk Index: sysmon")]

    K -->|"Network Traffic"| F
    F --> S
    S --> U
    U -->|"TCP 9997"| D
    D --> I
