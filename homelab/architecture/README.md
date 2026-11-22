# SOC Homelab Architecture

## Overview

This document describes the architecture of the SOC homelab, including its infrastructure, network configuration, endpoint monitoring components, and event collection workflow.

The environment is designed to simulate a small-scale Security Operations Center (SOC), allowing security events to be generated, collected, centralized, monitored, and investigated using Splunk Enterprise.

The lab consists of three primary systems:

- **Dell:** SIEM server running Splunk Enterprise.
- **Fujitsu:** Monitored Windows endpoint running Sysmon and Splunk Universal Forwarder.
- **Kali Linux:** Testing system used to generate controlled security-related activity.

## Infrastructure Components

| System | Operating System | IP Address | Role |
|---|---|---|---|
| Dell Inspiron 15 3535 | Windows 11 | `192.168.1.104` | Splunk Enterprise server |
| Fujitsu | Windows 10 Pro | `192.168.1.102` | Monitored endpoint |
| Kali Linux | Kali Linux | `192.168.1.103` | Security testing system |

**Network:** `192.168.1.0/24`

All three systems are connected to the same local network.

## System Roles

### 1. Dell — SIEM Server

**Operating System:** Windows 11  
**IP Address:** `192.168.1.104`  
**SIEM Platform:** Splunk Enterprise 10.6.1.1

The Dell system acts as the central SIEM server.

Its responsibilities include:

- Receiving forwarded telemetry from the monitored endpoint.
- Indexing and storing collected events.
- Providing SPL-based searches and investigations.
- Executing scheduled detection searches and alerts.
- Displaying security information through the SOC dashboard.

Splunk Enterprise receives forwarded events through TCP port `9997`.

The Splunk Web interface is available through port `8000`.

### 2. Fujitsu — Monitored Endpoint

**Operating System:** Windows 10 Pro  
**Hostname:** `DESKTOP-1BDISO6`  
**IP Address:** `192.168.1.102`

The Fujitsu system acts as the monitored Windows endpoint.

It runs two primary monitoring components:

**Sysmon**

Sysmon provides detailed endpoint telemetry, including:

- Process creation events.
- Network connection events.
- File creation events.

Relevant Sysmon Event IDs include:

| Event ID | Description |
|---|---|
| 1 | Process Creation |
| 3 | Network Connection |
| 11 | File Create |

**Splunk Universal Forwarder**

The Universal Forwarder collects configured Windows event logs and forwards them to the Splunk Enterprise server.

Its responsibilities include:

- Collecting Sysmon Operational events.
- Collecting configured Windows Event Logs.
- Forwarding events to the Dell SIEM server.
- Maintaining communication with the configured receiving endpoint.

### 3. Kali Linux — Testing System

**Operating System:** Kali Linux  
**IP Address:** `192.168.1.103`

Kali Linux is used to generate controlled security-related activity for laboratory testing.

It supports scenarios such as:

- Authentication testing.
- Network connection testing.
- Remote access simulations.
- Controlled interaction with the monitored Windows endpoint.

Kali is used as a testing system, not as part of the production monitoring infrastructure.

Since Kali and the Fujitsu endpoint share the same local network, these activities simulate an internal network threat scenario rather than a connection originating from a genuinely external network.

## Event Collection Architecture

The endpoint monitoring and event collection workflow is based on Sysmon and Splunk Universal Forwarder.

The process follows these stages:

1. **Activity Generation:** User activity or controlled security testing generates events on the Fujitsu endpoint.
2. **Telemetry Collection:** Sysmon records supported endpoint activity, while Windows records security and operational events.
3. **Event Forwarding:** Splunk Universal Forwarder collects the configured event sources.
4. **Centralized Ingestion:** Events are forwarded to the Dell system through TCP port `9997`.
5. **Indexing:** Splunk Enterprise processes and stores the incoming events.
6. **Security Monitoring:** SPL searches, detection rules, alerts, and dashboards provide visibility into the collected telemetry.
7. **Investigation:** The analyst reviews relevant events, correlates evidence, and documents findings.

## Data Sources and Indexes

The laboratory uses separate Splunk indexes for the principal event sources.

| Index | Data Source | Purpose |
|---|---|---|
| `sysmon` | Sysmon Operational Log | Endpoint activity and process telemetry |
| `wineventlog` | Windows Event Logs | Windows authentication and security events |

The `sysmon` index supports investigations involving process execution, network connections, and file creation.

The `wineventlog` index supports investigations involving Windows authentication and security events.

Additional Splunk internal and laboratory indexes may exist for platform operations or separate exercises.

## Communication and Network Configuration

| Source | Destination | Protocol | Port | Purpose |
|---|---|---|---|---|
| Fujitsu | Dell | TCP | 9997 | Forwarded event ingestion |
| Analyst workstation | Dell | TCP | 8000 | Splunk Web access |

The Universal Forwarder is configured to send events to the Dell system at `192.168.1.104:9997`.

The receiving port must be accessible through the Dell firewall for event forwarding to work.

## Monitoring and Detection Layer

Once events are indexed, Splunk Enterprise provides the main monitoring and investigation capabilities.

The SOC homelab includes:

- **Detection Engineering:** SPL-based detection rules for authentication, process execution, network activity, and remote access.
- **Alerting:** Configured alert searches for identifying activity that requires analyst attention.
- **SOC Dashboard:** A four-tab dashboard covering Summary, Authentication, Process & Execution, and Network & Remote Access.
- **Incident Investigations:** Documented investigations based on collected telemetry and controlled laboratory scenarios.

These capabilities allow the analyst to move from event visibility to detection, triage, investigation, and escalation.

## Architecture Scope and Limitations

This architecture represents a controlled, small-scale SOC laboratory.

Its main limitations include:

- Monitoring is focused on one Windows endpoint.
- The testing system and monitored endpoint share the same local network.
- Detection coverage depends on the configured Sysmon and Windows event sources.
- The environment does not represent a distributed enterprise network.
- The laboratory does not provide comprehensive network traffic inspection or enterprise-wide endpoint visibility.

The architecture is intended to demonstrate practical experience with endpoint telemetry, centralized log collection, SIEM monitoring, detection engineering, and SOC investigation workflows.

## Related Documentation

- [Detection Engineering](../detection/README.md)
- [SOC Dashboard Documentation](../dashboards/README.md)


## Project Purpose

This homelab demonstrates the implementation of a basic SOC monitoring environment using freely available or accessible security technologies.

It provides a practical environment for developing SOC Analyst L1 skills, including event analysis, SPL searches, alert triage, endpoint investigation, evidence collection, and incident escalation.
