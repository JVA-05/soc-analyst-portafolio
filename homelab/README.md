
# SOC Analyst Home Lab — Windows Monitoring, Threat Detection & Incident Investigation

## Project Overview

This project documents the development of a personal SOC Analyst home lab designed to simulate essential Tier 1 Security Operations Center (SOC) activities.

The environment focuses on Windows endpoint monitoring, centralized log collection, security event detection, alert validation, incident investigation and escalation procedures.

The main objective is to gain practical experience with SIEM operations and develop the technical and analytical skills required for a SOC Analyst L1 position.

## Lab Architecture

The laboratory consists of two physical computers and a virtualized security testing environment.

| System | Role | Tools |
|---|---|---|
| Dell Inspiron 15 3535 | SIEM workstation | Windows 11, Splunk Enterprise |
| Fujitsu Laptop | Monitored Windows endpoint | Windows, Sysmon, Splunk Universal Forwarder |
| Kali Linux VM | Controlled attacker simulation | Kali Linux |

### Architecture Overview

The Fujitsu endpoint generates Windows and Sysmon security events.

Splunk Universal Forwarder collects the configured event logs and forwards them to Splunk Enterprise running on the Dell workstation.

Splunk Enterprise indexes the received telemetry and provides the environment for searching, detection development, scheduled alerts and investigation.

The Kali Linux virtual machine is intended to generate controlled security testing activity for future detection and investigation scenarios.

## Technologies & Tools

- **Splunk Enterprise:** SIEM platform for centralized log collection, searching, detection and alert management.
- **Sysmon:** Windows system monitoring and detailed event generation.
- **Splunk Universal Forwarder:** Endpoint log collection and forwarding.
- **Splunk Add-on for Microsoft Sysmon:** Improved interpretation and field extraction of Sysmon events.
- **Kali Linux:** Controlled security testing and attacker behavior simulation.
- **Windows PowerShell:** Generation and investigation of endpoint activity.
- **Splunk Processing Language (SPL):** Security event searches and detection logic.

## Infrastructure & Log Collection

### Splunk Enterprise

Installed on the Dell workstation and configured to receive forwarded events through TCP port 9997.

### Windows Endpoint Monitoring

Sysmon was deployed on the Fujitsu laptop to collect detailed endpoint activity.

### Log Forwarding

Splunk Universal Forwarder was configured to transmit Sysmon Operational events to the central Splunk instance.

### Data Verification

Received Sysmon telemetry is indexed under:

`index=sysmon`

Process creation events (Event ID 1) have been successfully collected and analyzed.

## Detection Engineering

Initial detection use cases have been developed using Splunk Processing Language (SPL).

Current detection scenarios:

| Detection Use Case | Sysmon Event |
|---|---|
| PowerShell Process Execution | Event ID 1 |
| Suspicious PowerShell Execution | Event ID 1 |
| Office Applications Spawning Command-Line Interpreters | Event ID 1 |
| LOLBins Execution | Event ID 1 |
| PowerShell Network Connections | Event ID 3 |
| Executable File Creation in Downloads | Event ID 11 |

These detection rules identify potentially suspicious activity and require additional investigation before determining whether an actual security incident has occurred.

## Alert Management & Validation

Scheduled alerts have been configured in Splunk Enterprise.

The alerts use search-result-based trigger conditions and the Add to Triggered Alerts action.

Initial controlled tests have demonstrated successful alert generation for PowerShell process execution.

Further validation of the remaining detection use cases is ongoing.

## Incident Investigation Workflow

The project includes practical exercises designed to simulate Tier 1 SOC Analyst responsibilities.

The investigation methodology includes:

1. Alert reception and initial triage.
2. Identification of affected endpoints and users.
3. Process execution analysis.
4. Parent-child process relationship investigation.
5. Examination of command-line arguments.
6. Correlation with related endpoint events.
7. False positive and true positive assessment.
8. Incident documentation and escalation.

## Incident Escalation

A structured L1-to-L2 escalation workflow is being developed.

The objective is to document how a Tier 1 analyst collects evidence, evaluates suspicious activity, assesses severity and communicates findings to a Tier 2 analyst.

## Project Documentation

Detailed configuration guides, detection logic, investigation reports and supporting screenshots will be maintained in separate project directories.

- `architecture/` — Network and laboratory architecture.
- `configuration/` — Sysmon, Universal Forwarder and Splunk configuration.
- `detections/` — SPL detection searches and their validation.
- `investigations/` — Practical SOC investigation reports.
- `escalation/` — Incident escalation documentation.
- `screenshots/` — Supporting technical evidence.

## Skills Practiced

- SIEM administration and monitoring.
- Splunk SPL searches.
- Windows endpoint monitoring.
- Sysmon event analysis.
- Log collection and forwarding troubleshooting.
- Detection engineering fundamentals.
- Alert validation and triage.
- Incident investigation.
- Security event classification.
- SOC documentation and escalation procedures.

## Project Status

**Status: Work in Progress**

The core log collection infrastructure is operational, and initial detection searches and scheduled alerts have been configured and tested.

Current development priorities:

- Validate all detection use cases.
- Complete controlled security testing scenarios.
- Investigate and classify multiple alerts.
- Develop practical incident escalation reports.
- Expand endpoint and network monitoring capabilities.

All security testing is performed within authorized laboratory systems and controlled environments.
