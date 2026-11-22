# SOC Incident Response Playbooks

## Overview

This directory contains short incident response playbooks designed to support Tier 1 SOC analysis in the home lab environment.

Each playbook provides a consistent procedure to investigate a security alert, validate suspicious activity, collect relevant evidence, and determine whether escalation is required.

## Environment

- **SIEM:** Splunk Enterprise
- **Endpoint monitoring:** Sysmon
- **Log collection:** Splunk Universal Forwarder
- **Monitored endpoint:** `DESKTOP-1BDISO6`
- **Primary index:** `sysmon`
- **Log sources:** Sysmon Operational and Windows Security events

## Available Playbooks

| Playbook | Description | Related Detection |
|---|---|---|
| [Suspicious PowerShell](./suspicious-powershell.md) | Investigate potentially suspicious PowerShell activity | DET-005, DET-007 |
| [Suspicious Process Execution](./suspicious-process-execution.md) | Review unusual process execution and parent-child relationships | DET-004, DET-005, DET-006, DET-007 |
| [Suspicious File Creation](./suspicious-file-creation.md) | Investigate executable files created on the endpoint | DET-002, DET-003 |
| [Suspicious Network Activity](./suspicious-network-activity.md) | Analyze unusual inbound and outbound network connections | DET-008, DET-009, DET-010 |
| [Suspicious PowerShell Download](./suspicious-powershell-download.md) | Investigate PowerShell commands that may download files | DET-011 |
| [Suspicious Remote Access](./suspicious-remote-access.md) | Review potentially unauthorized remote access | DET-012 |
| [Multiple Failed Logons](./multiple-failed-logons.md) | Investigate repeated authentication failures | DET-001 |

## Standard Investigation Workflow

1. **Detection:** Review the triggered alert and identify the affected host.
2. **Triage:** Determine what happened, when it happened, and which account or process was involved.
3. **Investigation:** Correlate relevant events and inspect supporting evidence.
4. **Classification:** Decide whether the activity is expected, suspicious, or confirmed malicious.
5. **Escalation:** Escalate cases requiring further investigation or response.

## Evidence to Collect

When applicable, record:

- Alert name and detection reference.
- Timestamp and affected host.
- Username and process information.
- Command line and parent process.
- Source and destination IP addresses.
- Relevant event records and investigation findings.
- Classification and recommended next action.

## Important Notes

- A detection alert is an investigation lead, not proof of malicious activity.
- Validate suspicious behavior using multiple sources of evidence whenever possible.
- Do not classify activity as malicious based only on a process name, file extension, destination port, or failed login count.
- Preserve relevant evidence before closing or escalating an investigation.
- Follow the incident management workflow documented in the homelab.

## Disclaimer

These playbooks are designed for controlled lab exercises and educational purposes. They do not represent procedures from a production SOC environment.
