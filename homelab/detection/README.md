# SOC Detection Engineering

## Overview

This directory contains the detection rules developed and implemented in the SOC homelab using Splunk Enterprise.

The detections focus on identifying suspicious authentication activity, process execution, PowerShell behavior, network connections, and remote access activity on the monitored Windows endpoint.

Each detection includes its objective, data sources, SPL query, detection logic, alert configuration, investigation guidance, limitations, and validation information.

## Detection Categories

### Authentication

| Detection | Description |
|---|---|
| Multiple Failed Logon Attempts | Identifies repeated failed Windows authentication attempts. |

### Process Execution

| Detection | Description |
|---|---|
| Executable File Creation | Identifies executable file creation activity. |
| Executable Created in Downloads | Identifies executable files created in the Downloads directory. |
| Office Spawning Shell | Identifies Office applications launching command interpreters or shells. |
| PowerShell Execution | Monitors PowerShell process execution. |
| Suspicious LOLBins Execution | Identifies execution of selected Windows utilities that may be abused by attackers. |
| Suspicious PowerShell | Identifies potentially suspicious PowerShell command-line patterns. |

### Network Activity

| Detection | Description |
|---|---|
| Incoming HTTP Connection | Identifies incoming HTTP connection activity. |
| PowerShell Network Activity | Identifies network activity associated with PowerShell. |
| Suspicious Outbound Network Connection | Identifies outbound network connections matching suspicious conditions. |
| Suspicious PowerShell Download | Identifies potentially suspicious download activity involving PowerShell. |

### Remote Access

| Detection | Description |
|---|---|
| Suspicious Remote Access | Identifies remote access activity requiring investigation. |

## Detection Documentation

Each detection has an individual technical document containing its SPL query, data sources, logic, configuration, investigation guidance, and limitations.

## Validation and Maintenance

Detection rules are tested through controlled lab activity.

The documentation records validation results, known limitations, and potential false positives. Detection status is maintained separately from the investigation status of related incidents.

## Environment

**SIEM:** Splunk Enterprise  
**Endpoint telemetry:** Sysmon  
**Windows telemetry:** Windows Event Logs  
**Log collection:** Splunk Universal Forwarder  
**Monitored endpoint:** Fujitsu Windows system

This detection library is developed for a controlled SOC homelab environment. It is intended for learning, detection engineering practice, and SOC Analyst L1 investigation workflows.
