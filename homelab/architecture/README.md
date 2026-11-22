# SOC Home Lab Architecture

## 1. Overview

This section documents the architecture and log collection infrastructure of the SOC home lab.

The environment consists of three systems connected through a local network:

- **Dell Inspiron:** Hosts Splunk Enterprise and serves as the centralized SIEM.
- **Fujitsu Laptop:** Acts as the monitored Windows endpoint, generating Sysmon telemetry and forwarding events through Splunk Universal Forwarder.
- **Kali Linux:** Generates controlled network activity for detection validation and security investigation exercises.

The architecture is designed to support hands-on SOC Analyst Level 1 activities, including endpoint monitoring, centralized log collection, detection, alert triage, and incident investigation.

## 2. Architecture Documentation

The following documents describe the laboratory infrastructure and its operation.

### 2.1 SOC Lab Architecture

**File:** [`soc-lab-architecture.md`](./soc-lab-architecture.md)

Provides an overview of the complete laboratory infrastructure, including:

- System specifications and roles.
- Hostnames and IP addressing.
- Local network architecture.
- Communication between laboratory systems.
- Sysmon and Splunk Universal Forwarder integration.
- Event collection and data flow.
- Architecture diagram.
- Project scope and security considerations.

### 2.2 Splunk Data Collection

**File:** [`splunk-data-collection.md`](./splunk-data-collection.md)

Documents the technical implementation and verification of the Windows event collection pipeline, including:

- Sysmon Operational event collection.
- Splunk Universal Forwarder configuration.
- Windows Event Log input configuration.
- Splunk receiving configuration.
- TCP port 9997 communication.
- Event indexing and data reception verification.
- Sysmon Event ID availability.
- Field extraction verification.

## 3. Infrastructure Summary

| Component | System | Primary Role |
|---|---|---|
| SIEM Server | Dell Inspiron - Windows 11 | Splunk Enterprise |
| Monitored Endpoint | Fujitsu - Windows 10 Pro | Sysmon and Universal Forwarder |
| Testing Machine | Kali Linux | Controlled security testing |

### Network Configuration

| System | IP Address |
|---|---|
| Dell - SIEM Server | `192.168.1.104` |
| Fujitsu - Monitored Endpoint | `192.168.1.102` |
| Kali Linux - Testing Machine | `192.168.1.103` |
| Local Network | `192.168.1.0/24` |

**Relevant communication ports:**

- `9997/TCP`: Splunk receiving port for forwarded events.
- `8000/TCP`: Splunk Web interface.

## 4. Architecture and Monitoring Scope

The current laboratory architecture supports:

- Centralized Windows endpoint telemetry collection.
- Sysmon event monitoring.
- Process creation and execution analysis.
- Network connection monitoring.
- File creation monitoring.
- PowerShell activity investigation.
- SPL-based detection searches.
- Scheduled alert monitoring.
- SOC Analyst L1 investigation and escalation exercises.

The collected telemetry is primarily stored in the `sysmon` index. Additional Windows event sources and indexes are documented separately where applicable.

## 5. Related Documentation

The architecture documentation is part of the broader SOC home lab project.

Other relevant sections include:

- [`../detection/README.md`](../detection/README.md) — Detection use cases and SPL queries.
- [`../investigations/`](../investigations/) — Security investigation reports and incident evidence.
- [`../README.md`](../README.md) — Main SOC home lab documentation.

## 6. Project Scope

This is an educational SOC home lab, not a production SOC environment.

Its purpose is to demonstrate practical knowledge of endpoint telemetry collection, SIEM monitoring, detection development, investigation, and incident handling through a controlled environment.

The architecture and supporting documentation reflect the current laboratory configuration and may be updated as the infrastructure evolves.
