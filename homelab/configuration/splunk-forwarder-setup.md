# Splunk Universal Forwarder Setup

## 1. Overview

This document describes the installation and configuration of Splunk Universal Forwarder on a Windows endpoint. The Forwarder collects Windows event logs and sends them to a centralized Splunk Enterprise instance for monitoring and investigation.

## 2. Lab Environment

| Component | Details |
|---|---|
| Forwarder Host | Fujitsu Laptop |
| Hostname | DESKTOP-1BDISO6 |
| Operating System | Windows |
| Forwarder Software | Splunk Universal Forwarder |
| Splunk Enterprise Server | Dell Inspiron 15 |
| Splunk Server IP | 192.168.1.104 |
| Receiving Port | TCP 9997 |

## 3. Installation Path

Splunk Universal Forwarder is installed at:

`C:\Program Files\SplunkUniversalForwarder\`

## 4. Forwarder Output Configuration

The forwarding destination is configured in:

`C:\Program Files\SplunkUniversalForwarder\etc\system\local\outputs.conf`

Configuration:

```ini
[tcpout]
defaultGroup = default-autolb-group

[tcpout:default-autolb-group]
server = 192.168.1.104:9997

[tcpout-server://192.168.1.104:9997]
```

The configuration directs the Forwarder to send data to the Splunk Enterprise server at `192.168.1.104` using TCP port `9997`.

## 5. Deployment Server Configuration

The following file was checked:

`C:\Program Files\SplunkUniversalForwarder\etc\system\local\deploymentclient.conf`

The file was not present. No Deployment Server configuration was identified in this location.

A Deployment Server is not required for direct event forwarding.

## 6. Windows Service Configuration

The Windows service was verified using PowerShell:

```powershell
Get-Service -Name SplunkForwarder |
Format-List Name, DisplayName, Status, StartType
```

Verified results:

- Service name: `SplunkForwarder`
- Status: `Running`
- Startup type: `Automatic`

This ensures that the Forwarder starts automatically with Windows.

## 7. Forwarding Verification

The forwarding configuration was checked using:

```powershell
& "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" list forward-server
```

Verified result:

```text
Active forwards:
    192.168.1.104:9997

Configured but inactive forwards:
    None
```

The Forwarder successfully maintains an active connection to the configured Splunk Enterprise destination.

## 8. Conclusion

Splunk Universal Forwarder is installed and running on the Fujitsu Windows endpoint. Its output configuration points to the Splunk Enterprise server on the Dell laptop, and the forwarding destination is reported as active.

The Forwarder service is configured for automatic startup, providing persistent log forwarding after Windows restarts.
