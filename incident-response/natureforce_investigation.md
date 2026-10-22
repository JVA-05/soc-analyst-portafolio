# NatureForce - SOC Analyst L1 Investigation

## 1. Investigation Overview

**Role:** SOC Analyst L1  
**Lab:** [NatureForce - Malware Traffic Analysis](https://www.malware-traffic-analysis.net/2026/10/01/index.html)  
**Primary tool:** Wireshark  
**Additional tools:** Linux `sha256sum`, VirusTotal

### Objective

Investigate a packet capture (PCAP) associated with security alerts involving a Windows executable download and suspected command-and-control (C2) traffic. The goal was to identify the affected Windows client, collect relevant host information, and calculate the SHA-256 hash of the downloaded executable.

### Initial Alerts

| Source | Alert |
|---|---|
| `107.175.82.242:9000` | Windows executable transferred over an unusual TCP port |
| `195.64.128.106:443` | CNCmachineRMS RAT command-and-control traffic |

The investigation focused on identifying the client associated with the executable transfer and gathering evidence to assess the alert.

## 2. Investigation Process

### Step 1. Identify the HTTP Request

I started by filtering traffic originating from `107.175.82.242` and using TCP port `9000`.

**Wireshark display filter:**

```text
ip.src == 107.175.82.242 and tcp.port == 9000
```

I used `ip.src` because the alert indicated that the executable was sent from this IP address.

The filtered traffic revealed the following HTTP GET request:

```http
GET /wilow/runner_ilove.exe HTTP/1.1
Host: 107.175.82.242:9000
User-Agent: curl/8.21.0
Accept: */*
```

The request provided two relevant indicators:

- **Requested file:** `runner_ilove.exe`
- **User-Agent:** `curl/8.21.0`

Curl is a legitimate command-line tool commonly used to transfer data. Its presence alone does not establish malicious activity. However, the requested executable and the surrounding security alerts justified further investigation.

### Step 2. Extract and Hash the Executable

I exported the transferred executable from the packet capture using Wireshark and saved it locally as `ilove`.

I then calculated its SHA-256 hash using Linux:

```bash
sha256sum ilove
```

**Result:**

```text
b789adce70c028a6d17be45ec34667aa95586350ee0c4057e75b138b1ad35061
```

I submitted the hash to VirusTotal for reputation analysis. The result classified the file as malicious, specifically as a Trojan.

This finding strengthened the suspicion that the executable was malicious. The hash provides a unique identifier that can be used to search for related activity in endpoint and security monitoring tools.

### Step 3. Identify the Affected Windows Client

By examining the HTTP transfer and its destination, I identified the receiving client as:

```text
10.10.1.128
```

I used this IP address to investigate additional host information in the packet capture.

### Step 4. Identify the Hostname and MAC Address

I filtered for NBNS traffic associated with the external IP:

```text
ip.addr == 107.175.82.242 and nbns
```

The traffic revealed the following host information:

| Attribute | Value |
|---|---|
| Hostname | `DESKTOP-4VGYQX7` |
| MAC address | `00:22:fb:ec:7e:e7` |

These values helped associate the network activity with a specific Windows client.

### Step 5. Identify the User Account

To investigate the user account associated with the client, I applied the following Wireshark filter:

```text
ip.addr == 10.10.1.128 and kerberos.cname_string == 1
```

The Kerberos traffic revealed the username:

```text
bdiaz
```

This account name was recorded as part of the host investigation.

## 3. Investigation Findings

The following table summarizes the answers obtained during the investigation.

| Question | Finding |
|---|---|
| Infected Windows client IP | `10.10.1.128` |
| Client MAC address | `00:22:fb:ec:7e:e7` |
| Client hostname | `DESKTOP-4VGYQX7` |
| User account | `bdiaz` |
| Executable SHA-256 | `b789adce70c028a6d17be45ec34667aa95586350ee0c4057e75b138b1ad35061` |

## 4. Security Assessment

The investigation identified a Windows client that received an executable from an external IP address over TCP port `9000`. The executable was extracted from the packet capture, hashed, and identified as malicious by VirusTotal.

These findings support treating the file transfer as a security incident requiring further investigation.

However, the PCAP and file reputation alone do not confirm that the executable was executed or establish the full extent of a compromise. The separate CNCmachineRMS RAT C2 alert should also be investigated and correlated with the affected client.

### Recommended Next Steps

- Search endpoint security logs for the executable name and SHA-256 hash.
- Review process execution and persistence-related events on `10.10.1.128`.
- Investigate the alert involving `195.64.128.106:443` and determine whether the client communicated with that address.
- Correlate the PCAP findings with DNS, proxy, firewall, and EDR telemetry.
- Preserve relevant evidence and follow the organization's incident response procedures for containment and escalation.

## 5. Skills Demonstrated

- Network traffic analysis using Wireshark.
- Filtering traffic by IP address, TCP port, and protocol.
- HTTP request inspection and executable transfer analysis.
- Extracting a file from a PCAP and calculating its SHA-256 hash.
- Using VirusTotal for file reputation checks.
- Identifying a host through network traffic.
- Reviewing Kerberos traffic to identify a user account.
- Documenting evidence and distinguishing confirmed findings from unverified conclusions.

## 6. Conclusion

This investigation demonstrated how network traffic analysis can help a SOC analyst investigate a suspicious executable transfer, identify the affected client, and collect indicators for further investigation.

The key outcome was the identification of the client IP, hostname, MAC address, user account, and executable hash. These findings provide a starting point for endpoint investigation, threat hunting, and incident response.

**Disclaimer:** This report documents analysis performed in a cybersecurity training environment. It does not claim professional incident response experience.
