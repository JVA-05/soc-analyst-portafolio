# First to Last - SOC Analyst L1 Investigation Report

## 1. Investigation Overview

**Role:** SOC Analyst L1  
**Lab:** [First to Last - Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/2026/08/09/index.html)  
**Primary tool:** Wireshark  
**Additional resource:** VirusTotal

### Objective

Investigate repeated FormBook command-and-control (C2) alerts by analyzing network traffic in a packet capture (PCAP). The objective was to identify the Windows client associated with the suspicious activity and establish the client's IP address, MAC address, hostname, username, and user's full name.

## 2. Alert Context

During the investigation, the SOC received multiple alerts identifying suspected FormBook C2 check-in activity over HTTP.

| Time (UTC) | Destination IP | Port | Alert |
|---|---|---|---|
| 02:13 | `172.64.155.76` | 80 | FormBook C2 Check-in |
| 02:14 | `146.59.71.167` | 80 | FormBook C2 Check-in |
| 02:14 | `38.182.168.246` | 80 | FormBook C2 Check-in |
| 02:15 | `45.130.41.161` | 80 | FormBook C2 Check-in |
| 02:15 | `172.67.162.153` | 80 | FormBook C2 Check-in |
| 02:16 | `121.54.163.148` | 80 | FormBook C2 Check-in |

The alerts continued over the following minutes, suggesting repeated network activity that required investigation.

### Network Environment

| Attribute | Value |
|---|---|
| Internal network | `172.16.8.0/24` |
| Domain | `firsttolast.tech` |
| Active Directory environment | `FIRSTTOLAST` |
| Domain controller | `172.16.8.2` |
| Domain controller hostname | `FIRSTTOLAST-DC` |
| Default gateway | `172.16.8.1` |
| Broadcast address | `172.16.8.255` |

## 3. Investigation Methodology

### Step 1. Investigate an Alerted Destination

I selected `172.64.155.76`, one of the IP addresses identified in the alerts, and filtered the packet capture for traffic involving that address over TCP port 80.

**Wireshark display filter:**

```text
ip.addr == 172.64.155.76 and tcp.port == 80
```

This filter allowed me to examine TCP traffic involving the alerted IP and inspect the associated HTTP communications.

While reviewing the traffic, I identified HTTP POST requests containing unusual request paths and parameter values.

One request referenced the following URL:

```text
http://www.independent.ie/ujvq/
```

The request contained a parameter named `2kn1` with a long, encoded-looking value:

```text
2kn1 = "NZo7 SiZkmVWl07yPdVOgIXsib1y5w0nlFtsTRMSN7ykhEeFafGUBoXNqT2UzMu1YYnGnRmrPhvf4e7kY3Ie6gMrUhWu7zp ZtppD8iDOp6pUBIhGMwT4xZFriMI9pxlGPs2wP E1fTlOEGdvRjwgP8XcSDc8KkdtZZmkUy7BSQvQ0aII stI1tVgdzQr7yNZM/XkCJg6220Ux04Tw=="
```

The unusual parameter value and request context warranted further investigation. However, an unusual URL or encoded-looking value is not sufficient on its own to establish malicious activity.

### Step 2. Examine HTTP POST Traffic

To investigate whether the behavior was isolated or repeated across the capture, I applied the following display filter:

```text
http.request.method == "POST"
```

This revealed multiple POST requests to different URLs, several of which contained the same parameter name, `2kn1`, with different values.

One example was:

```text
http://www.taibeinan.cc/lqjm/
```

I checked the URLs using VirusTotal. Some received a small number of malicious detections, including the example above, which had four detections at the time of my analysis.

I did not treat these results as conclusive evidence by themselves. A low detection count can provide a lead for further investigation, but it does not independently confirm that a domain or URL is malicious.

The more significant observation was the recurring pattern of POST requests to different destinations, with similar request structures and the same parameter name.

This pattern, combined with the existing FormBook C2 alerts, increased the suspicion that the traffic was related to automated malware communications.

### Step 3. Correlate the Activity to an Internal Client

While examining the repeated HTTP POST requests, I observed that the traffic originated from the same internal client:

```text
172.16.8.49
```

This was an important correlation because it connected the suspicious network activity to a specific host on the organization's internal network.

The internal IP was within the documented `172.16.8.0/24` LAN segment.

### Step 4. Identify the Hostname and MAC Address

To identify the host associated with the internal IP, I used the following Wireshark filter:

```text
nbns and ip.addr == 172.16.8.49
```

The NBNS traffic revealed the following information:

| Attribute | Value |
|---|---|
| Host IP address | `172.16.8.49` |
| Hostname | `DESKTOP-5NLV63K` |
| MAC address | `00:12:f0:28:d4:34` |

These network observations allowed me to associate the suspicious traffic with a specific Windows client.

### Step 5. Identify the User Account

I then examined Kerberos traffic associated with the identified client to determine which user account appeared in the authentication traffic.

**Wireshark display filter:**

```text
ip.addr == 172.16.8.49 and kerberos.CNameString and !(kerberos.CNameString contains "$")
```

The results identified the username:

```text
rvance
```

The filter excludes Kerberos client names containing `$`, which can help distinguish ordinary user accounts from computer accounts in the relevant traffic. The resulting packet should still be checked to verify the account name.

### Step 6. Retrieve the User's Full Name

To find the full name associated with the user account, I examined SAMR user information in the capture using:

```text
samr.samr_UserInfo21.full_name and ip.addr == 172.16.8.49
```

The full name associated with the account was:

```text
Raymond Vance
```

This completed the identification of the client and its associated user account using the available network evidence.

## 4. Findings Summary

| Investigation question | Finding |
|---|---|
| Infected Windows client IP | `172.16.8.49` |
| Client MAC address | `00:12:f0:28:d4:34` |
| Client hostname | `DESKTOP-5NLV63K` |
| User account name | `rvance` |
| User's full name | Raymond Vance |

## 5. Security Assessment

The investigation identified a Windows client associated with repeated HTTP POST requests to multiple destinations. These requests shared a recurring structure and included a parameter named `2kn1` with unusual values.

The traffic was investigated in the context of repeated FormBook C2 alerts. This combination of alert context and observed network behavior supports treating the client as a suspected malware-affected endpoint.

VirusTotal results provided additional investigative leads, but the low detection counts observed for individual URLs were not considered sufficient to establish maliciousness independently.

**Assessment:** The available evidence supports escalating the client for further investigation as a suspected FormBook infection.

The PCAP analysis identifies the client associated with the suspicious traffic, but it does not, by itself, establish the full extent of compromise or prove how the malware initially reached the system.

## 6. Recommended Next Steps

If this were a live SOC investigation, I would recommend the following actions:

- Review endpoint detection and response (EDR) telemetry for FormBook detections, suspicious processes, and related file activity on `172.16.8.49`.
- Correlate the observed HTTP requests with proxy, firewall, DNS, and endpoint logs.
- Investigate the alerted destination IPs and related network indicators using approved threat intelligence sources.
- Examine the suspicious POST request bodies and other available packet details to determine what information was transmitted, where possible.
- Review endpoint and authentication logs for evidence of execution, persistence, or additional suspicious activity.
- Preserve the PCAP and relevant logs as investigation evidence.
- Follow the organization's incident response and escalation procedures. Any containment action should be based on the severity of the evidence and the SOC's established procedures.

## 7. Skills Demonstrated

- Wireshark filtering and HTTP traffic analysis.
- Investigating suspicious POST requests and recurring network patterns.
- Correlating security alerts with packet-level evidence.
- Using VirusTotal as a supporting threat intelligence resource.
- Identifying an internal Windows client from network traffic.
- Examining NBNS, Kerberos, and SAMR traffic to collect host and user information.
- Documenting findings and distinguishing investigative leads from confirmed evidence.

## 8. Conclusion

This investigation used packet-level analysis to correlate repeated FormBook C2 alerts with suspicious HTTP activity from an internal Windows client.

By combining alert context, HTTP request analysis, and host-related network protocols, I identified the client IP address, MAC address, hostname, username, and user's full name.

The results provide a basis for further endpoint investigation and incident response. Additional endpoint and network telemetry would be required to establish the full scope of the suspected infection.

**Disclaimer:** This report documents a cybersecurity training exercise and demonstrates practical investigation techniques. It does not represent professional SOC employment experience.
