# Hammered Lab — SOC Analyst L1 Writeup

## Metadata

| Field | Value |
|---|---|
| Platform | CyberDefenders |
| Lab | Hammered |
| Target Role | SOC Analyst L1 |
| Target System | Ubuntu 2.6.24-26-server |
| Tools | `grep`, `awk`, `sort`, `uniq`, `wc` |
| Sources Analyzed | `auth.log`, `dmesg`, `dpkg.log`, `daemon.log`, `term.log`, `www-access.log` |
| Objective | Analyze Linux logs to identify initial access, persistence, TTPs, and reconstruct the timeline |

---

## Executive Summary

The target system was compromised through **SSH brute force**. The primary attacker, `219.150.161.20`, generated **9,259 failed attempts** and subsequently obtained successful access as the **`root`** user.

**6 unique IP addresses** were identified that successfully authenticated after failed attempts. The IP `219.150.161.20` logged in successfully the most times. Additionally, the installation of **Nmap**, the addition of rules to `iptables`, the creation of user **`wind3str0y`**, and the use of user-agent **`pxyscand/2.1`** associated with a proxy used for scanning were observed.

Critical findings:

- Exploited service: **SSH**
- Compromised account: **root**
- Most active IP: **219.150.161.20**
- Scanning tool installed: **nmap**
- User created: **wind3str0y**
- Suspicious user-agent: **pxyscand/2.1**
- Critical database warning: **MySQL root accounts without password**

---

## Answers

| # | Question | Answer |
|---|---|---|
| 1 | Service used for initial access | SSH |
| 2 | Operating system version | Ubuntu 2.6.24-26-server / kernel 2.6.24-26-server |
| 3 | Compromised account | `root` |
| 4 | Unique IPs with successful access after failures | 6 |
| 5 | IP with the most successful logins | `219.150.161.20` |
| 6 | Requests to the Apache server | 365 |
| 7 | Rules added to the firewall | 6 |
| 8 | Scanning tool downloaded | `nmap` |
| 9 | Last login from `219.150.161.20` | `2010-04-19 05:56:05` |
| 10 | Critical database warning | `mysql.user contains 2 root accounts without password!` |
| 11 | User created on April 26 at 04:43:15 | `wind3str0y` |
| 12 | User-agent of the proxy used for scans | `pxyscand/2.1` |

---

## Detailed Analysis

### 1. Initial Access: SSH Brute Force

Multiple SSH authentication failures concentrated from `219.150.161.20` were identified.

```bash
grep "Failed password" auth.log | grep -c "219.150.161.20"
```

Result: **9,259 failed attempts**.

The attempts occur with only a few seconds apart, which is consistent with automation:

```bash
grep "Failed password" auth.log | grep "219.150.161.20" | head -n 10
```

Example:

```text
Apr 19 05:38:01 app-1 sshd[7702]: Failed password for invalid user globus from 219.150.161.20 port 42337 ssh2
Apr 19 05:38:04 app-1 sshd[7706]: Failed password for invalid user marine from 219.150.161.20 port 44339 ssh2
Apr 19 05:38:05 app-1 sshd[7708]: Failed password for invalid user condor from 219.150.161.20 port 44816 ssh2
```

**Answer 1:** SSH.

---

### 2. Operating System Version

```bash
grep "Linux version" dmesg
```

Relevant output:

```text
Linux version 2.6.24-26-server (buildd@crested) (gcc version 4.2.4 (Ubuntu 4.2.4-1ubuntu3)) #1 SMP Tue Dec 1 18:26:43 UTC 2009 (Ubuntu 2.6.24-26.64-server)
```

The OS/kernel version is **Ubuntu 2.6.24-26-server**.

**Answer 2:** Ubuntu 2.6.24-26-server.

---

### 3. Compromised Account

Successful authentications from the brute force IP were reviewed:

```bash
grep "Accepted" auth.log | grep "219.150.161.20"
```

Output:

```text
Apr 19 05:41:44 app-1 sshd[8810]: Accepted password for root from 219.150.161.20 port 51249 ssh2
Apr 19 05:42:27 app-1 sshd[9031]: Accepted password for root from 219.150.161.20 port 40877 ssh2
Apr 19 05:55:20 app-1 sshd[12996]: Accepted password for root from 219.150.161.20 port 55545 ssh2
Apr 19 05:56:05 app-1 sshd[13218]: Accepted password for root from 219.150.161.20 port 36585 ssh2
```

**Answer 3:** `root`.

---

### 4. Unique IPs with Successful Access After Initial Failures

IPs with failed attempts were grouped, and a heuristic threshold of `>= 15` was applied to separate automated activity from noise:

```bash
grep "Failed password" auth.log \
  | grep -oE 'from [0-9.]+' \
  | awk '{print $2}' \
  | sort | uniq -c | sort -rn > failed_count.txt

awk '$1 >= 15 {print $2}' failed_count.txt > brute_ips.txt
```

Successful authentications from those IPs were then searched:

```bash
grep -F -f brute_ips.txt auth.log \
  | grep "Accepted" \
  | grep -oE 'from [0-9.]+' \
  | awk '{print $2}' \
  | sort -u \
  | wc -l
```

Result: **6 unique IPs**.

Identified IPs:

```text
219.150.161.20
122.226.202.12
61.168.227.12
222.66.204.246
222.169.224.197
121.11.66.70
```

**Answer 4:** 6.

> Methodological note: the `>= 15` threshold is a lab heuristic; in production it should be adjusted based on baseline and time window.

---

### 5. IP with the Most Successful Logins

```bash
grep -F -f brute_ips.txt auth.log \
  | grep "Accepted" \
  | grep -oE 'from [0-9.]+' \
  | awk '{print $2}' \
  | sort | uniq -c | sort -rn
```

Result:

```text
4 219.150.161.20
2 122.226.202.12
1 61.168.227.12
1 222.66.204.246
1 222.169.224.197
1 121.11.66.70
```

**Answer 5:** `219.150.161.20`.

---

### 6. Requests to the Apache Server

```bash
wc -l www-access.log
```

Result:

```text
365 www-access.log
```

**Answer 6:** 365 requests.

---

### 7. Rules Added to the Firewall

```bash
grep "iptables -A" auth.log | wc -l
```

Result: **6**.

**Answer 7:** 6 rules.

---

### 8. Scanning Tool Installed

The package installation log was reviewed:

```bash
grep -Ei "nmap|nikto|gobuster|dirb|masscan|sqlmap|hydra|whatweb|wpscan|ffuf|feroxbuster|openvas|nessus|acunetix" term.log
```

Relevant output:

```text
Selecting previously deselected package nmap.
Unpacking nmap (from .../archives/nmap_4.53-3_amd64.deb) ...
Setting up nmap (4.53-3) ...
```

**Answer 8:** `nmap`.

---

### 9. Last Login from `219.150.161.20`

```bash
grep "Accepted" auth.log | grep "219.150.161.20" | tail -n 1
```

Output:

```text
Apr 19 05:56:05 app-1 sshd[13218]: Accepted password for root from 219.150.161.20 port 36585 ssh2
```

The year is inferred by correlating with `dpkg.log`:

```bash
tail -n 1 dpkg.log
```

```text
2010-04-26 04:53:23 status installed yum 2.4.0-3.1
```

**Answer 9:** `2010-04-19 05:56:05`.

> Limitation: the year does not appear in the `auth.log` line; it is inferred from the time range of the lab logs.

---

### 10. Critical Database Warning

```bash
grep "WARNING" daemon.log
```

Relevant output:

```text
Apr 14 14:44:34 app-1 /etc/mysql/debian-start[5369]: WARNING: mysql.user contains 2 root accounts without password!
```

**Answer 10:** `mysql.user contains 2 root accounts without password!`

This condition is critical because it allows unauthenticated or empty-password access to MySQL accounts with elevated privileges.

---

### 11. User Created on April 26 at 04:43:15

```bash
grep "useradd" auth.log | grep "Apr 26"
```

Output:

```text
Apr 26 04:43:15 app-1 useradd[20115]: new user: name=wind3str0y, UID=1004, GID=1005, home=/home/wind3str0y, shell=/bin/bash
```

**Answer 11:** `wind3str0y`.

---

### 12. User-Agent of the Proxy Used for Scans

```bash
awk -F'"' '{print $6}' www-access.log | sort | uniq -c | sort -n
```

Relevant output:

```text
3 pxyscand/2.1
```

**Answer 12:** `pxyscand/2.1`.

---

## Incident Timeline

| Date/Time | Event |
|---|---|
| Apr 14 14:44:34 | MySQL warning: 2 root accounts without password |
| Apr 19 05:38 | Start of SSH brute force from `219.150.161.20` |
| Apr 19 05:41:44 | First successful login as `root` from `219.150.161.20` |
| Apr 19 05:56:05 | Last observed login from `219.150.161.20` |
| Apr 26 04:43:15 | Creation of user `wind3str0y` |

---

## IOCs

| Type | Value |
|---|---|
| Main attacker IP | `219.150.161.20` |
| IPs with successful access | `122.226.202.12`, `61.168.227.12`, `222.66.204.246`, `222.169.224.197`, `121.11.66.70` |
| Compromised account | `root` |
| User created | `wind3str0y` |
| Tool installed | `nmap` |
| Proxy user-agent | `pxyscand/2.1` |
| DB warning | `mysql.user contains 2 root accounts without password!` |

---

## MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|---|---|---|
| Brute Force | T1110 | 9,259 SSH failures from `219.150.161.20` |
| Valid Accounts | T1078 | Successful login as `root` |
| Network Service Discovery | T1046 | Installation of `nmap` |
| Create Account | T1136 | Creation of `wind3str0y` |

---

## Detection and Mitigation Recommendations

- Disable direct `root` login over SSH.
- Implement public key authentication and disable passwords where possible.
- Alert on more than N SSH failures from the same IP within a short window.
- Monitor execution of `useradd`, changes to `iptables`, and installation of reconnaissance tools.
- Review MySQL accounts without passwords and apply the principle of least privilege.
- Create rules to detect anomalous user-agents such as `pxyscand/2.1`.

---

## Lessons Learned

This lab reinforces the importance of correlating multiple log sources: `auth.log` for authentication, `dmesg` for kernel version, `term.log` for package installation, `daemon.log` for services, and `www-access.log` for web activity. A SOC L1 analyst must not only answer questions: they must document evidence, reconstruct the timeline, and propose detections.

---

## Conclusion

Initial access occurred through SSH brute force against the `root` user. The primary attacker made thousands of attempts, gained access, installed `nmap`, added firewall rules, and created the user `wind3str0y`. The MySQL warning about accounts without passwords represents an additional critical risk. The case demonstrates the need to monitor SSH authentication, user creation, firewall changes, and anomalous activity on web servers.
