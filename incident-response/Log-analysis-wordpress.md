# Incident Investigation: Compromised WordPress Website

## 1. Investigation Overview

| Field | Details |
|---|---|
| Role | SOC Analyst L1 |
| Platform | Blue Team Labs Online (BTLO) |
| Challenge | Log Analysis – Compromised WordPress |
| SIEM | Splunk |
| Investigation Type | Web Log Analysis / Incident Investigation |
| Primary Focus | Web attack activity, vulnerability exploitation, and web shell investigation |

**Lab:** [Log Analysis – Compromised WordPress](https://blueteamlabs.online/home/challenge/log-analysis-compromised-wordpress-ce000f5b59)

## 2. Incident Background

A WordPress website was reported as compromised. The initial hypothesis was that an attacker exploited a vulnerable plugin to achieve remote code execution (RCE) and gain access to the underlying server.

The investigation focused on identifying the attacker’s activity, determining which tools were used, examining evidence of attempted plugin exploitation, and tracing activity associated with a suspected PHP web shell.

## 3. Investigation Objectives

The investigation aimed to answer the following questions:

1. What was the administrative login URI, including its security token?
2. Which tools did the attacker use?
3. Which CVE was associated with the attempted Contact Form 7 exploitation?
4. Which plugin was associated with the successful access vector?
5. What was the name of the suspected PHP web shell?
6. What HTTP response code was recorded during the final request to the web shell?

## 4. Investigation and Findings

### 4.1. Initial Log Review and Administrative Login URI

I began by reviewing the available data in Splunk to understand the log structure and identify the fields relevant to the investigation.

I then filtered the events associated with the WordPress login endpoint:

```spl
index="btlo_lab" uri_path="/wp-login.php"
```

During this review, I identified a request to the following URI:

```text
/wp-login.php*" uri="/wp-login.php?itsec-hb-token=adminlogin&mglS=2151%2BAND%2B1%3D1%2BUNION%2BALL%2BSELECT%2B1%2CNULL%2C%27%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E%27%2Ctable_name%2BFROM%2Binformation_schema.tables%2BWHERE%2B2%3E1--%2F%2A%2A%2F%3B%2BEXEC%2Bxp_cmdshell%28%27cat%2B..%2F..%2F..%2Fetc%2Fpasswd%27%29%23
```

The request contained a URL-encoded payload. After decoding it, I observed several recognizable attack patterns, including:

- A SQL injection-style expression using `UNION ALL SELECT`.
- An embedded JavaScript payload intended to trigger an XSS alert.
- A command-execution attempt containing `xp_cmdshell` and a reference to `/etc/passwd`.

These patterns indicate an attempt to test or exploit multiple injection techniques. However, the presence of a payload in a request does not establish that the targeted vulnerability was exploitable or that the payload executed successfully.

The administrative login URI identified for the challenge was:

```text
/wp-login.php?itsec-hb-token=adminlogin
```

### 4.2. Investigating the HTTP Response

To examine the response associated with the suspicious request, I used the following search:

```spl
index="btlo_lab" uri_path="/wp-login.php"
uri="/wp-login.php?itsec-hb-token=adminlogin&mglS=..."
status=200
```

The query returned an HTTP `200` response associated with the request.

A `200 OK` response confirms that the server returned a successful HTTP response. It does **not**, by itself, prove that SQL injection, XSS, command execution, or another exploit succeeded.

The request therefore provided evidence of attempted injection activity, while additional server-side or application evidence would be required to confirm execution.

### 4.3. Identifying the Source IP and Attacker Tools

I associated the suspicious request sequence with the following source IP address:

```text
168.22.54.119
```

I then examined the User-Agent values associated with this address:

```spl
index="btlo_lab" uri_path="/wp-login.php"
clientip="168.22.54.119"
| stats count by useragent
| sort - count
```

One of the observed User-Agent values was:

```text
sqlmap/1.4.11#stable (http://sqlmap.org)
```

This indicates that the requests identifying themselves with this User-Agent were consistent with activity from **sqlmap**, a tool used to test for and exploit SQL injection vulnerabilities.

To identify other tools present in the dataset, I reviewed the distinct User-Agent values:

```spl
index="btlo_lab"
| stats count by useragent
| sort - count
```

The results included:

```text
WPScan v3.8.10 (https://wpscan.org/)
python-requests/2.24.0
```

WPScan is a security scanner designed to assess WordPress websites, including their plugins and known vulnerabilities.

The `python-requests` User-Agent indicates that the requests were made using Python's Requests library or software identifying itself that way. It does not independently establish malicious intent or identify a specific tool.

**Finding:** The investigation identified sqlmap and WPScan as tools represented in the logs. The attribution of every request to the same operator should be based on source IP, timestamps, and related event evidence rather than User-Agent values alone.

### 4.4. Investigating the Contact Form 7 Exploitation Attempt

During the review, I identified activity targeting the following plugin path:

```text
/wp-content/plugins/contact-form-7/uploads/fr34k.png
```

The observed activity was consistent with an attempt to interact with a file path associated with Contact Form 7.

The vulnerability investigated in connection with this activity was:

**CVE-2020-35489**

The evidence should be interpreted carefully: a request targeting a plugin-related path does not, by itself, prove that the plugin vulnerability was successfully exploited. Confirmation would require correlating the request with the vulnerability’s exploitation conditions and the server’s response or resulting file activity.

### 4.5. Identifying the Plugin Associated with the Access Vector

I then examined requests associated with the following path:

```text
/wp-content/uploads/simple-file-list/fr34k.png
```

The filename `fr34k.png` appeared in activity associated with the Simple File List plugin.

Research into the plugin's vulnerability history identified the following vulnerability description:

**Simple File List versions earlier than 4.2.3 — Unauthenticated Arbitrary File Upload leading to Remote Code Execution**

This vulnerability is consistent with a scenario in which an attacker uploads a file and subsequently attempts to execute it through the web server.

The observed sequence was consistent with an attempted file-upload-to-RCE attack. However, the log evidence should be used to establish the sequence of requests, while confirmation of successful code execution would require additional evidence.

### 4.6. Tracking the Suspected PHP Web Shell

The investigation followed the filename `fr34k.png` through subsequent requests.

The observed activity was consistent with a possible transition from:

```text
fr34k.png
```

to:

```text
fr34k.php
```

The PHP filename was associated with subsequent HTTP requests, including POST and GET activity.

A file extension change cannot be established merely because both filenames appear in related requests; the logs must show the relevant server-side processing or file activity. Nevertheless, the observed sequence, combined with the suspected arbitrary file upload vulnerability, supported investigating `fr34k.php` as a potential web shell.

A web shell is a server-side script that can provide an attacker with a way to execute commands or perform other unauthorized operations through HTTP requests.

### 4.7. Final Request to the Web Shell

The final request to the suspected web shell returned the following HTTP response code:

```text
404 Not Found
```

This means that the requested resource was not found at the requested path when that response was generated.

Possible explanations include file deletion, a changed path, access through an incorrect URI, or other server-side changes. The response code alone does not prove that the attacker deleted the web shell or that the compromise had been remediated.

## 5. Summary of Findings

| Investigation Question | Finding |
|---|---|
| Administrative login URI | `/wp-login.php?itsec-hb-token=adminlogin` |
| Identified tools | sqlmap and WPScan |
| Contact Form 7 vulnerability investigated | CVE-2020-35489 |
| Plugin associated with the suspected access vector | Simple File List, vulnerable versions earlier than 4.2.3 |
| Suspected PHP web shell | `fr34k.php` |
| Final recorded HTTP response | `404 Not Found` |

## 6. Security Assessment

The available logs show web requests consistent with reconnaissance, injection attempts, and activity involving a potentially vulnerable WordPress plugin.

The combination of suspicious requests, a plugin-related upload path, and subsequent requests associated with a PHP filename supports treating the activity as a potential web compromise requiring further investigation.

However, HTTP access logs alone may not establish whether the attacker successfully executed operating-system commands, obtained persistent access, or exfiltrated data.

### Recommended Follow-up Actions

1. Preserve the relevant web access logs and any available application, PHP, and web-server error logs.
2. Inspect the suspected web shell and related files using a controlled forensic process.
3. Review file creation and modification timestamps to establish whether the upload and execution sequence can be confirmed.
4. Correlate suspicious requests with process creation, command execution, and endpoint telemetry, if available.
5. Check the WordPress plugin inventory and versions against the relevant vulnerability advisories.
6. Review WordPress administrative accounts, authentication events, and other potential persistence mechanisms.
7. If compromise is confirmed, follow the organization's incident response procedures to contain the affected host, remove malicious artifacts, patch vulnerable components, and validate recovery.

## 7. Skills Demonstrated

- Splunk-based web log investigation
- Filtering and correlating HTTP requests
- Interpreting URL-encoded attack payloads
- Identifying suspicious User-Agent values
- Recognizing SQL injection, XSS, and command-execution patterns
- Investigating WordPress plugin vulnerabilities
- Tracking suspicious file activity
- Distinguishing observed evidence from unconfirmed conclusions

## 8. Conclusion

This investigation examined suspicious activity against a WordPress website and identified requests associated with sqlmap, WPScan, Contact Form 7, Simple File List, and a suspected PHP web shell named `fr34k.php`.

The findings support the hypothesis of a web compromise, but additional server-side and endpoint evidence would be needed to confirm successful remote code execution and determine the full impact.

The investigation demonstrates a structured approach to log analysis, attack-pattern recognition, and evidence-based incident assessment.

## References

- [BTLO — Log Analysis: Compromised WordPress](https://blueteamlabs.online/home/challenge/log-analysis-compromised-wordpress-ce000f5b59)
- [CVE-2020-35489 — NVD](https://nvd.nist.gov/vuln/detail/CVE-2020-35489)
- [WPScan](https://wpscan.com/)
- [Splunk Documentation](https://help.splunk.com/)

---

**Disclaimer:** This report documents an educational investigation conducted using the supplied lab data. Findings and conclusions are limited to the evidence reviewed.
