# INC-005 — Suspicious PowerShell Download

## Detection

| Field | Detail |
|---|---|
| Triggered Alert | Suspicious PowerShell Download |
| Detection Time | 2026-11-19 17:20:02 |
| Host | DESKTOP-1BDISO6 |
| User | Administrador |
| Source IP | 192.168.1.103 |
| Downloaded File | INC005-payload.txt |
| Severity | Medium |
| Status | Closed |

## Investigation

- At 17:17:36.760, PowerShell executed `Invoke-WebRequest` to download `payload.txt` from `192.168.1.103`.
- The file was saved in `C:\Users\ADMINI~1\AppData\Local\Temp\INC005-payload.txt`.
- Sysmon Event ID 1 recorded the PowerShell execution and its command line.
- The HTTP server on the source host returned HTTP 200, confirming successful delivery.
- The source IP belongs to the Kali Linux host, acting as an external host relative to the simulated corporate environment.

## Conclusion

**Verdict:** True Positive — Suspicious Activity.

The detection correctly identified a PowerShell download from an external host. However, the available evidence does not establish that the downloaded file was malicious or that it caused a compromise.

The activity was part of an authorized laboratory simulation. No confirmed malicious execution or system compromise was established.

**Severity:** Medium (simulated).

**Disposition:** Closed — Benign Lab Activity.

**Escalation:** No further escalation required.
