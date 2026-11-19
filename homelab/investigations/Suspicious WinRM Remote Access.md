# INC-004 — Suspicious WinRM Remote Access

## Detection

| Field | Details |
|---|---|
| Detection Time | 2026-11-19 12:45:01 |
| Alert | Suspicious Remote Access |
| Severity | Medium |
| Status | Escalated |
| Source IP | 192.168.1.103 |
| Target Host | DESKTOP-1BDISO6 |

## Alert Evidence

Windows Security Event ID 4624 recorded a successful network logon:

| Time | Account | Source IP | Logon Type | Authentication | Logon ID |
|---|---|---|---|---|---|
| 12:43:13.173 | SOC_Lab | 192.168.1.103 | 3 | NTLM | 0x6a26c4a |

## Investigation

- The authentication originated from `192.168.1.103`, an external host relative to the simulated corporate environment (Kali Linux).
- Event ID 4624 with Logon Type 3 confirmed a successful network authentication using the `SOC_Lab` account.
- At 12:43:25.708, the account executed `whoami.exe`, followed by `whoami /groups` and `whoami /all`. These commands are consistent with account and privilege reconnaissance.
- Process analysis identified `wsmprovhost.exe`, the legitimate Windows Remote Management host process, running under `DESKTOP-1BDISO6\SOC_Lab`. This supports the identification of a remote WinRM session.

### Process Evidence

| Time | Process | PID | Parent Process | Parent PID | User |
|---|---|---:|---|---:|---|
| 12:43:13.224 | wsmprovhost.exe | 15612 | svchost.exe | 988 | DESKTOP-1BDISO6\SOC_Lab |

## Conclusion

The investigation confirmed a successful remote authentication followed by WinRM-based command execution and account reconnaissance.

**Activity Timeline:**

`12:43:13.173` — Successful network logon (4624) → `12:43:13.224` — WinRM host process started → `12:43:25.708` — Account reconnaissance began.

| Verdict | Severity | Action |
|---|---|---|
| True Positive | Medium | Escalate to L2 |

**L2 Recommendation:** Verify whether the remote access was authorized, assess the account's privileges, and determine whether additional suspicious activity occurred.

**Scope:** The activity was intentionally simulated in the lab. No privilege escalation or further compromise was demonstrated.
