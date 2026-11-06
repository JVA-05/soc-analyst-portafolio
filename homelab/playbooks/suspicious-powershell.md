SOC Playbook — Suspicious PowerShell Execution
Tier 1 Investigation Procedure
Objective: Establish whether the detected PowerShell activity is legitimate or potentially malicious.

Investigation checklist:
- [ ] Identify the affected host.
- [ ] Identify the user associated with the process.
- [ ] Review the process command line.
- [ ] Identify the parent process.
- [ ] Review related process executions.
- [ ] Check associated network connections.
- [ ] Look for related file creation.
- [ ] Determine what is confirmed and what remains unknown.
- [ ] Decide whether to close or escalate the case.
Escalation criteria:
- Suspicious parent-child process relationship.
- Unexplained encoded PowerShell command.
- Suspicious external network connection.
- Evidence of persistence or privilege escalation.
- Insufficient evidence to rule out a security incident.
