# Patch Tuesday, November 2026: Sigma rules

Companion to the PenTestIT November 2026 Patch Tuesday post - https://pentestit.com/microsoft-patch-tuesday-november-2026-exploitability-and-patching-priority/ Status: experimental. The Sysmon telemetry these rules expect is in [mayur-esh/sysmon](https://github.com/mayur-esh/sysmon/blob/main/PatchTuesday-2026-11.xml).

## New rules

| File | Level | Logsource | CVE |
|---|---|---|---|
| [net_connection_win_smb_outbound_to_public_ip.yml](net_connection_win_smb_outbound_to_public_ip.yml) | high | network_connection | CVE-2026-124194 (Outlook NTLMv2 leak, Exploitation Detected) |
| [proc_creation_win_windows_search_unexpected_child.yml](proc_creation_win_windows_search_unexpected_child.yml) | high | process_creation | CVE-2026-116928 (Windows Search RCE via Exchange indexing) |
| [proc_creation_win_werfault_search_or_iis_crash.yml](proc_creation_win_werfault_search_or_iis_crash.yml) | medium | process_creation | CVE-2026-116928, CVE-2026-119961 |

## Related rules (linked, not copied)

| Rule | ID | Note |
|---|---|---|
| [Suspicious WebDav Client Execution Via Rundll32.EXE](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_rundll32_webdav_client_susp_execution.yml) | 982e9f2d | CVE-2026-124194 WebDAV fallback; matches IPv4 URLs only, not host names |
| [Suspicious Outlook Child Process](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_office_outlook_susp_child_processes.yml) | 208748f7 | Outlook and Office RCEs |
| [Potential CVE-2023-21554 QueueJumper Exploitation](https://github.com/SigmaHQ/sigma/blob/master/rules-emerging-threats/2022/Exploits/CVE-2022-21554/proc_creation_win_exploit_cve_2023_21554_queuejumper.yml) | 53207cc2 | Message Queuing child processes (five MSMQ RCEs this month) |
| [Unusual Parent Process For Cmd.EXE](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_cmd_unusual_parent.yml) | 4b991083 | includes SearchIndexer and SearchProtocolHost as parents |
| [Potentially Suspicious Child Process Of VsCode](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_vscode_child_processes_anomalies.yml) | 5a3164f2 | CVE-2026-121662 and CVE-2026-121663 |
| [LSASS Process Crashed - Application](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/application/application_error/win_application_error_lsass_crash.yml) | a18e0862 | matches exception c0000001 only |
| [Critical service crash (October)](../PatchTuesday-2026-10/win_application_error_critical_service_crash.yml) | this repository | LSASS, MSMQ, Spooler crashes; LDAP CVE-2026-119958, AD DS CVE-2026-118146, Schannel CVE-2026-119952 |
| [WerFault for a critical service (October)](../PatchTuesday-2026-10/proc_creation_win_werfault_critical_service_crash.yml) | this repository | same services, Sysmon process view |

## Tests

`tests/events.yml` holds 19 synthetic events (positive and negative). Validated with `tools/validate_detections.py`: pySigma validators, Splunk and Kusto conversion, and every rule executed against the events in SQLite. Result: PASS.

## Not proven

- Sysmon loading the overlay (`sysmon64 -c` on Windows) and the SIEM field mappings.
- Real exploit traffic. No public exploit was used.
- The SMB rule assumes Sysmon logs kernel SMB client connections as `Image: System`. Microsoft Defender for Endpoint records them differently, so the Kusto output needs a field check before use; its IPv6 ranges also convert to `ipv4_is_in_range`, which does not match IPv6.
- CVE-2026-116928: Microsoft does not name the Exchange process that hosts the Search component. The rule covers the three Windows Search binaries; baseline each Exchange server before alerting.
