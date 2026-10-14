# Patch Tuesday, October 2026: Sigma rules

Companion to the PenTestIT October 2026 Patch Tuesday post - https://pentestit.com/microsoft-patch-tuesday-october-2026-exploitability-and-patching-priority/ Status: experimental. The Sysmon telemetry these rules expect is in [mayur-esh/sysmon](https://github.com/mayur-esh/sysmon/blob/main/PatchTuesday-2026-10.xml). 

## New rules

| File | Level | Logsource |
|---|---|---|
| [proc_creation_win_motw_bypass_scripthost_from_download_path.yml](proc_creation_win_motw_bypass_scripthost_from_download_path.yml) | medium | process_creation |
| [proc_creation_win_werfault_critical_service_crash.yml](proc_creation_win_werfault_critical_service_crash.yml) | low | process_creation |
| [win_application_error_critical_service_crash.yml](win_application_error_critical_service_crash.yml) | medium | Application 1000 |
| [image_load_win_unsigned_userpath_dll_by_system_binary.yml](image_load_win_unsigned_userpath_dll_by_system_binary.yml) | low | image_load |
| [proc_creation_win_vmwp_child_process.yml](proc_creation_win_vmwp_child_process.yml) | high | process_creation (CVE-2026-105733) |
| [win_security_adcs_ndes_certificate_issuance_burst.yml](win_security_adcs_ndes_certificate_issuance_burst.yml) | medium | Security 4887 + event_count correlation |
| [file_event_win_exchange_webdir_script_write.yml](file_event_win_exchange_webdir_script_write.yml) | high | file_event (works with plain Sysmon) |

## Related rules (linked, not copied)

| Rule | ID | Note |
|---|---|---|
| [Suspicious Outlook Child Process](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_office_outlook_susp_child_processes.yml) | 208748f7 | |
| [Suspicious Execution From Outlook Temporary Folder](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_office_outlook_execution_from_temp.yml) | a018fdc3 | |
| [Unusual Child Process of dns.exe](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_dns_susp_child_process.yml) | a4e3d776 | |
| [Suspicious Spool Service Child Process](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_spoolsv_susp_child_processes.yml) | dcdbc940 | |
| [Potential CVE-2023-21554 QueueJumper Exploitation](https://github.com/SigmaHQ/sigma/blob/master/rules-emerging-threats/2022/Exploits/CVE-2022-21554/proc_creation_win_exploit_cve_2023_21554_queuejumper.yml) | 53207cc2 | MSMQ child processes |
| [Suspicious ASPX File Drop by Exchange](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_exchange_webshell_drop.yml) | bd1212e5 | needs CommandLine on file events (EDR); plain Sysmon EID 11 lacks it |
| [LSASS Process Crashed - Application](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/application/application_error/win_application_error_lsass_crash.yml) | a18e0862 | matches exception c0000001 only |
| [HardBreacher - Unsigned DLL Loaded from System32](../HardBreacher/HardBreacher-unsigned-dll-load.yml) | 7d8a3965 | this repo; complements the CVE-2026-108398 rule (System32 instead of user paths) |
| [BITS Transfer Job Download From Direct IP](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/bits_client/win_bits_client_new_transfer_via_ip_address.yml) | 90f138c1 | post-exploitation staging |
