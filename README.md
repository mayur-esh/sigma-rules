# sigma-rules

Sigma detection rules I write for new vulnerabilities, public PoCs and Patch Tuesday releases. Most target Windows endpoint telemetry (Sysmon and built-in event logs). A smaller set covers Linux, web server and proxy logs.

Every rule is `status: experimental`. Treat them as hunting leads until you have baselined them in your environment.

## Layout

| Folder | What it covers | Rule files |
|---|---|---|
| [BigDiskBuster](#bigdiskbuster) | Disk-space exhaustion used to starve Microsoft Defender of updates | 7 |
| [GreenSection](#greensection) | GreenSection PoC: out-of-bounds write in the NVIDIA user-mode driver (`nvoglv64.dll`) | 2 |
| [HardBreacher](#hardbreacher) | HardBreacher PoC: Kaspersky privileged file operation abused to plant a DLL in System32 | 4 |
| [PrettyPrague](#prettyprague) | PrettyPrague PoC: offline SAM parsing, local admin password reset, SYSTEM shell via a transient service | 6 |
| [generic](#generic) | Standalone rules: web server and runtime RCE post-exploitation, OpenSSH "sshole", Electron abuse, LSA/WDigest tampering, ARTEX user-agents | 14 |
| [PatchTuesday-2026-10](PatchTuesday-2026-10/README.md) | Microsoft Patch Tuesday, October 2026 | 7 |
| [PatchTuesday-2026-11](PatchTuesday-2026-11/README.md) | Microsoft Patch Tuesday, November 2026 | 3 |

The two Patch Tuesday folders have their own README with related SigmaHQ rules and caveats.

## Telemetry

Most Windows rules need Sysmon. Matching configs live in [mayur-esh/sysmon](https://github.com/mayur-esh/sysmon):

| Rules | Sysmon config |
|---|---|
| BigDiskBuster | [BigDiskBuster.xml](https://github.com/mayur-esh/sysmon/blob/main/BigDiskBuster.xml) |
| GreenSection, HardBreacher, PrettyPrague | [nightmare-eclipse-HardBreacher-GreenSection-PrettyPrague.xml](https://github.com/mayur-esh/sysmon/blob/main/nightmare-eclipse-HardBreacher-GreenSection-PrettyPrague.xml) |
| PatchTuesday-2026-10 | [PatchTuesday-2026-10.xml](https://github.com/mayur-esh/sysmon/blob/main/PatchTuesday-2026-10.xml) |
| PatchTuesday-2026-11 | [PatchTuesday-2026-11.xml](https://github.com/mayur-esh/sysmon/blob/main/PatchTuesday-2026-11.xml) |

Other sources used:

- Windows built-in logs: System (Srv 2013, Service Control Manager 7045), Application (Application Error 1000), Microsoft Defender (`windefend`), Security 4887 on an ADCS CA.
- Linux: process creation (auditd or an EDR) and `auth` logs from sshd and doas.
- Web server and proxy logs for the ARTEX user-agent rules.

The ADCS rule only works if the CA has `AuditFilter` bit `0x04` set and "Certification Services" success auditing turned on.

## Using the rules

Install [sigma-cli](https://github.com/SigmaHQ/sigma-cli), then validate and convert:

```bash
pip install sigma-cli
sigma plugin install splunk sysmon

sigma check .
sigma convert -t splunk -p sysmon PatchTuesday-2026-11/
```

Swap `splunk` for your backend. Field names for the faulting module, file paths and network fields vary between pipelines, so check the converted query against your data before you deploy it.

### Correlation rules

Four files use Sigma correlations. Convert each one in the same run as the rules it references, or the reference won't resolve:

| Correlation | Type | Window | References |
|---|---|---|---|
| BigDiskBuster: Burst of GUID-named temp file creations | event_count, by `Computer` | 5m | GUID-named file created in temp directory |
| BigDiskBuster: File activity plus Defender update failure | temporal, by `Computer` | 15m | GUID-named file created in temp directory; Microsoft Defender Update Failure |
| generic: Failed then Accepted pair | event_count, by `src_ip`, `user` | 2m | base rule in the same file |
| PatchTuesday-2026-10: ADCS certificate issuance burst | event_count, by `Requester` | 10m | base rule in the same file |

The two BigDiskBuster correlations reference rules in other files, so convert the whole `BigDiskBuster/` folder at once.

## Rule index

The CVE column shows only the `cve.*` tags in each rule. Some rules mention CVEs in their description without tagging them.

### BigDiskBuster

| Rule | Level | Log source | CVE |
|---|---|---|---|
| [Burst Of GUID-Named Temp File Creations](BigDiskBuster/Burst%20of%20GUID-named%20temp%20file%20creations.yaml) | high | correlation (event_count) | - |
| [Defender Update Failure Following GUID-Named Temp File Activity](BigDiskBuster/Correlation%2C%20file%20activity%20plus%20Defender%20update%20failure.yaml) | high | correlation (temporal) | - |
| [Microsoft Defender Update Failure Due To Insufficient Disk Space](BigDiskBuster/Defender%20update%20failure%20with%20disk-full%20status.yaml) | high | windows windefend | - |
| [GUID-Named Extensionless File Created In Temp Directory](BigDiskBuster/Hidden%20GUID-named%20file%20created%20in%20a%20temp%20directory.yaml) | medium | windows file_event | - |
| [GUID-Named Temp File Deleted Shortly After Creation](BigDiskBuster/Same%20file%20created%20and%20deleted%20in%20quick%20succession.yaml) | medium | windows file_delete | - |
| [Low Disk Space Warning From Server Service](BigDiskBuster/Low%20disk%20space%20warning.yaml) | low | windows system | - |
| [Microsoft Defender Update Failure](BigDiskBuster/Microsoft%20Defender%20Update%20Failure.yaml) | low | windows windefend | - |

The low-level Defender rule is a hunting feed; benign update failures are common. Srv event 2013 is reported as unreliable on client SKUs.

### GreenSection

Source PoC: [MSNightmare/GreenSection](https://github.com/MSNightmare/GreenSection)

| Rule | Level | Log source | CVE |
|---|---|---|---|
| [GreenSection - Cross-Process Access into Desktop Compositor (dwm.exe)](GreenSection/GreenSection-dwm.yml) | medium | windows process_access | - |
| [GreenSection - NVIDIA User-Mode Driver Crash (nvoglv64)](GreenSection/GreenSection-nvlogv64.yml) | low | windows application | - |

### HardBreacher

Source PoC: [MSNightmare/HardBreacher](https://github.com/MSNightmare/HardBreacher)

| Rule | Level | Log source | CVE |
|---|---|---|---|
| [HardBreacher - MY_SNAKE_IS_SOLID.dll IOC (File or Load)](HardBreacher/HardBreacher-ioc-dll.yml) | critical | windows file_event | - |
| [HardBreacher - DLL Written into System32 by Non-Servicing Process](HardBreacher/HardBreacher-dll-create.yml) | high | windows file_event | - |
| [HardBreacher - Unsigned DLL Loaded from System32](HardBreacher/HardBreacher-unsigned-dll-load.yml) | high | windows image_load | - |
| [HardBreacher - Handle Access / Injection into Kaspersky UI Process](HardBreacher/HardBreacher-avp.yml) | medium | windows process_access | - |

The IOC rule matches the PoC's hard-coded DLL name. The other three cover the technique.

### PrettyPrague

Source PoC: [MSNightmare/PrettyPrague](https://github.com/MSNightmare/PrettyPrague)

| Rule | Level | Log source | CVE |
|---|---|---|---|
| [PrettyPrague - Command Line IOC String](PrettyPrague/PrettyPrague-cli.yml) | critical | windows process_creation | - |
| [PrettyPrague - Offline Registry API Loaded for SAM Hive Parsing](PrettyPrague/PrettyPrague-offreg.yml) | high | windows image_load | - |
| [PrettyPrague - samlib.dll Loaded by Unusual Process (SAM Password Manipulation)](PrettyPrague/PrettyPrague-samlib.yml) | high | windows image_load | - |
| [PrettyPrague - SYSTEM Shell via Transient Service (services.exe spawns conhost.exe)](PrettyPrague/PrettyPrague-services.yml) | high | windows process_creation | - |
| [PrettyPrague - Transient GUID-Named Service Installed](PrettyPrague/PrettyPrague-service-name.yml) | medium | windows system | - |
| [SAM / Credential Theft - Raw Disk Volume Read](PrettyPrague/PrettyPrague-sam.yml) | medium | windows raw_access_read | - |

### generic

| Rule | Level | Log source | CVE |
|---|---|---|---|
| [OpenSSH Password Login to Account With No Password (sshole CVE-2026-123158)](generic/password%20login%20to%20an%20account%20with%20no%20password.yml) | critical | linux auth | CVE-2026-123158 |
| [doas Root Execution By Alpine Cloud Image User](generic/doas%20by%20the%20cloud-image%20user.yml) | high | linux auth | - |
| [sshd Failed Then Accepted Password Pair Within Two Minutes (sshole Pattern)](generic/Failed%20then%20Accepted%20pair%20%28correlation%29.yml) | medium | linux auth + correlation (event_count) | - |
| [Apache HTTP Server Worker Spawning a Shell or Download Tool](generic/CVE-2026-119618.yml) | high | linux process_creation | CVE-2026-119618 |
| [Shell or Downloader Started by an nginx Worker](generic/CVE-2026-123007.yml) | high | linux process_creation | CVE-2026-123007 |
| [Shell or Network Tool Spawned by PHP Worker](generic/shell-spawned-by-php-worker.yml) | high | linux process_creation | - |
| [Node.js Server Process Spawning Shell, Downloader or Recon Tool](generic/NodeJS-launching-shell.yml) | medium | process_creation | CVE-2026-111497 |
| [Electron app.asar Written by a Non-Updater Process](generic/app.asar-written.yml) | high | windows file_event | - |
| [Electron Application Started With Inspector or Remote Debugging Enabled](generic/electron-app-inspector.yml) | high | windows process_creation | - |
| [Electron Application Launched With a Script Argument](generic/electron-app-with-script.yml) | medium | windows process_creation | - |
| [Defense Tamper - LSA Protection (RunAsPPL) Disabled](generic/Generic-RunAsPPL.yml) | high | windows registry_set | - |
| [Defense Tamper - WDigest Cleartext Credentials Re-Enabled](generic/Generic-WDigest.yml) | high | windows registry_set | - |
| [ARTEX Family Enrichment User-Agent in Proxy Logs](generic/proxy_artex_enrich_useragent.yml) | high | proxy | - |
| [ARTEX Family Enrichment User-Agent in Web Server Logs](generic/web_artex_enrich_useragent.yml) | medium | webserver | - |

Notes:

- The sshole rule needs a per-host list of accounts whose `/etc/shadow` password field is `*`. The rule file shows how to build it.
- The web server and runtime rules (Apache, nginx, PHP, Node.js) catch post-exploitation process activity, not the exploit itself. Expect hits on servers that run CGI, piped loggers or legitimate child processes.
- The PHP rule's description names CVE-2026-109618 and CVE-2026-109619.

### PatchTuesday-2026-10

Companion to the [PenTestIT October 2026 Patch Tuesday post](https://pentestit.com/microsoft-patch-tuesday-october-2026-exploitability-and-patching-priority/). Details and related SigmaHQ rules: [PatchTuesday-2026-10/README.md](PatchTuesday-2026-10/README.md).

| Rule | Level | Log source | CVE |
|---|---|---|---|
| [Hyper-V Worker Process Spawns A Child Process](PatchTuesday-2026-10/proc_creation_win_vmwp_child_process.yml) | high | windows process_creation | CVE-2026-105733 |
| [Script File Written To Exchange Web Directory](PatchTuesday-2026-10/file_event_win_exchange_webdir_script_write.yml) | high | windows file_event | CVE-2026-70571 |
| [Script Host Launched By Explorer From Download Or Attachment Path](PatchTuesday-2026-10/proc_creation_win_motw_bypass_scripthost_from_download_path.yml) | medium | windows process_creation | CVE-2026-96951 |
| [Application Crash Of A Service Patched In October 2026](PatchTuesday-2026-10/win_application_error_critical_service_crash.yml) | medium | windows application | - |
| [ADCS Certificate Issuance Burst From A Single Requester (Correlation)](PatchTuesday-2026-10/win_security_adcs_ndes_certificate_issuance_burst.yml) | medium | windows security + correlation (event_count) | CVE-2026-69802 |
| [Unsigned DLL From User-Writable Path Loaded By Windows Binary](PatchTuesday-2026-10/image_load_win_unsigned_userpath_dll_by_system_binary.yml) | low | windows image_load | CVE-2026-108398 |
| [WerFault Spawned By A Network-Facing Or Credential Service](PatchTuesday-2026-10/proc_creation_win_werfault_critical_service_crash.yml) | low | windows process_creation | - |

### PatchTuesday-2026-11

Companion to the [PenTestIT November 2026 Patch Tuesday post](https://pentestit.com/microsoft-patch-tuesday-november-2026-exploitability-and-patching-priority/). Details, related SigmaHQ rules and known limits: [PatchTuesday-2026-11/README.md](PatchTuesday-2026-11/README.md).

| Rule | Level | Log source | CVE |
|---|---|---|---|
| [Outbound SMB Connection To A Public IP Address](PatchTuesday-2026-11/net_connection_win_smb_outbound_to_public_ip.yml) | high | windows network_connection | CVE-2026-124194 |
| [Windows Search Process Spawns An Unexpected Child Process](PatchTuesday-2026-11/proc_creation_win_windows_search_unexpected_child.yml) | high | windows process_creation | CVE-2026-116928 |
| [Windows Search Or IIS Worker Crash](PatchTuesday-2026-11/proc_creation_win_werfault_search_or_iis_crash.yml) | medium | windows process_creation | CVE-2026-116928, CVE-2026-119961 |

## Author

Mayuresh Dani

## License

[GPL-3.0](LICENSE)
