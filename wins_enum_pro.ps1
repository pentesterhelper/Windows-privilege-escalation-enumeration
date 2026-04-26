#Requires -Version 5.1
<#
.SYNOPSIS
    wins-enum-pro -- Professional Windows Local Privilege Escalation Enumerator

.DESCRIPTION
    Comprehensive Windows privilege escalation enumeration tool.
    Checks for common misconfigurations, weak permissions, stored credentials,
    kernel vulnerabilities, registry weaknesses, and more.

.NOTES
    Author  : pentesterhelper
    Website : pentesterhelper.in
    GitHub  : https://github.com/pentesterhelper/wins-enum
    License : MIT

.PARAMETER OutputDir
    Directory to save the report. Defaults to current directory.

.PARAMETER NoColor
    Disable colored console output.

.PARAMETER Quiet
    Suppress OK messages; show only findings and progress.

.EXAMPLE
    .\wins_enum_pro.ps1
    .\wins_enum_pro.ps1 -OutputDir C:\Temp -NoColor
#>

[CmdletBinding()]
param(
    [string]$OutputDir = $PWD.Path,
    [switch]$NoColor,
    [switch]$Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# ------------------------------------------------------------------------------
# GLOBALS
# ------------------------------------------------------------------------------
$Script:Version    = "2.1.0"
$Script:Timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$Script:ReportFile = Join-Path $OutputDir "wins_enum_$Script:Timestamp.txt"
$Script:Findings   = [System.Collections.Generic.List[hashtable]]::new()
$Script:Counts     = @{ CRITICAL=0; HIGH=0; MEDIUM=0; LOW=0; INFO=0 }

# -- Progress state ------------------------------------------------------------
$Script:Steps = @(
    "System Information",
    "Current User & Groups",
    "Privilege Analysis",
    "Security Products",
    "Network Information",
    "Scheduled Tasks",
    "Service Binary Perms",
    "Unquoted Service Paths",
    "Weak Service Perms",
    "Registry Autoruns",
    "Installed Applications",
    "Sensitive Files",
    "PowerShell History",
    "Stored Credentials",
    "DPAPI Artifacts",
    "Active Sessions & Users",
    "Running Processes",
    "PATH Hijacking",
    "Weak Folder Perms",
    "Domain Information",
    "Interesting Files"
)
$Script:TotalSteps  = $Script:Steps.Count
$Script:CurrentStep = 0
$Script:ProgressRow = -1
$Script:BarWidth    = 50

# ------------------------------------------------------------------------------
# CONSOLE HELPERS
# ------------------------------------------------------------------------------
function Write-Color {
    param([string]$Text, [ConsoleColor]$Color = [ConsoleColor]::White, [switch]$NoNewline)
    if ($NoColor) {
        if ($NoNewline) { Write-Host $Text -NoNewline } else { Write-Host $Text }
    } else {
        if ($NoNewline) { Write-Host $Text -ForegroundColor $Color -NoNewline }
        else            { Write-Host $Text -ForegroundColor $Color }
    }
}

function Write-BelowBar {
    param([string]$Text, [ConsoleColor]$Color = [ConsoleColor]::White)
    if ($NoColor) { Write-Host $Text }
    else          { Write-Host $Text -ForegroundColor $Color }
}

function Write-OK {
    param([string]$Msg)
    if (-not $Quiet) { Write-BelowBar "      [OK] $Msg" DarkGreen }
}

# ------------------------------------------------------------------------------
# PROGRESS BAR ENGINE
# ------------------------------------------------------------------------------
function Initialize-ProgressBar {
    Write-Host ""
    $Script:ProgressRow = $Host.UI.RawUI.CursorPosition.Y
    Write-Host (" " * ($Script:BarWidth + 50))
    Write-Host (" " * ($Script:BarWidth + 50))
    Write-Host ""
}

function Update-ProgressBar {
    param([string]$StepName = "")

    if ($Script:ProgressRow -lt 0) { return }

    $pct    = [int](($Script:CurrentStep / $Script:TotalSteps) * 100)
    $filled = [int](($Script:CurrentStep / $Script:TotalSteps) * $Script:BarWidth)
    $empty  = $Script:BarWidth - $filled
    $bar    = ("#" * $filled) + ("-" * $empty)
    $label  = "  {0,3}%  [{1}]  {2}/{3}" -f $pct, $bar, $Script:CurrentStep, $Script:TotalSteps

    $barColor = if    ($pct -lt 33)  { [ConsoleColor]::Cyan }
                elseif($pct -lt 66)  { [ConsoleColor]::Yellow }
                elseif($pct -lt 100) { [ConsoleColor]::DarkYellow }
                else                 { [ConsoleColor]::Green }

    $saved = $Host.UI.RawUI.CursorPosition

    $Host.UI.RawUI.CursorPosition = [System.Management.Automation.Host.Coordinates]::new(0, $Script:ProgressRow)
    if ($NoColor) { Write-Host ($label.PadRight($Script:BarWidth + 20)) -NoNewline }
    else          { Write-Host ($label.PadRight($Script:BarWidth + 20)) -ForegroundColor $barColor -NoNewline }

    $Host.UI.RawUI.CursorPosition = [System.Management.Automation.Host.Coordinates]::new(0, $Script:ProgressRow + 1)
    $statusText = "  Scanning: " + $(if ($StepName.Length -gt 58) { $StepName.Substring(0,55)+"..." } else { $StepName })
    if ($NoColor) { Write-Host ($statusText.PadRight(80)) -NoNewline }
    else          { Write-Host ($statusText.PadRight(80)) -ForegroundColor DarkGray -NoNewline }

    $Host.UI.RawUI.CursorPosition = $saved
}

function Complete-ProgressBar {
    $Script:CurrentStep = $Script:TotalSteps
    if ($Script:ProgressRow -lt 0) { return }

    $bar   = "#" * $Script:BarWidth
    $label = "  100%  [$bar]  $Script:TotalSteps/$Script:TotalSteps  [COMPLETE]"

    $saved = $Host.UI.RawUI.CursorPosition

    $Host.UI.RawUI.CursorPosition = [System.Management.Automation.Host.Coordinates]::new(0, $Script:ProgressRow)
    if ($NoColor) { Write-Host ($label.PadRight($Script:BarWidth + 20)) -NoNewline }
    else          { Write-Host ($label.PadRight($Script:BarWidth + 20)) -ForegroundColor Green -NoNewline }

    $Host.UI.RawUI.CursorPosition = [System.Management.Automation.Host.Coordinates]::new(0, $Script:ProgressRow + 1)
    $done = "  All $Script:TotalSteps checks completed -- $(Get-Date -Format 'HH:mm:ss')"
    if ($NoColor) { Write-Host ($done.PadRight(80)) -NoNewline }
    else          { Write-Host ($done.PadRight(80)) -ForegroundColor Green -NoNewline }

    $Host.UI.RawUI.CursorPosition = $saved
}

function Step-Progress {
    param([string]$Name = "")
    $Script:CurrentStep++
    Update-ProgressBar -StepName $Name
}

# ------------------------------------------------------------------------------
# BANNER
# ------------------------------------------------------------------------------
function Write-Banner {
    $banner = @"

  WINS-ENUM-PRO v$Script:Version
  Windows Privilege Escalation Enumerator
  ========================================
"@
    Write-Color $banner Cyan
    Write-Color "  by pentesterhelper  |  pentesterhelper.in  |  github.com/pentesterhelper/wins-enum" DarkCyan
    Write-Color ("  " + "-"*78) DarkGray
    Write-Color "  Report : $Script:ReportFile" DarkGray
    Write-Color "  Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" DarkGray
    Write-Color ("  " + "-"*78) DarkGray
}

function Write-SectionHeader {
    param([string]$Title, [string]$Icon = ">")
    $pad  = [Math]::Max(0, 76 - $Title.Length - 3)
    $line = "-" * $pad
    Write-BelowBar ""
    Write-BelowBar "  $Icon  $Title  $line" Yellow
}

function Write-FindingConsole {
    param([string]$Severity, [string]$Title, [string]$Detail = "")
    $colors = @{ CRITICAL='Red'; HIGH='DarkRed'; MEDIUM='Yellow'; LOW='Cyan'; INFO='Gray' }
    $icons  = @{ CRITICAL='[!!!]'; HIGH='[!!] '; MEDIUM='[!]  '; LOW='[i]  '; INFO='[~]  ' }
    $col    = [ConsoleColor]($colors[$Severity])
    Write-BelowBar "      $($icons[$Severity]) $Title" $col
    if ($Detail) { Write-BelowBar "             $Detail" DarkGray }
}

# ------------------------------------------------------------------------------
# REPORT FILE HELPERS
# ------------------------------------------------------------------------------
function Out-Report {
    param([string]$Line = "")
    Add-Content -Path $Script:ReportFile -Value $Line -Encoding UTF8
}

function Out-Section {
    param([string]$Title)
    Out-Report ""
    Out-Report ("=" * 80)
    Out-Report "  $Title"
    Out-Report ("=" * 80)
    Out-Report ""
}

function Out-Finding {
    param(
        [string]$Severity,
        [string]$Title,
        [string]$Detail    = "",
        [string]$Reference = ""
    )
    $Script:Counts[$Severity]++
    Out-Report "  [$Severity] $Title"
    if ($Detail)    { Out-Report "  Detail   : $Detail" }
    if ($Reference) { Out-Report "  Reference: $Reference" }
    Out-Report ""
    $Script:Findings.Add(@{ Severity=$Severity; Title=$Title; Detail=$Detail; Ref=$Reference })
    Write-FindingConsole $Severity $Title $Detail
}

function Out-Raw {
    param([string[]]$Lines)
    if ($Lines) { $Lines | ForEach-Object { Out-Report "    $_" } }
    Out-Report ""
}

# ------------------------------------------------------------------------------
# UTILITY
# ------------------------------------------------------------------------------
function Get-ExecutablePath {
    param([string]$RawPath)
    if ($RawPath -match '^"([^"]+)"') { return $Matches[1] }
    return ($RawPath.Trim() -split '\s+')[0]
}

function Get-AclDetail {
    param([string]$Path)
    try { return (icacls $Path 2>$null) } catch { return @() }
}

function Test-AclVulnerable {
    param([string[]]$Acl)
    $pattern = '(Everyone|BUILTIN\\Users|Authenticated Users):.*(F\)|M\)|W\))'
    return ($Acl | Where-Object { $_ -match $pattern })
}

function Resolve-ServiceBinary {
    param([string]$Svc)
    try {
        $qc       = sc.exe qc $Svc 2>$null
        $binLine  = $qc | Select-String 'BINARY_PATH_NAME'
        $userLine = $qc | Select-String 'SERVICE_START_NAME'
        $bin  = if ($binLine)  { ($binLine.ToString()  -split ':',2)[1].Trim() } else { $null }
        $user = if ($userLine) { ($userLine.ToString() -split ':',2)[1].Trim() } else { 'Unknown' }
        return @{ Bin=$bin; User=$user }
    } catch { return $null }
}

# ------------------------------------------------------------------------------
# LOCATE ACCESSCHK
# ------------------------------------------------------------------------------
$Script:Accesschk = @(
    (Join-Path $PSScriptRoot "accesschk64.exe"),
    "C:\tools\AccessChk\accesschk64.exe",
    ".\accesschk64.exe",
    "accesschk64.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1


# ==============================================================================
#  BEGIN
# ==============================================================================
Write-Banner
Initialize-ProgressBar

Out-Report "wins-enum-pro v$Script:Version  --  Windows Privilege Escalation Enumerator"
Out-Report "by pentesterhelper  |  pentesterhelper.in"
Out-Report "Report generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Out-Report ("=" * 80)


# ------------------------------------------------------------------------------
# 1. SYSTEM INFORMATION
# ------------------------------------------------------------------------------
Step-Progress "System Information"
Write-SectionHeader "System Information" ">"
Out-Section "System Information"

try {
    $os  = Get-CimInstance Win32_OperatingSystem
    $cs  = Get-CimInstance Win32_ComputerSystem
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    $ips = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -notlike "127.*" } |
            Select-Object -ExpandProperty IPAddress) -join ", "

    $info = [ordered]@{
        "Computer Name"  = $env:COMPUTERNAME
        "User"           = "$env:USERDOMAIN\$env:USERNAME"
        "Session Type"   = if ([bool](Get-Process -Name 'explorer' -ErrorAction SilentlyContinue)) {"Interactive"} else {"Non-Interactive"}
        "OS"             = $os.Caption
        "Build"          = $os.BuildNumber
        "Version"        = $os.Version
        "Architecture"   = $os.OSArchitecture
        "Install Date"   = $os.InstallDate
        "Last Boot"      = $os.LastBootUpTime
        "Manufacturer"   = $cs.Manufacturer
        "Model"          = $cs.Model
        "CPU"            = $cpu.Name
        "RAM (GB)"       = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
        "IPv4 Addresses" = $ips
    }
    $info.GetEnumerator() | ForEach-Object {
        $k = $_.Key.PadRight(16)
        Out-Report "  $k : $($_.Value)"
        if (-not $Quiet) { Write-BelowBar "    $k : $($_.Value)" Gray }
    }
} catch { Out-Report "  [ERROR] Could not retrieve system info: $_" }


# ------------------------------------------------------------------------------
# 2. CURRENT USER & GROUPS
# ------------------------------------------------------------------------------
Step-Progress "Current User & Groups"
Write-SectionHeader "Current User & Groups" ">"
Out-Section "Current User & Groups"

try {
    $whoamiOut = whoami /all 2>$null
    Out-Raw $whoamiOut

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
                [Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
        Out-Finding "CRITICAL" "Running as Administrator" "Current process has full administrative rights"
    } else { Write-OK "Not running as Administrator" }

    if ((net localgroup Administrators 2>$null) -match $env:USERNAME) {
        Out-Finding "HIGH" "Current user is member of local Administrators group"
    }
} catch {}


# ------------------------------------------------------------------------------
# 3. PRIVILEGE ANALYSIS
# ------------------------------------------------------------------------------
Step-Progress "Privilege Analysis"
Write-SectionHeader "Privilege Analysis" ">"
Out-Section "Privilege Analysis"

try {
    $privOutput = whoami /priv 2>$null
    Out-Raw $privOutput

    $dangerousPrivs = [ordered]@{
        "SeImpersonatePrivilege"        = @{ Sev="HIGH";     Ref="https://pentesterhelper.in/notes/share.html?id=9106380598"; Desc="Token impersonation -- Potato exploits (PrintSpoofer, GodPotato, RoguePotato)" }
        "SeAssignPrimaryTokenPrivilege" = @{ Sev="HIGH";     Ref="https://pentesterhelper.in/notes/share.html?id=9106380598"; Desc="Can assign a primary token to a process" }
        "SeDebugPrivilege"              = @{ Sev="CRITICAL"; Ref=""; Desc="Debug/inject into any process including LSASS -- full credential dump" }
        "SeBackupPrivilege"             = @{ Sev="HIGH";     Ref=""; Desc="Read any file ignoring ACLs -- SAM/SYSTEM/NTDS exfil" }
        "SeRestorePrivilege"            = @{ Sev="HIGH";     Ref=""; Desc="Write any file ignoring ACLs -- DLL planting / binary replacement" }
        "SeTakeOwnershipPrivilege"      = @{ Sev="HIGH";     Ref=""; Desc="Take ownership of any object" }
        "SeLoadDriverPrivilege"         = @{ Sev="HIGH";     Ref=""; Desc="Load kernel drivers -- kernel-mode code execution" }
        "SeCreateSymbolicLinkPrivilege" = @{ Sev="MEDIUM";   Ref=""; Desc="Create symbolic links -- possible file redirection attacks" }
        "SeTcbPrivilege"                = @{ Sev="CRITICAL"; Ref=""; Desc="Act as OS -- create tokens for any user" }
        "SeCreateTokenPrivilege"        = @{ Sev="CRITICAL"; Ref=""; Desc="Create arbitrary access tokens" }
        "SeManageVolumePrivilege"       = @{ Sev="MEDIUM";   Ref=""; Desc="Manage volume operations" }
        "SeShutdownPrivilege"           = @{ Sev="LOW";      Ref=""; Desc="Can shut down the system" }
    }

    $found = $false
    foreach ($priv in $dangerousPrivs.Keys) {
        if ($privOutput -match $priv) {
            $p = $dangerousPrivs[$priv]
            Out-Finding $p.Sev "Dangerous privilege: $priv" $p.Desc $p.Ref
            $found = $true
        }
    }
    if (-not $found) { Write-OK "No high-risk privileges detected" }
} catch {}


# ------------------------------------------------------------------------------
# 4. SECURITY PRODUCTS
# ------------------------------------------------------------------------------
Step-Progress "Security Products"
Write-SectionHeader "Security Products" ">"
Out-Section "Security Products"

try {
    $av = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop
    $av | ForEach-Object {
        $state = switch ($_.productState.ToString().Substring(1,2)) {
            "01" { "Disabled" } "10" { "Enabled" } "11" { "Enabled (out of date)" } default { "Unknown" }
        }
        Out-Report "  AV: $($_.displayName)  [$state]"
        if (-not $Quiet) { Write-BelowBar "    AV: $($_.displayName)  [$state]" Gray }
    }
} catch {}

try {
    $wdPref   = Get-MpPreference -ErrorAction Stop
    $wdStatus = Get-MpComputerStatus -ErrorAction Stop
    if ($wdStatus.AntivirusEnabled -eq $false) {
        Out-Finding "HIGH" "Windows Defender is DISABLED"
    } elseif ($wdPref.DisableRealtimeMonitoring) {
        Out-Finding "HIGH" "Windows Defender Real-Time Protection is DISABLED"
    } else { Write-OK "Windows Defender real-time protection is active" }
    if ($wdPref.ExclusionPath) {
        Out-Finding "MEDIUM" "Windows Defender exclusion paths configured" ($wdPref.ExclusionPath -join '; ')
    }
} catch {}

try {
    Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object {
        if ($_.Enabled -eq $false) { Out-Finding "MEDIUM" "Firewall DISABLED on profile: $($_.Name)" }
    }
} catch {}


# ------------------------------------------------------------------------------
# 5. NETWORK INFORMATION
# ------------------------------------------------------------------------------
Step-Progress "Network Information"
Write-SectionHeader "Network Information" ">"
Out-Section "Network Information"

try {
    Out-Report "  --- Interfaces ---"
    Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -ne '127.0.0.1' } |
        ForEach-Object { Out-Report "  $($_.InterfaceAlias.PadRight(30)) $($_.IPAddress)/$($_.PrefixLength)" }

    Out-Report ""; Out-Report "  --- DNS Servers ---"
    Get-DnsClientServerAddress -ErrorAction SilentlyContinue |
        Where-Object { $_.ServerAddresses } |
        ForEach-Object { Out-Report "  $($_.InterfaceAlias.PadRight(30)) $($_.ServerAddresses -join ', ')" }

    Out-Report ""; Out-Report "  --- Listening Ports ---"
    Out-Raw (netstat -ano 2>$null | Select-String "LISTENING")

    Out-Report "  --- ARP Cache ---"
    Out-Raw (arp -a 2>$null)

    $hostsContent = Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue |
                    Where-Object { $_ -notmatch '^\s*#' -and $_.Trim() }
    if ($hostsContent) {
        Out-Report "  --- Custom Hosts Entries ---"
        Out-Raw $hostsContent
        Out-Finding "LOW" "Custom entries in hosts file" ($hostsContent -join ' | ')
    }
} catch {}


# ------------------------------------------------------------------------------
# 6. SCHEDULED TASKS -- WRITABLE TARGETS
# ------------------------------------------------------------------------------
Step-Progress "Scheduled Tasks -- Writable Targets"
Write-SectionHeader "Scheduled Tasks -- Writable Targets" ">"
Out-Section "Scheduled Tasks -- Writable Targets"

try {
    $tasks     = schtasks /query /fo csv /v 2>$null | ConvertFrom-Csv
    $vulnFound = $false
    foreach ($task in $tasks) {
        $cmd = $task.'Task To Run'
        if (-not $cmd -or $cmd -in 'COM handler','') { continue }
        $file = Get-ExecutablePath $cmd
        if (-not (Test-Path $file)) { continue }
        $acl  = Get-AclDetail $file
        if (Test-AclVulnerable $acl) {
            Out-Finding "HIGH" "Writable scheduled task binary: $($task.TaskName)" `
                "Runs as: $($task.'Run As User')  |  Binary: $file" `
                "https://pentesterhelper.in/notes/share.html?id=5999949182"
            Out-Raw $acl
            $vulnFound = $true
        }
    }
    if (-not $vulnFound) { Write-OK "No writable scheduled task binaries found" }
} catch {}


# ------------------------------------------------------------------------------
# 7. SERVICES -- INSECURE BINARY PERMISSIONS
# ------------------------------------------------------------------------------
Step-Progress "Service Binary Permissions"
Write-SectionHeader "Services -- Insecure Binary Permissions" ">"
Out-Section "Services -- Insecure Binary Permissions"

try {
    $vulnFound = $false
    foreach ($svc in (Get-Service | Select-Object -ExpandProperty Name)) {
        $info = Resolve-ServiceBinary $svc
        if (-not $info -or -not $info.Bin) { continue }
        $file = Get-ExecutablePath $info.Bin
        if (-not (Test-Path $file)) { continue }
        $acl  = Get-AclDetail $file
        if (Test-AclVulnerable $acl) {
            Out-Finding "HIGH" "Writable service binary: $svc" `
                "Runs as: $($info.User)  |  Binary: $file" `
                "https://pentesterhelper.in/notes/share.html?id=8956244530"
            Out-Raw $acl
            $vulnFound = $true
        }
    }
    if (-not $vulnFound) { Write-OK "No writable service binaries found" }
} catch {}


# ------------------------------------------------------------------------------
# 8. SERVICES -- UNQUOTED PATHS
# ------------------------------------------------------------------------------
Step-Progress "Unquoted Service Paths"
Write-SectionHeader "Services -- Unquoted Paths" ">"
Out-Section "Services -- Unquoted Service Paths"

try {
    $uq = Get-CimInstance Win32_Service | Where-Object {
        $_.PathName -and
        $_.PathName -notlike '"*' -and
        $_.PathName -like '* *' -and
        $_.PathName -notlike 'C:\Windows\*'
    }
    if ($uq) {
        foreach ($s in $uq) {
            Out-Finding "MEDIUM" "Unquoted service path: $($s.Name)" `
                "Path: $($s.PathName)  |  Runs as: $($s.StartName)" `
                "https://pentesterhelper.in/notes/share.html?id=3706347449"
        }
    } else { Write-OK "No unquoted service paths found" }
} catch {}


# ------------------------------------------------------------------------------
# 9. SERVICES -- WEAK SERVICE PERMISSIONS (accesschk)
# ------------------------------------------------------------------------------
Step-Progress "Weak Service Permissions"
Write-SectionHeader "Services -- Weak Permissions (accesschk)" ">"
Out-Section "Services -- Weak Service Permissions"

if ($Script:Accesschk) {
    Out-Report "  accesschk path: $Script:Accesschk"
    try {
        $res       = & $Script:Accesschk -accepteula -uwcqv Users * 2>$null
        $vulnFound = $false
        foreach ($line in $res) {
            if ($line -match "RW\s+(.+)") {
                $svcName = $Matches[1].Trim()
                Out-Finding "HIGH" "Users have RW access on service: $svcName" "" `
                    "https://pentesterhelper.in/notes/share.html?id=5200723355"
                Out-Raw (& $Script:Accesschk -accepteula -qlc $svcName 2>$null)
                $vulnFound = $true
            }
        }
        if (-not $vulnFound) { Write-OK "No weak service permissions via accesschk" }
    } catch {}
} else {
    Out-Report "  [INFO] accesschk64.exe not found -- place alongside script for enhanced ACL checks."
    if (-not $Quiet) { Write-BelowBar "      [~] accesschk64.exe not found -- skipping weak service ACL check" Gray }
}


# ------------------------------------------------------------------------------
# 10. REGISTRY -- AUTORUNS & WEAK PERMISSIONS
# ------------------------------------------------------------------------------
Step-Progress "Registry Autoruns"
Write-SectionHeader "Registry -- Autoruns & Weak Permissions" ">"
Out-Section "Registry -- Autoruns & Weak Permissions"

$autorunKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
)

foreach ($key in $autorunKeys) {
    try {
        $vals = Get-ItemProperty -Path $key -ErrorAction Stop
        $vals.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
            $bin = Get-ExecutablePath $_.Value
            Out-Report "  Key: $key  Name: $($_.Name)  Value: $($_.Value)"
            if (Test-Path $bin) {
                if (Test-AclVulnerable (Get-AclDetail $bin)) {
                    Out-Finding "HIGH" "Writable autorun binary: $($_.Name)" $bin
                }
            } else {
                Out-Finding "LOW" "Autorun references missing binary: $($_.Name)" $bin
            }
        }
    } catch {}
}

try {
    $aieHKLM = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction Stop).AlwaysInstallElevated
    $aieHKCU = (Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction Stop).AlwaysInstallElevated
    if ($aieHKLM -eq 1 -and $aieHKCU -eq 1) {
        Out-Finding "CRITICAL" "AlwaysInstallElevated is ENABLED" "Any user can install .msi packages with SYSTEM privileges"
    }
} catch { Write-OK "AlwaysInstallElevated is not set" }


# ------------------------------------------------------------------------------
# 11. INSTALLED APPLICATIONS
# ------------------------------------------------------------------------------
Step-Progress "Installed Applications"
Write-SectionHeader "Installed Applications" ">"
Out-Section "Installed Applications"

try {
    @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    ) | ForEach-Object { Get-ItemProperty $_ -ErrorAction SilentlyContinue } |
        Where-Object { $_.DisplayName } |
        Select-Object DisplayName, DisplayVersion, Publisher |
        Sort-Object DisplayName -Unique |
        ForEach-Object {
            Out-Report ("  {0,-55} {1,-15} {2}" -f $_.DisplayName, $_.DisplayVersion, $_.Publisher)
        }
} catch {}


# ------------------------------------------------------------------------------
# 12. SENSITIVE FILE DISCOVERY
# ------------------------------------------------------------------------------
Step-Progress "Sensitive File Discovery"
Write-SectionHeader "Sensitive File Discovery" ">"
Out-Section "Sensitive File Discovery"

$sensitiveFiles = @(
    @{ Path="C:\Unattend.xml";                                Sev="CRITICAL"; Desc="Unattended install -- may contain credentials" }
    @{ Path="C:\Windows\Panther\Unattend.xml";                Sev="CRITICAL"; Desc="Unattended install -- may contain credentials" }
    @{ Path="C:\Windows\Panther\Unattend\Unattend.xml";       Sev="CRITICAL"; Desc="Unattended install -- may contain credentials" }
    @{ Path="C:\Windows\system32\sysprep.inf";                Sev="HIGH";     Desc="Sysprep -- may contain AutoLogon credentials" }
    @{ Path="C:\Windows\system32\sysprep\sysprep.xml";        Sev="HIGH";     Desc="Sysprep -- may contain credentials" }
    @{ Path="C:\Windows\repair\SAM";                          Sev="CRITICAL"; Desc="Backup SAM -- offline credential extraction" }
    @{ Path="C:\Windows\repair\SYSTEM";                       Sev="HIGH";     Desc="Backup SYSTEM hive" }
    @{ Path="C:\Windows\repair\SECURITY";                     Sev="HIGH";     Desc="Backup SECURITY hive" }
    @{ Path="C:\Windows\System32\config\RegBack\SAM";         Sev="CRITICAL"; Desc="Registry backup SAM" }
    @{ Path="C:\Windows\System32\config\RegBack\SYSTEM";      Sev="HIGH";     Desc="Registry backup SYSTEM" }
    @{ Path="$env:APPDATA\Microsoft\Credentials";             Sev="HIGH";     Desc="DPAPI-encrypted credentials" }
    @{ Path="$env:LOCALAPPDATA\Microsoft\Credentials";        Sev="HIGH";     Desc="DPAPI-encrypted credentials" }
    @{ Path="$env:USERPROFILE\.ssh\id_rsa";                   Sev="HIGH";     Desc="SSH private key" }
    @{ Path="$env:USERPROFILE\.ssh\id_ed25519";               Sev="HIGH";     Desc="SSH private key (ed25519)" }
)

$sensitiveFound = $false
foreach ($sf in $sensitiveFiles) {
    if (Test-Path $sf.Path) {
        Out-Finding $sf.Sev "Found: $($sf.Path)" $sf.Desc
        try {
            $content = Get-Content $sf.Path -TotalCount 50 -ErrorAction SilentlyContinue
            if ($content) { Out-Raw $content }
        } catch {}
        $sensitiveFound = $true
    }
}
if (-not $sensitiveFound) { Write-OK "No sensitive files found in checked locations" }


# ------------------------------------------------------------------------------
# 13. POWERSHELL HISTORY & TRANSCRIPTS
# ------------------------------------------------------------------------------
Step-Progress "PowerShell History"
Write-SectionHeader "PowerShell History & Transcripts" ">"
Out-Section "PowerShell History & Transcripts"

$histFile = "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $histFile) {
    $histContent = Get-Content $histFile -ErrorAction SilentlyContinue
    Out-Report "  History file: $histFile  ($($histContent.Count) lines)"
    $keywords = @('password','passwd','cred','secret','token','apikey','iex','invoke-expression','downloadstring','net user','runas','psexec')
    $flagged  = $histContent | Where-Object { $kw = $_; ($keywords | Where-Object { $kw -imatch $_ }) }
    if ($flagged) {
        Out-Finding "HIGH" "Sensitive keywords in PowerShell history"
        Out-Raw $flagged
    } else { Write-OK "No sensitive keywords in PowerShell history" }
    Out-Report "  --- Full History ---"; Out-Raw $histContent
} else { Write-OK "No PowerShell history file found" }

@("$env:USERPROFILE","C:\Transcripts") | ForEach-Object {
    $t = Get-ChildItem $_ -Filter "PowerShell_transcript*.txt" -Recurse -ErrorAction SilentlyContinue
    if ($t) { Out-Finding "MEDIUM" "PowerShell transcripts found in $_" ($t.FullName -join ' | ') }
}


# ------------------------------------------------------------------------------
# 14. STORED CREDENTIALS
# ------------------------------------------------------------------------------
Step-Progress "Stored Credentials"
Write-SectionHeader "Stored Credentials" ">"
Out-Section "Stored Credentials"

try {
    $creds = cmdkey /list 2>$null
    if ($creds -match "Target:") {
        Out-Finding "HIGH" "Stored credentials via cmdkey" "" "https://pentesterhelper.in/notes/share.html?id=1292840269"
        Out-Raw $creds
    } else { Write-OK "No cmdkey stored credentials" }
} catch {}

try {
    $putty = reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /f "Proxy" /s 2>$null
    if ($putty) { Out-Finding "MEDIUM" "PuTTY sessions with proxy settings found"; Out-Raw $putty }
} catch {}

try {
    $winscp = reg query "HKCU\Software\Martin Prikryl\WinSCP 2\Sessions" 2>$null
    if ($winscp) { Out-Finding "MEDIUM" "WinSCP saved sessions found"; Out-Raw $winscp }
} catch {}

try {
    $vc = vaultcmd /listcreds:"Windows Credentials" 2>$null
    if ($vc -match "Resource:") { Out-Finding "HIGH" "Windows Vault credentials found"; Out-Raw $vc }
} catch {}

@("C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config","C:\inetpub\wwwroot\web.config") | ForEach-Object {
    if (Test-Path $_) {
        $hits = Get-Content $_ -ErrorAction SilentlyContinue | Select-String "connectionString|password"
        if ($hits) { Out-Finding "HIGH" "Potential credentials in web.config: $_"; Out-Raw ($hits | Select-Object -ExpandProperty Line) }
    }
}

@("$env:USERPROFILE\.git-credentials","$env:USERPROFILE\.netrc") | ForEach-Object {
    if (Test-Path $_) { Out-Finding "HIGH" "Credential file found: $_"; Out-Raw (Get-Content $_ -ErrorAction SilentlyContinue) }
}


# ------------------------------------------------------------------------------
# 15. DPAPI ARTIFACTS
# ------------------------------------------------------------------------------
Step-Progress "DPAPI Artifacts"
Write-SectionHeader "DPAPI Artifacts" ">"
Out-Section "DPAPI Artifacts"

try {
    $mkDir = "$env:APPDATA\Microsoft\Protect"
    if (Test-Path $mkDir) {
        $keys = Get-ChildItem $mkDir -Recurse -ErrorAction SilentlyContinue
        if ($keys) {
            Out-Finding "MEDIUM" "DPAPI master keys present: $mkDir" "Use mimikatz sekurlsa::dpapi or SharpDPAPI to decrypt"
            $keys | ForEach-Object { Out-Report "    $($_.FullName)" }
            Out-Report ""
        }
    }
} catch {}


# ------------------------------------------------------------------------------
# 16. ACTIVE SESSIONS & USERS
# ------------------------------------------------------------------------------
Step-Progress "Active Sessions & Users"
Write-SectionHeader "Active Sessions & Users" ">"
Out-Section "Active Sessions & Users"

try {
    Out-Report "  --- Logged-On Users ---"; Out-Raw (query user 2>$null)
    Out-Report "  --- Local User Accounts ---"
    $localUsers = Get-LocalUser -ErrorAction Stop
    foreach ($u in $localUsers) {
        $flags = ""
        if (-not $u.Enabled)          { $flags += " [DISABLED]" }
        if (-not $u.PasswordRequired) { $flags += " [NO PASSWORD]" }
        Out-Report ("  {0,-25} Enabled:{1,-6}  LastLogon:{2}{3}" -f $u.Name, $u.Enabled, $u.LastLogon, $flags)
        if (-not $u.PasswordRequired -and $u.Enabled) {
            Out-Finding "CRITICAL" "Enabled account with no password: $($u.Name)"
        }
    }
    Out-Report ""; Out-Report "  --- Local Groups ---"
    Get-LocalGroup -ErrorAction SilentlyContinue | ForEach-Object {
        Out-Report "  Group: $($_.Name)"
        try { Get-LocalGroupMember $_.Name -ErrorAction Stop | ForEach-Object { Out-Report "    $($_.Name)  [$($_.ObjectClass)]" } } catch {}
        Out-Report ""
    }
} catch {}


# ------------------------------------------------------------------------------
# 17. RUNNING PROCESSES
# ------------------------------------------------------------------------------
Step-Progress "Running Processes"
Write-SectionHeader "Running Processes" ">"
Out-Section "Running Processes"

try {
    $procs = Get-CimInstance Win32_Process |
        Select-Object ProcessId, Name, ExecutablePath,
            @{N="Owner";E={ try{($_.GetOwner()).User}catch{"N/A"} }} |
        Sort-Object Owner, Name

    $procs | ForEach-Object {
        Out-Report ("  {0,-6} {1,-40} {2,-20} {3}" -f $_.ProcessId, $_.Name, $_.Owner, $_.ExecutablePath)
    }

    $systemProcs = $procs | Where-Object {
        $_.Owner -eq "SYSTEM" -and $_.ExecutablePath -and $_.ExecutablePath -notlike "C:\Windows\*"
    }
    if ($systemProcs) {
        Out-Finding "MEDIUM" "SYSTEM processes in non-standard paths"
        $systemProcs | ForEach-Object { Out-Report "    PID $($_.ProcessId) -- $($_.ExecutablePath)" }
        Out-Report ""
    }
} catch {}


# ------------------------------------------------------------------------------
# 18. PATH HIJACKING
# ------------------------------------------------------------------------------
Step-Progress "PATH Hijacking Opportunities"
Write-SectionHeader "PATH Hijacking Opportunities" ">"
Out-Section "PATH Hijacking Opportunities"

try {
    $vulnFound = $false
    $env:PATH -split ';' | Where-Object { $_ -and (Test-Path $_) } | ForEach-Object {
        if (Test-AclVulnerable (Get-AclDetail $_)) {
            Out-Finding "HIGH" "Writable PATH directory: $_" "Plant a malicious binary here to hijack execution"
            $vulnFound = $true
        }
    }
    if (-not $vulnFound) { Write-OK "No writable PATH directories found" }
} catch {}


# ------------------------------------------------------------------------------
# 19. WEAK FOLDER PERMISSIONS
# ------------------------------------------------------------------------------
Step-Progress "Weak Folder Permissions"
Write-SectionHeader "Weak Folder Permissions" ">"
Out-Section "Weak Folder Permissions in Common Locations"

foreach ($dir in @("C:\Program Files","C:\Program Files (x86)","C:\ProgramData","C:\")) {
    if (-not (Test-Path $dir)) { continue }
    $acl = Get-AclDetail $dir
    if (Test-AclVulnerable $acl) {
        Out-Finding "HIGH" "Writable common directory: $dir" "Possible DLL planting or binary replacement"
        Out-Raw $acl
    }
}


# ------------------------------------------------------------------------------
# 20. DOMAIN INFORMATION
# ------------------------------------------------------------------------------
Step-Progress "Domain Information"
Write-SectionHeader "Domain Information" ">"
Out-Section "Domain Information"

try {
    $cs = Get-CimInstance Win32_ComputerSystem
    if ($cs.PartOfDomain) {
        Out-Report "  Domain: $($cs.Domain)"
        try { Out-Report "  --- Domain Trusts ---";      Out-Raw (nltest /domain_trusts 2>$null) }          catch {}
        try { Out-Report "  --- Domain Controllers ---"; Out-Raw (nltest /dclist:$($cs.Domain) 2>$null) }   catch {}
        try { Out-Report "  --- GPResult ---";           Out-Raw (gpresult /r 2>$null) }                    catch {}
    } else {
        Out-Report "  Not domain-joined (Workgroup: $($cs.Workgroup))"
        Write-OK "Not domain-joined"
    }
} catch {}


# ------------------------------------------------------------------------------
# 21. INTERESTING FILE SEARCH
# ------------------------------------------------------------------------------
Step-Progress "Interesting File Search"
Write-SectionHeader "Interesting File Search" ">"
Out-Section "Interesting File Search"

$searchRoots         = @($env:USERPROFILE,"C:\inetpub","C:\xampp","C:\wamp","C:\Apache24")
$interestingPatterns = @("*password*","*passwd*","*credentials*","*secret*","*id_rsa*","*config*.xml","*.kdbx","*private*.key")

foreach ($root in $searchRoots) {
    if (-not (Test-Path $root)) { continue }
    foreach ($pattern in $interestingPatterns) {
        try {
            Get-ChildItem -Path $root -Filter $pattern -Recurse -Force -ErrorAction SilentlyContinue |
                Where-Object { -not $_.PSIsContainer } |
                ForEach-Object {
                    Out-Finding "MEDIUM" "Interesting file: $($_.FullName)" "Pattern: $pattern  Size: $($_.Length) bytes"
                }
        } catch {}
    }
}


# ==============================================================================
#  FINALIZE
# ==============================================================================
Complete-ProgressBar

$totalFindings = ($Script:Counts.Values | Measure-Object -Sum).Sum

Out-Section "SUMMARY"
Out-Report ("  CRITICAL : {0,4}" -f $Script:Counts.CRITICAL)
Out-Report ("  HIGH     : {0,4}" -f $Script:Counts.HIGH)
Out-Report ("  MEDIUM   : {0,4}" -f $Script:Counts.MEDIUM)
Out-Report ("  LOW      : {0,4}" -f $Script:Counts.LOW)
Out-Report ("  INFO     : {0,4}" -f $Script:Counts.INFO)
Out-Report "  -----------------"
Out-Report ("  TOTAL    : {0,4}" -f $totalFindings)
Out-Report ""
if ($Script:Counts.CRITICAL -gt 0 -or $Script:Counts.HIGH -gt 0) {
    Out-Report "  [!] High-severity findings detected -- review immediately"
}
Out-Report ""
Out-Report "  Report saved : $Script:ReportFile"
Out-Report "  Completed    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Out-Report ("=" * 80)

Write-Host ""
Write-Color ("  " + "-"*78) DarkGray
Write-Color "  FINDINGS SUMMARY" Yellow
Write-Color ("  " + "-"*78) DarkGray
Write-Color ("  CRITICAL : {0,4}" -f $Script:Counts.CRITICAL) Red
Write-Color ("  HIGH     : {0,4}" -f $Script:Counts.HIGH) DarkRed
Write-Color ("  MEDIUM   : {0,4}" -f $Script:Counts.MEDIUM) Yellow
Write-Color ("  LOW      : {0,4}" -f $Script:Counts.LOW) Cyan
Write-Color ("  INFO     : {0,4}" -f $Script:Counts.INFO) Gray
Write-Color "  -----------------" DarkGray
Write-Color ("  TOTAL    : {0,4}" -f $totalFindings) White
Write-Host ""
Write-Color "  [+] Report saved: $Script:ReportFile" Green
Write-Host ""
