<#
=====================================================================
 Admin By Request (ABR) - Endpoint Health Check   (Windows)   v2.1
=====================================================================
 Copyright (c) 2026 OnCloud Ltd. MIT License (see LICENSE in the repo root).
 https://github.com/oncloud-public/adminbyrequest-tools

 Community tool by OnCloud, an Admin By Request partner.
 Not an official Admin By Request product.

 Read-only diagnostic for a Windows endpoint running ABR.
 Scope: EPM by default. Add -IncludeSRA and/or -IncludeWAM for those
        add-ons (Secure Remote Access / Web Access Management).
 It makes NO changes - it only reads state and prints PASS/WARN/FAIL/INFO.

 The checks are independent of the agent: they read the endpoint
 directly instead of trusting the ABR agent to report on itself.

 USAGE
   Run as the END USER (not elevated) to judge their rights correctly:
     powershell -ExecutionPolicy Bypass -File .\ABR-EPM-HealthCheck.ps1
   Options:
     -AsJson            Emit results as JSON (for a tool to consume)
     -OutFile <path>    Also save a text/JSON report to a file
     -IncludeSRA        Also run Secure Remote Access checks (MQTT/tunnel/RDP)
     -IncludeWAM        Also run Web Access Management checks
     -UseApi            Also cross-check THIS device against the ABR portal
                        (reporting freshness, version, admin state). Prompts
                        for an ABR API key; the key is never stored or logged.
                        ADMINS ONLY - never give an API key to an end user.
     -ApiBase <url>     API prefix (default https://dc1api.adminbyrequest.com = EU;
                        US = https://dc2api.adminbyrequest.com)
     -StaleDays <n>     Flag this device if it hasn't reported to the portal in N days (default 7)
     -MinAbrVersion <v> Lowest ABR for Windows version you support (default 8.4.2.0)
   SRA/WAM are optional add-ons - only enable those checks for customers
   who have them, or they will WARN on endpoints that don't run them.
   Single-device only: everything is read from / about THIS endpoint.
   A few checks (some registry values) are richer when elevated; the
   script still runs and degrades gracefully as a standard user.
=====================================================================
#>

[CmdletBinding()]
param(
    [switch]$AsJson,
    [string]$OutFile,
    [switch]$IncludeSRA,
    [switch]$IncludeWAM,
    [switch]$UseApi,                                      # prompts for the ABR API key at runtime
    [string]$ApiBase = 'https://dc1api.adminbyrequest.com', # EU = dc1api, US = dc2api (your portal shows the exact prefix)
    [int]$ApiTake = 5000,
    [int]$StaleDays = 7,
    [version]$MinAbrVersion = '8.4.2.0'
)

$ErrorActionPreference = 'Stop'
$results = New-Object System.Collections.Generic.List[object]

function Add-Result {
    param(
        [string]$Id,          # short check id (area)
        [string]$Name,
        [ValidateSet('PASS','WARN','FAIL','INFO')][string]$Status,
        [string]$Detail = '',
        [string]$Fix = ''
    )
    $results.Add([pscustomobject]@{
        Id     = $Id
        Check  = $Name
        Status = $Status
        Detail = $Detail
        Fix    = $Fix
    })
}

function Test-Tcp {
    param([string]$HostName, [int]$Port, [int]$TimeoutMs = 4000)
    try {
        $c = New-Object System.Net.Sockets.TcpClient
        $iar = $c.BeginConnect($HostName, $Port, $null, $null)
        $ok = ($iar.AsyncWaitHandle.WaitOne($TimeoutMs)) -and $c.Connected
        $c.Close(); return $ok
    } catch { return $false }
}

$script:AbrVersion = $null

# --- environment -----------------------------------------------------
$IsAdmin = $false
try {
    $IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
                ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
} catch {}

$AbrRoot    = 'C:\Program Files (x86)\FastTrack Software\Admin By Request'
$VAudioRoot = 'C:\Program Files (x86)\Common Files\VAudio'
$PolicyKey  = 'HKLM:\SOFTWARE\FastTrack Software\Admin By Request\Policies'

# Well-known SIDs (language-independent, unlike group names)
$SidAdministrators = 'S-1-5-32-544'
$SidPowerUsers     = 'S-1-5-32-547'
$SidNetConfigOps   = 'S-1-5-32-556'
# Domain groups: S-1-5-21-<domain>-<RID>
$DomainRiskyRids = @{ '512' = 'Domain Admins'; '518' = 'Schema Admins'; '519' = 'Enterprise Admins'; '520' = 'Group Policy Creator Owners' }

function Get-RiskySidName {
    param([string]$Sid)
    if ($Sid -eq $SidPowerUsers)   { return 'Power Users' }
    if ($Sid -eq $SidNetConfigOps) { return 'Network Configuration Operators' }
    if ($Sid -match '^S-1-5-21-\d+-\d+-\d+-(\d+)$' -and $DomainRiskyRids.ContainsKey($Matches[1])) { return $DomainRiskyRids[$Matches[1]] }
    return $null
}

# =====================================================================
# 1. ABR installed + version
# =====================================================================
try {
    $uninst = @(@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') |
              ForEach-Object { Get-ItemProperty $_ -ErrorAction SilentlyContinue } |
              Where-Object { $_.DisplayName -like '*Admin By Request*' })

    if ($uninst.Count -eq 0) {
        Add-Result 'install' 'ABR agent installed' 'FAIL' 'No Admin By Request product found in the registry.' 'Install the ABR for Windows agent.'
    } else {
        $ver = ($uninst | Select-Object -First 1).DisplayVersion
        try { $v = [version]$ver } catch { $v = $null }
        $script:AbrVersion = $v
        if ($v -and $v -lt $MinAbrVersion) {
            Add-Result 'version' "ABR version ($ver)" 'WARN' "Below supported minimum $MinAbrVersion." "Upgrade to >= $MinAbrVersion (adminbyrequest.com/ABRDownload?fullversion=true) and reboot."
        } else {
            Add-Result 'version' "ABR version ($ver)" 'PASS' "Installed."
        }
        # 2. duplicate installs (an old build re-pushed by MDM causes MSI 1603 loops)
        if ($uninst.Count -gt 1) {
            Add-Result 'install' 'Single ABR install' 'WARN' "$($uninst.Count) ABR products registered (possible duplicate/old build being re-pushed)." 'Deploy one current version; stop MDM/Intune pushing an older build (causes 1603 loops).'
        } else {
            Add-Result 'install' 'Single ABR install' 'PASS' 'One ABR product registered.'
        }
    }
} catch { Add-Result 'install' 'ABR agent installed' 'WARN' "Check failed: $($_.Exception.Message)" }

# =====================================================================
# 3. ABR Windows service running  (discover by binary path)
# =====================================================================
try {
    $svc = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
           Where-Object { $_.PathName -match 'Admin By Request|FastTrack Software|AdminByRequest' -or $_.Name -match 'AdminByRequest' -or $_.DisplayName -match 'Admin By Request' }
    if (-not $svc) {
        # Newer ABR (9.x) may have no standalone Win32 service - it runs via its filter driver + adminbyrequest.exe.
        Add-Result 'service' 'ABR service' 'INFO' 'No standalone Win32 service found - agent runs via its filter driver + adminbyrequest.exe (see the driver & tray checks).'
    } else {
        foreach ($s in $svc) {
            if ($s.State -eq 'Running') {
                Add-Result 'service' "ABR service '$($s.Name)'" 'PASS' 'Running.'
            } else {
                Add-Result 'service' "ABR service '$($s.Name)'" 'WARN' "State: $($s.State), StartMode: $($s.StartMode)." 'Start the ABR service if the agent misbehaves.'
            }
        }
    }
} catch { Add-Result 'service' 'ABR service' 'INFO' "Check skipped: $($_.Exception.Message)" }

# =====================================================================
# 4. ABR kernel driver loaded  (no driver => native UAC fallback)
#    Matched by binary path only, so other drivers with similar names
#    (e.g. Sysinternals Process Monitor's PROCMON24) are not counted.
# =====================================================================
try {
    $drv = Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue |
           Where-Object { $_.PathName -match 'FastTrack Software|Admin By Request|\\VAudio\\' }
    if (-not $drv) {
        Add-Result 'driver' 'ABR elevation driver loaded' 'WARN' 'Could not find an ABR driver (ProcMon.sys / VAudio.sys) registered from the ABR folders.' 'If elevations fall back to native Windows UAC, reboot (driver may not have loaded after a reinstall).'
    } else {
        $running = $drv | Where-Object { $_.State -eq 'Running' }
        if ($running) {
            Add-Result 'driver' 'ABR elevation driver loaded' 'PASS' (($running | ForEach-Object { $_.Name }) -join ', ')
        } else {
            Add-Result 'driver' 'ABR elevation driver loaded' 'FAIL' 'ABR driver present but not Running => native UAC fallback.' 'Reboot to reload the driver (esp. after an uninstall+reinstall without a restart).'
        }
    }
} catch { Add-Result 'driver' 'ABR elevation driver loaded' 'WARN' "Check failed: $($_.Exception.Message)" }

# =====================================================================
# 5. ABR tray/GUI process running  (tray icon disappears)
# =====================================================================
try {
    $gui = Get-Process -Name 'AdminByRequest' -ErrorAction SilentlyContinue
    if ($gui) {
        Add-Result 'tray' 'ABR tray/GUI process' 'PASS' "adminbyrequest.exe running (PID $(( $gui | Select-Object -First 1).Id))."
    } else {
        Add-Result 'tray' 'ABR tray/GUI process' 'WARN' 'adminbyrequest.exe not running (tray icon missing; service may still run).' "Relaunch: `"$AbrRoot\adminbyrequest.exe`"  (and stop any continuous MDM re-push)."
    }
} catch { Add-Result 'tray' 'ABR tray/GUI process' 'WARN' "Check failed: $($_.Exception.Message)" }

# =====================================================================
# 6. Is the current user effectively a local admin?
#    The key integrity check: do NOT trust the ABR icon - read the token.
#    The logon token lists every group the user is in, including groups
#    nested inside local Administrators, and lists Administrators even
#    when UAC filters it ("deny only"). SIDs are language-independent.
# =====================================================================
$tok = $null
try {
    $tok = @(whoami /groups /fo csv /nh 2>$null | ConvertFrom-Csv -Header 'Name','Type','SID','Attributes')
} catch {}

$me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
if ($tok -and $tok.Count) {
    if ($tok | Where-Object { $_.SID -eq $SidAdministrators }) {
        if ($IsAdmin) {
            Add-Result 'local-admin' 'Current user NOT a local admin' 'INFO' "Skipped: script is running ELEVATED as $me. Run it in a normal (non-elevated) PowerShell as the end user to check their rights."
        } else {
            Add-Result 'local-admin' 'Current user NOT a local admin' 'FAIL' "$me is a member of local Administrators (directly or through a nested group) => ABR cannot revoke (tray may still show green). Ignore this if the user is inside an active ABR admin session." 'Remove the user, or the AD/Entra group that grants it (e.g. a Restricted Groups GPO or Intune policy), from local Administrators.'
        }
    } else {
        Add-Result 'local-admin' 'Current user NOT a local admin' 'PASS' "$me is a standard user."
    }

    # 6b. risky token groups of the current user (ABR "problem groups")
    $risky = @($tok | ForEach-Object { Get-RiskySidName $_.SID } | Where-Object { $_ })
    if ($risky.Count) {
        Add-Result 'risky-groups' 'Risky group membership (current user)' 'WARN' (($risky | Select-Object -Unique) -join ', ') 'Remove from Power Users / Network Configuration Operators / Group Policy Creator Owners / domain admin groups (ABR "problem groups"); then log off/on.'
    } else {
        Add-Result 'risky-groups' 'Risky group membership (current user)' 'PASS' 'None of the ABR problem groups.'
    }
} else {
    Add-Result 'local-admin' 'Current user NOT a local admin' 'WARN' 'Could not read the logon token (whoami /groups).' 'Run whoami /groups and look for S-1-5-32-544 (Administrators).'
}

# 6c. who is in local Administrators (broad/privileged groups make members unrevokable)
try {
    $admins = @(Get-LocalGroupMember -SID $SidAdministrators -ErrorAction Stop)
    $broad = @($admins | Where-Object {
        (Get-RiskySidName "$($_.SID)") -or $_.Name -match 'Company Administrators|Device Administrators|Global Administrator|Azure AD Joined Device Local Administrator'
    })
    if ($broad.Count) {
        Add-Result 'admins-group' 'Local Administrators membership' 'WARN' ("Broad groups in local Administrators: " + (($broad | ForEach-Object { $_.Name }) -join ', ')) 'Any domain/privileged group nested here makes its members unrevokable by ABR.'
    } else {
        # Entra ID roles/groups show only as SIDs (S-1-12-1-...). On Entra-joined devices Windows adds
        # the Global Administrator role and the "Microsoft Entra Joined Device Local Administrator" role by default.
        $memberNames = $admins | ForEach-Object { if ("$($_.Name)" -match '^S-1-12-1-') { "$($_.Name) (Entra role/group)" } else { $_.Name } }
        $entraNote = ''
        if ($admins | Where-Object { "$($_.Name)" -match '^S-1-12-1-' }) { $entraNote = ' Entra SIDs are normally the Global Administrator and Entra Joined Device Local Administrator roles; their members are local admins on this device and cannot be revoked by ABR - keep those roles small.' }
        Add-Result 'admins-group' 'Local Administrators membership' 'INFO' ("Members: " + ($memberNames -join ', ') + '.' + $entraNote)
    }
} catch {
    # Get-LocalGroupMember fails on some machines (e.g. orphaned Entra SIDs); fall back to ADSI.
    try {
        $grpName = (New-Object Security.Principal.SecurityIdentifier $SidAdministrators).Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
        $grp = [ADSI]"WinNT://$env:COMPUTERNAME/$grpName,group"
        $names = @($grp.Invoke('Members') | ForEach-Object { $_.GetType().InvokeMember('Name', 'GetProperty', $null, $_, $null) })
        Add-Result 'admins-group' 'Local Administrators membership' 'INFO' ("Members: " + ($names -join ', '))
    } catch { Add-Result 'admins-group' 'Local Administrators membership' 'WARN' "Could not enumerate Administrators: $($_.Exception.Message)" }
}

# =====================================================================
# 7. Secondary Logon service (seclogon)  (needed by Support Assist / Run as)
# =====================================================================
try {
    $sec = Get-Service -Name 'seclogon' -ErrorAction Stop
    if ($sec.StartType -eq 'Disabled') {
        Add-Result 'seclogon' 'Secondary Logon (seclogon) enabled' 'FAIL' 'seclogon is DISABLED => Support Assist / Run-as-different-user fail ("incorrect username/password").' 'Set-Service -Name seclogon -StartupType Manual ; Start-Service seclogon  (and exclude the device from any hardening GPO that disables it).'
    } else {
        Add-Result 'seclogon' 'Secondary Logon (seclogon) enabled' 'PASS' "StartType: $($sec.StartType), Status: $($sec.Status)."
    }
} catch { Add-Result 'seclogon' 'Secondary Logon (seclogon) enabled' 'WARN' "Could not query seclogon: $($_.Exception.Message)" }

# =====================================================================
# 8. Conflicting AV/EDR present
# =====================================================================
try {
    # Precise service identifiers (avoid loose substrings that false-positive).
    $edrConflict = [ordered]@{
        'CrowdStrike Falcon'   = 'CSFalconService|CSAgent'
        'SentinelOne'          = 'SentinelAgent|SentinelStaticEngine'
        'Trellix/McAfee'       = 'mfemms|masvc|mfefire|McAfeeFramework'
        'Palo Alto Cortex XDR' = 'cyserver|cyveraservice|CortexXDR'
        'VMware Carbon Black'  = 'CbDefense|CarbonBlack'
        'ETX Client Launcher'  = 'ETXClient'
    }
    $svcAll = Get-Service -ErrorAction SilentlyContinue
    $found  = @()
    foreach ($k in $edrConflict.Keys) {
        if ($svcAll | Where-Object { $_.Name -match $edrConflict[$k] -or $_.DisplayName -match $edrConflict[$k] }) { $found += $k }
    }
    if ($found) {
        Add-Result 'edr' 'Conflicting AV/EDR present' 'WARN' ("Detected: " + ($found -join ', ')) 'Verify ABR files/folders are EXCLUDED in this product (ABR exclusion list incl. VAudio\Audckq32.exe). Palo Alto Cortex: ensure content update CU 1190-75273+.'
    } else {
        Add-Result 'edr' 'Conflicting AV/EDR present' 'PASS' 'None of the known aggressive-conflict EDRs detected.'
    }
    # Microsoft Defender for Endpoint: very common; usually coexists, but CAN quarantine ABR files.
    if ($svcAll | Where-Object { $_.Name -match '^Sense$|^WdNisSvc$|^WinDefend$' }) {
        Add-Result 'defender' 'Microsoft Defender for Endpoint' 'INFO' 'Present. Usually coexists with ABR; add ABR exclusions only if you see ABR file/icon/elevation issues.'
    }
} catch { Add-Result 'edr' 'Conflicting AV/EDR present' 'INFO' "Check failed: $($_.Exception.Message)" }

# =====================================================================
# 9. ABR file integrity  (AV may quarantine ABR files)
# =====================================================================
try {
    $files = @("$AbrRoot\AdminByRequest.exe", "$AbrRoot\ProcMon.sys", "$VAudioRoot\Audckq32.exe")
    $missing = @(); $unsigned = @(); $denied = @()
    foreach ($f in $files) {
        $leaf = Split-Path $f -Leaf
        try {
            if (-not (Test-Path -LiteralPath $f -ErrorAction Stop)) { $missing += $leaf; continue }
            if ((Get-AuthenticodeSignature -LiteralPath $f -ErrorAction Stop).Status -ne 'Valid') { $unsigned += $leaf }
        } catch [System.UnauthorizedAccessException] { $denied += $leaf }
          catch { if ($_.Exception.Message -match 'denied') { $denied += $leaf } else { throw } }
    }
    if ($missing) {
        Add-Result 'files' 'ABR core files present' 'FAIL' ("Missing: " + ($missing -join ', ') + " (possible AV quarantine).") 'Restore from AV quarantine + add ABR exclusions; repair/reinstall the agent if the install is corrupted.'
    } elseif ($unsigned) {
        Add-Result 'files' 'ABR core files signed' 'WARN' ("Not a valid signature: " + ($unsigned -join ', ')) 'Investigate tampering/AV; verify with certutil -hashfile.'
    } elseif ($denied) {
        Add-Result 'files' 'ABR core files present & signed' 'INFO' ("Not readable as a standard user: " + ($denied -join ', ') + ". Normal - ABR protects these files.") 'To verify them, an admin can re-run the script elevated.'
    } else {
        Add-Result 'files' 'ABR core files present & signed' 'PASS' 'AdminByRequest.exe, ProcMon.sys, Audckq32.exe OK.'
    }
} catch { Add-Result 'files' 'ABR core files' 'WARN' "Check failed: $($_.Exception.Message)" }

# =====================================================================
# 10. Portal connectivity (EPM)  (yellow icon / offline PIN fallback)
# =====================================================================
try {
    if (Test-Tcp 'api.adminbyrequest.com' 443 4000) {
        Add-Result 'portal' 'ABR portal reachable (api:443)' 'PASS' 'TCP 443 to api.adminbyrequest.com OK.'
    } else {
        Add-Result 'portal' 'ABR portal reachable (api:443)' 'FAIL' 'Cannot reach api.adminbyrequest.com:443 => yellow icon; requests fall back to offline PIN.' 'Allow api.adminbyrequest.com (and api1/api2) through proxy/firewall; check TLS-decrypt.'
    }
} catch { Add-Result 'portal' 'ABR portal reachable (api:443)' 'WARN' "Check failed: $($_.Exception.Message)" }

# =====================================================================
# 11. Windows patch level + MSI SecureRepair  (CVE-2025-50173)
# =====================================================================
try {
    $os = Get-CimInstance Win32_OperatingSystem
    $build = "$($os.Caption) build $($os.BuildNumber)"
    $srp = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'SecureRepairPolicy' -ErrorAction SilentlyContinue).SecureRepairPolicy
    $detail = "$build. SecureRepairPolicy=" + ($(if ($null -ne $srp) { $srp } else { '(not set)' }))
    Add-Result 'msi-repair' 'Windows / MSI SecureRepair' 'INFO' $detail 'If standard users get UAC on MSI repair/install: install latest Windows updates (Oct 28 2025+), or allowlist the app ProductCode (KB5067315).'
} catch { Add-Result 'msi-repair' 'Windows / MSI SecureRepair' 'INFO' "Check failed: $($_.Exception.Message)" }

# =====================================================================
# 12. Pending reboot  (driver may not be loaded yet)
# =====================================================================
try {
    $pending = $false
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $pending = $true }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $pending = $true }
    $pfro = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue).PendingFileRenameOperations
    if ($pfro) { $pending = $true }
    if ($pending) {
        Add-Result 'reboot' 'No pending reboot' 'WARN' 'A reboot is pending (ABR driver may not be fully loaded after a recent install/upgrade).' 'Reboot the endpoint.'
    } else {
        Add-Result 'reboot' 'No pending reboot' 'PASS' 'None.'
    }
} catch { Add-Result 'reboot' 'No pending reboot' 'INFO' "Check failed: $($_.Exception.Message)" }

# =====================================================================
# 13. DebugMode leftover  (hygiene)
# =====================================================================
try {
    $dm = (Get-ItemProperty $PolicyKey -Name 'DebugMode' -ErrorAction SilentlyContinue).DebugMode
    if ($dm) {
        Add-Result 'hygiene' 'ABR DebugMode off' 'WARN' 'DebugMode=1 left enabled (extra logging/perf).' "Delete the DebugMode value under $PolicyKey."
    } else {
        Add-Result 'hygiene' 'ABR DebugMode off' 'PASS' 'Not enabled.'
    }
} catch { Add-Result 'hygiene' 'ABR DebugMode off' 'INFO' 'Policies key not readable (standard user).' }

# ---- Auto-Update override (ABR FAQ: InternetUpdate reg value) ----
try {
    $iu = (Get-ItemProperty $PolicyKey -Name 'InternetUpdate' -ErrorAction SilentlyContinue).InternetUpdate
    if ($null -eq $iu) { Add-Result 'update' 'ABR auto-update' 'PASS' 'No local override (follows the portal Auto-Update setting).' }
    elseif ($iu -eq 0) { Add-Result 'update' 'ABR auto-update' 'WARN' 'InternetUpdate=0 - auto-update DISABLED on this device; it will not get new versions automatically.' 'Remove/flip the InternetUpdate override unless this device is intentionally pinned.' }
    else { Add-Result 'update' 'ABR auto-update' 'PASS' 'InternetUpdate=1 (enabled).' }
} catch { Add-Result 'update' 'ABR auto-update' 'INFO' 'Policies key not readable (standard user).' }

# =====================================================================
# 14. ABR elevation mode + unexpected-UAC reference
#     (per the ABR Tech Note "Unexpected UAC prompts", Dec 2022)
#     In AUTHENTICATION mode a native-style UAC prompt is EXPECTED (the user
#     types their own standard credentials) - so it is NOT a fault there.
# =====================================================================
if (-not (Test-Path $PolicyKey)) {
    Add-Result 'mode' 'ABR elevation mode' 'INFO' 'No local ABR Policies key on this device (settings come from the portal). Reminder: in Authentication mode a UAC-style prompt is normal; only in Confirmation mode does a native UAC mean ABR could not hook.'
} else { try {
    $pol = Get-ItemProperty $PolicyKey -ErrorAction Stop
    $modeVals = $pol.PSObject.Properties | Where-Object { $_.Name -match 'mode|auth|confirm' -and $_.Name -notmatch 'DebugMode|offlinemode|enablesessions|^PS' }
    if ($modeVals) {
        Add-Result 'mode' 'ABR elevation mode' 'INFO' (($modeVals | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '; ') 'In Authentication mode a native-style UAC prompt is EXPECTED (user enters their own non-admin credentials), not a fault.'
    } else {
        Add-Result 'mode' 'ABR elevation mode' 'INFO' 'Not determinable from the Policies key. Reminder: in Authentication mode a UAC-style prompt is normal; only in Confirmation mode does a native UAC mean ABR could not hook.'
    }
} catch { Add-Result 'mode' 'ABR elevation mode' 'INFO' 'Policies key not readable (standard user).' } }

# =====================================================================
# SRA - Secure Remote Access / Remote Support      (-IncludeSRA)
# SRA's chain = live message bus + outbound MQTT (8883) + tunnel (7844).
# =====================================================================
if ($IncludeSRA) {
    try {
        if (Get-Process -Name 'messagebus' -ErrorAction SilentlyContinue) {
            Add-Result 'SRA' 'messagebus.exe running' 'PASS' 'MQTT message bus up.'
        } else {
            Add-Result 'SRA' 'messagebus.exe running' 'WARN' 'Not running - Remote Support pop-ups will not appear.' 'Restart the agent/endpoint; if it stays dead the root cause is MQTT connectivity.'
        }
    } catch { Add-Result 'SRA' 'messagebus.exe running' 'WARN' "Check failed: $($_.Exception.Message)" }

    foreach ($h in 'FastTrackHubEU1.azure-devices.net','FastTrackHubUS1.azure-devices.net') {
        if (Test-Tcp $h 8883 4000) { Add-Result 'SRA' "MQTT broker $h`:8883" 'PASS' 'Reachable.' }
        else { Add-Result 'SRA' "MQTT broker $h`:8883" 'FAIL' 'Blocked - Remote Support cannot connect.' 'Allow 8883 to *.azure-devices.net through firewall/proxy; no TLS-decrypt on it.' }
    }
    foreach ($h in 'region1.v2.argotunnel.com','region2.v2.argotunnel.com') {
        if (Test-Tcp $h 7844 4000) { Add-Result 'SRA' "Cloudflare tunnel $h`:7844" 'PASS' 'Reachable.' }
        else { Add-Result 'SRA' "Cloudflare tunnel $h`:7844" 'WARN' 'Blocked.' 'Allow 7844 to *.v2.argotunnel.com; SNI firewalls: allow cftunnel.com / h2.cftunnel.com / quic.cftunnel.com.' }
    }
    try {
        $deny = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections
        $ts = Get-Service -Name 'TermService' -ErrorAction SilentlyContinue
        if ($deny -eq 0 -and $ts.Status -eq 'Running') { Add-Result 'SRA' 'RDP (3389) for Unattended' 'PASS' 'RDP enabled.' }
        else { Add-Result 'SRA' 'RDP (3389) for Unattended' 'INFO' "fDenyTSConnections=$deny, TermService=$($ts.Status) - only needed for Unattended Access." 'Enable RDP if Unattended Access is required.' }
    } catch { Add-Result 'SRA' 'RDP (3389) for Unattended' 'INFO' "Check failed: $($_.Exception.Message)" }

    if ($script:AbrVersion) {
        if ($script:AbrVersion -lt [version]'8.4.0.0') { Add-Result 'SRA' 'Version supports Remote Support' 'WARN' "$($script:AbrVersion) < 8.4.0." 'Remote Support needs ABR for Windows 8.4.0 build 31936+.' }
        else { Add-Result 'SRA' 'Version supports Remote Support' 'PASS' "$($script:AbrVersion) (needs >= 8.4.0 b31936)." }
    }
    try {
        $px = ((netsh winhttp show proxy) 2>$null | Out-String).Trim()
        if ($px -match 'Direct access|no proxy|no proxy server') { Add-Result 'SRA' 'No WinHTTP decrypt proxy' 'PASS' 'Direct access.' }
        else { Add-Result 'SRA' 'WinHTTP proxy present' 'WARN' ($px -replace '\s+',' ') 'A decrypting proxy breaks MQTT/TLS to ABR; exclude *.azure-devices.net / *.argotunnel.com from TLS-decrypt.' }
    } catch { Add-Result 'SRA' 'WinHTTP proxy' 'INFO' 'Could not read proxy.' }
}

# =====================================================================
# WAM - Web Access Management                       (-IncludeWAM)
# Single-device: installed apps that WAM TLS-inspection commonly breaks.
# =====================================================================
if ($IncludeWAM) {
    try {
        $appPat = 'WhatsApp|Splashtop|AnyDesk|GlobalProtect|Cloudflare WARP|FortiClient|OpenVPN|Zscaler'
        $inst = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') |
                ForEach-Object { Get-ItemProperty $_ -ErrorAction SilentlyContinue } |
                Where-Object { $_.DisplayName -match $appPat } | Select-Object -ExpandProperty DisplayName -Unique
        if ($inst) { Add-Result 'WAM' 'Apps WAM may break present' 'INFO' (($inst) -join ', ') 'Add WAM URL/app bypasses for these (e.g. splashtop.com); use FQDN not raw IP for internal servers.' }
        else { Add-Result 'WAM' 'Apps WAM may break present' 'PASS' 'None of the common problem apps detected.' }
    } catch { Add-Result 'WAM' 'Apps WAM may break present' 'INFO' "Check failed: $($_.Exception.Message)" }
}

# =====================================================================
# API - cross-check THIS device against the ABR portal  (-UseApi)
# ADMINS ONLY. The key is read with a hidden prompt, kept in memory for
# this run only, and never written to disk, history or the report.
# The portal inventory is read in memory to find THIS computer by name;
# only this device's results are reported. Needs network access to
# $ApiBase (dc1api = EU, dc2api = US).
# =====================================================================
if ($UseApi) {
    $secureKey = Read-Host -Prompt 'ABR API key (input hidden; never stored)' -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
    try { $plainKey = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }

    if (-not $plainKey) {
        Add-Result 'API' 'ABR API cross-check' 'INFO' 'No API key entered - portal cross-check skipped.'
    } else {
        try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
        $hdr = @{ apikey = $plainKey }
        function Invoke-Abr { param([string]$Path) Invoke-RestMethod -Uri "$ApiBase$Path" -Headers $hdr -Method GET -TimeoutSec 60 }
        $authOK = $false
        try {
            $null = Invoke-Abr '/inventory?take=1'
            $authOK = $true
            Add-Result 'API' 'ABR API auth (apikey)' 'PASS' "Connected to $ApiBase."
        } catch {
            $code = $null; try { $code = [int]$_.Exception.Response.StatusCode } catch {}
            if ($code -in 401,403) { Add-Result 'API' 'ABR API auth (apikey)' 'FAIL' "HTTP $code - key rejected (or wrong data center)." 'Confirm the key is Active and -ApiBase (dc1=EU / dc2=US).' }
            else { Add-Result 'API' 'ABR API reachable' 'FAIL' "Could not reach $ApiBase/inventory: $($_.Exception.Message)" 'Check network/proxy to the ABR API host and -ApiBase.' }
        }
        if ($authOK) {
            # ABR inventory fields used: .name, .inventoryDate,
            # .abrClientVersion, .user.isAdmin, .user.account, .computer.localAdmins[]
            try {
                $inv = Invoke-Abr "/inventory?take=$ApiTake"
                $dev = $null
                foreach ($d in $inv) { if ("$($d.name)" -eq "$env:COMPUTERNAME") { $dev = $d; break } }
                $scanned = @($inv).Count
                $inv = $null   # drop the tenant-wide list as soon as this device is found
                if (-not $dev) {
                    Add-Result 'API' 'This device in ABR portal' 'WARN' "$env:COMPUTERNAME not found in portal inventory (scanned $scanned)." 'Agent may not be registered/reporting; or raise -ApiTake. Check About ABR > Connectivity.'
                } else {
                    Add-Result 'API' 'This device in ABR portal' 'PASS' "Found (id $($dev.id))."
                    try {
                        $idate = [datetime]$dev.inventoryDate
                        $ageh  = [int]((Get-Date) - $idate).TotalHours
                        if ($idate -lt (Get-Date).AddDays(-$StaleDays)) { Add-Result 'API' 'Device reporting to portal' 'WARN' "Last inventory $($idate.ToString('yyyy-MM-dd HH:mm')) (~$ageh h ago)." 'Agent not syncing (should be ~every 4h). Check connectivity (api:443) and the driver.' }
                        else { Add-Result 'API' 'Device reporting to portal' 'PASS' "Last inventory $($idate.ToString('yyyy-MM-dd HH:mm')) (~$ageh h ago)." }
                    } catch { Add-Result 'API' 'Device reporting to portal' 'INFO' "inventoryDate: $($dev.inventoryDate)" }

                    if ($script:AbrVersion -and $dev.abrClientVersion) {
                        $localShort = ("$($script:AbrVersion)".Split('.')[0..2] -join '.')
                        if ($localShort -ne ("$($dev.abrClientVersion)".Split(' ')[0])) { Add-Result 'API' 'Version matches portal' 'INFO' "Local $($script:AbrVersion) vs portal $($dev.abrClientVersion)." }
                        else { Add-Result 'API' 'Version matches portal' 'PASS' "Portal $($dev.abrClientVersion) = local." }
                    }

                    if ($dev.user -and $dev.user.isAdmin) { Add-Result 'API' 'Portal: user is ADMIN (not revoked)' 'WARN' "$($dev.user.account) is shown as admin in the portal." 'Rights not revoked for this user - check group membership / Lockdown.' }
                    else { Add-Result 'API' 'Portal: user is ADMIN (not revoked)' 'PASS' 'Portal shows the user as standard.' }

                    if ($dev.computer -and $dev.computer.localAdmins) {
                        # Domain/legacy privileged groups are a real misconfiguration (WARN).
                        # The two Entra roles are added by Windows on every Entra-joined device (INFO).
                        $hit   = @($dev.computer.localAdmins | Where-Object { $_ -match 'Domain Admins|Enterprise Admins|Schema Admins|Power Users' })
                        $entra = @($dev.computer.localAdmins | Where-Object { $_ -match 'Company Administrators|Device Administrators' })
                        if ($hit.Count) { Add-Result 'API' 'Portal: privileged groups in local Admins' 'WARN' ($hit -join ', ') 'Domain/privileged groups in local Administrators make their members unrevokable by ABR. Remove them.' }
                        else { Add-Result 'API' 'Portal: privileged groups in local Admins' 'PASS' 'No domain/privileged groups.' }
                        if ($entra.Count) { Add-Result 'API' 'Portal: Entra admin roles in local Admins' 'INFO' (($entra -join ', ') + ' - Windows default on Entra-joined devices (Global Administrator and Entra Joined Device Local Administrator roles).') 'Members of these roles are local admins ABR cannot revoke - keep the roles small.' }
                    }
                }
            } catch { Add-Result 'API' 'This device in ABR portal' 'WARN' "Failed: $($_.Exception.Message)" }
        }
        $plainKey = $null; $hdr = $null
    }
}

# =====================================================================
# OUTPUT
# =====================================================================
if (-not $IsAdmin) {
    Add-Result 'env' 'Elevation' 'INFO' 'Running as a standard user - a few registry checks are limited.'
}

if ($AsJson) {
    $json = $results | ConvertTo-Json -Depth 4
    if ($OutFile) { $json | Out-File -FilePath $OutFile -Encoding UTF8 }
    $json
    return
}

$colors = @{ PASS='Green'; WARN='Yellow'; FAIL='Red'; INFO='Gray' }
Write-Host ""
Write-Host "=== ABR EPM Endpoint Health Check ===  $(Get-Date -Format 'yyyy-MM-dd HH:mm')  on $env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host ""
foreach ($r in $results) {
    $tag = '[{0}]' -f $r.Status
    Write-Host ("{0,-6} " -f $tag) -ForegroundColor $colors[$r.Status] -NoNewline
    Write-Host ("{0,-38} {1}" -f $r.Check, $r.Detail)
    if ($r.Fix -and $r.Status -in 'FAIL','WARN') { Write-Host ("        -> FIX: {0}" -f $r.Fix) -ForegroundColor DarkGray }
}
Write-Host ""
$sum  = $results | Group-Object Status | ForEach-Object { "$($_.Name)=$($_.Count)" }
$fail = @($results | Where-Object Status -eq 'FAIL').Count
$warn = @($results | Where-Object Status -eq 'WARN').Count
if ($fail)     { $verdict = 'UNHEALTHY';       $vc = 'Red' }
elseif ($warn) { $verdict = 'NEEDS ATTENTION'; $vc = 'Yellow' }
else           { $verdict = 'HEALTHY';         $vc = 'Green' }
Write-Host ("Summary: {0}   =>  {1}" -f ($sum -join '  '), $verdict) -ForegroundColor $vc
Write-Host ""

if ($OutFile) {
    $lines = $results | ForEach-Object { "[{0}] {1} | {2} | {3}" -f $_.Status, $_.Check, $_.Detail, $_.Fix }
    @("ABR EPM Endpoint Health Check  $(Get-Date -Format 'u')  $env:COMPUTERNAME","") + $lines +
      @("", "Summary: $($sum -join '  ')  => $verdict") | Out-File -FilePath $OutFile -Encoding UTF8
    Write-Host "Saved report to $OutFile" -ForegroundColor Cyan
}
