<#
=====================================================================
 Admin By Request (ABR) - Tenant Posture Scan            v1.0
=====================================================================
 Copyright (c) 2026 OnCloud Ltd. MIT License (see LICENSE in the repo root).
 https://github.com/oncloud-public/adminbyrequest-tools

 Community tool by OnCloud, an Admin By Request partner.
 Not an official Admin By Request product.

 Read-only posture scan across your WHOLE ABR tenant.
 It reads the ABR Inventory API and reports endpoints with weak
 posture: standing local admins, stale/missing agents, outdated
 clients, BitLocker/TPM/compliance gaps and end-of-life operating
 systems. It makes NO changes - it only calls GET /inventory and
 prints findings plus a CSV you can hand to the customer.

 This is the tenant-wide companion to ABR-EPM-HealthCheck (which
 checks a single endpoint from the inside).

 ADMINS ONLY. The ABR API key reads your entire tenant.

 USAGE (run as an ABR admin, on any machine with network access):
   powershell -ExecutionPolicy Bypass -File .\ABR-Tenant-PostureScan.ps1

 OPTIONS
   -ApiBase <url>            API prefix for your region. Default
                             https://dc1api.adminbyrequest.com (EU West).
                             US East = dc2api, UK = dc3api, EU Central = dc4api,
                             US West = dc5api, Asia = dc6api. Your ABR portal
                             shows the prefix next to the API key.
   -ApprovedLocalAdmins <a> Account/group names allowed in local Administrators
                             (break-glass, LAPS). Comma-separated. The built-in
                             Administrator and the two default Entra roles are
                             always allowed.
   -StaleDays <n>           Flag a device that has not reported in N days. Default 14.
   -CsvPath <path>          Where to write the CSV. Default
                             .\ABR-PostureScan-<yyyy-MM-dd>.csv
   -NoCsv                   Do not write a CSV.
   -AsJson                  Print findings + summary as JSON (for a tool to consume).
   -PageSize <n>            Devices per API page. Default 500.
   -MaxDevices <n>          Safety cap on devices scanned. Default 100000.

 The key is read with a hidden prompt, kept in memory for this run
 only, and never written to disk, history or the report. Use a
 dedicated read-only key and disable it when you are done.
=====================================================================
#>

[CmdletBinding()]
param(
    [string]$ApiBase = 'https://dc1api.adminbyrequest.com',
    [string[]]$ApprovedLocalAdmins = @(),
    [int]$StaleDays = 14,
    [string]$CsvPath,
    [switch]$NoCsv,
    [switch]$AsJson,
    [int]$PageSize = 500,
    [int]$MaxDevices = 100000
)

$ErrorActionPreference = 'Stop'
$findings = New-Object System.Collections.Generic.List[object]

function Add-Finding {
    param(
        [string]$Id,
        [string]$Device,
        $DeviceId,
        [ValidateSet('CRITICAL','HIGH','MEDIUM','LOW','INFO')][string]$Severity,
        [string]$Check,
        [string]$Detail = ''
    )
    $findings.Add([pscustomobject]@{
        CheckId  = $Id
        Severity = $Severity
        Check    = $Check
        Device   = $Device
        DeviceId = $DeviceId
        Detail   = $Detail
    })
}

# Read a property that may sit at the top level or under a child object,
# returning $null when it is absent (so missing data never false-flags).
function Get-Field {
    param($Object, [string[]]$Paths)
    foreach ($p in $Paths) {
        $cur = $Object; $ok = $true
        foreach ($seg in $p.Split('.')) {
            if ($null -eq $cur) { $ok = $false; break }
            $prop = $cur.PSObject.Properties[$seg]
            if ($null -eq $prop) { $ok = $false; break }
            $cur = $prop.Value
        }
        if ($ok -and $null -ne $cur) { return $cur }
    }
    return $null
}

# Operating systems unambiguously past vendor end of support in 2026.
$EolOsPatterns = @(
    'Windows XP', 'Windows Vista', 'Windows 7', 'Windows 8',
    'Windows Server 2003', 'Windows Server 2008', 'Windows Server 2012'
)
# Windows 10 reached end of support on 2025-10-14 (ESU aside); flag separately.

# =====================================================================
# API key + connection
# =====================================================================
$secureKey = Read-Host -Prompt 'ABR API key (input hidden; never stored)' -AsSecureString
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
try { $plainKey = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }

if (-not $plainKey) { Write-Host 'No API key entered - nothing to do.' -ForegroundColor Yellow; return }

try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
$hdr = @{ apikey = $plainKey }
function Invoke-Abr { param([string]$Path) Invoke-RestMethod -Uri "$ApiBase$Path" -Headers $hdr -Method GET -TimeoutSec 120 }

# Auth probe
try {
    $null = Invoke-Abr '/inventory?take=1'
} catch {
    $code = $null; try { $code = [int]$_.Exception.Response.StatusCode } catch {}
    if ($code -in 401,403) {
        Write-Host "HTTP $code - API key rejected (or wrong data center region)." -ForegroundColor Red
        Write-Host 'Confirm the key is Active and that -ApiBase matches your region (dc1api=EU West, dc2api=US East, ...).' -ForegroundColor DarkGray
    } else {
        Write-Host "Could not reach $ApiBase/inventory: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host 'Check network/proxy to the ABR API host and -ApiBase.' -ForegroundColor DarkGray
    }
    $plainKey = $null; $hdr = $null
    return
}

# =====================================================================
# Pull the full inventory (paged)
# =====================================================================
Write-Host "Scanning ABR tenant via $ApiBase ..." -ForegroundColor Cyan
$devices = New-Object System.Collections.Generic.List[object]
$startId = $null
while ($devices.Count -lt $MaxDevices) {
    $path = "/inventory?take=$PageSize"
    if ($null -ne $startId) { $path += "&startid=$startId" }
    $page = @(Invoke-Abr $path)
    if ($page.Count -eq 0) { break }
    foreach ($d in $page) { $devices.Add($d) }
    $maxId = ($page | ForEach-Object { [int]$_.id } | Measure-Object -Maximum).Maximum
    Write-Host ("  pulled {0} devices..." -f $devices.Count) -ForegroundColor DarkGray
    if ($page.Count -lt $PageSize) { break }
    $startId = $maxId + 1
}
$plainKey = $null; $hdr = $null
$total = $devices.Count
if ($total -eq 0) { Write-Host 'No devices returned from the tenant inventory.' -ForegroundColor Yellow; return }

# Tenant-newest ABR client major.minor (for ABR-05)
$newestMM = $null
foreach ($d in $devices) {
    $vs = Get-Field $d @('abrClientVersion')
    if ($vs) {
        $tok = ("$vs" -split '[ (]')[0]
        try { $v = [version]$tok } catch { $v = $null }
        if ($v) {
            $mm = [version]("{0}.{1}" -f $v.Major, [math]::Max($v.Minor,0))
            if ($null -eq $newestMM -or $mm -gt $newestMM) { $newestMM = $mm }
        }
    }
}

# =====================================================================
# Per-device checks (Inventory-based)
# =====================================================================
$osCount = @{}
foreach ($d in $devices) {
    $name = "$([string](Get-Field $d @('name')))"
    if (-not $name) { $name = "(id $($d.id))" }
    $id = Get-Field $d @('id')

    $osName = "$([string](Get-Field $d @('operatingSystem.name','osName')))"
    if ($osName) { if ($osCount.ContainsKey($osName)) { $osCount[$osName]++ } else { $osCount[$osName] = 1 } }

    $invAvail = Get-Field $d @('inventoryAvailable')
    $invDate  = Get-Field $d @('inventoryDate')

    # ABR-04 Stale or missing inventory ------------------------------
    if ($invAvail -eq $false) {
        Add-Finding 'ABR-04' $name $id 'MEDIUM' 'Agent not reporting inventory' 'inventoryAvailable = false (client metadata only; user/computer/OS/hardware are null).'
    } elseif ($invDate) {
        try {
            $dt = [datetime]$invDate
            if ($dt -lt (Get-Date).AddDays(-$StaleDays)) {
                $days = [int]((Get-Date) - $dt).TotalDays
                Add-Finding 'ABR-04' $name $id 'MEDIUM' 'Stale ABR client' ("Last inventory {0} (~{1} days ago)." -f $dt.ToString('yyyy-MM-dd'), $days)
            }
        } catch {}
    }
    # A device with no inventory is skipped for the hardware/user checks below.
    if ($invAvail -eq $false) { continue }

    # ABR-01 Standing local admins -----------------------------------
    $localAdmins = @(Get-Field $d @('computer.localAdmins'))
    $extra = @()
    foreach ($a in $localAdmins) {
        $s = "$a"
        if ([string]::IsNullOrWhiteSpace($s)) { continue }
        $leaf = ($s -split '\\')[-1]
        if ($leaf -ieq 'Administrator') { continue }                       # built-in local admin
        if ($s -match 'Company Administrators|Device Administrators') { continue }  # default Entra roles
        if ($ApprovedLocalAdmins | Where-Object { $s -ieq $_ -or $leaf -ieq $_ }) { continue }
        $extra += $s
    }
    if ($extra.Count) {
        Add-Finding 'ABR-01' $name $id 'HIGH' 'Standing local administrators' (($extra | Select-Object -Unique) -join ', ')
    }
    $userIsAdmin = Get-Field $d @('user.isAdmin')
    if ($userIsAdmin -eq $true) {
        $acct = "$([string](Get-Field $d @('user.account')))"
        Add-Finding 'ABR-01' $name $id 'HIGH' 'Signed-in user is admin (not revoked)' ($(if ($acct) { $acct } else { 'user shown as admin in inventory' }))
    }

    # ABR-05 Outdated ABR client -------------------------------------
    if ($newestMM) {
        $vs = Get-Field $d @('abrClientVersion')
        if ($vs) {
            $tok = ("$vs" -split '[ (]')[0]
            try { $v = [version]$tok } catch { $v = $null }
            if ($v) {
                $mm = [version]("{0}.{1}" -f $v.Major, [math]::Max($v.Minor,0))
                if ($mm -lt $newestMM) {
                    Add-Finding 'ABR-05' $name $id 'MEDIUM' 'Outdated ABR client' ("Version {0}; tenant newest is {1}.x" -f $tok, $newestMM)
                }
            }
        }
    }

    # ABR-06 BitLocker disabled (Windows only) -----------------------
    $isWin = ($osName -match 'Windows')
    $bl = Get-Field $d @('hardware.bitlockerEnabled','bitlockerEnabled')
    if ($isWin -and $bl -eq $false) {
        Add-Finding 'ABR-06' $name $id 'HIGH' 'BitLocker disabled' 'hardware.bitlockerEnabled = false.'
    }

    # ABR-07 TPM missing or old --------------------------------------
    $tpmEnabled = Get-Field $d @('hardware.tpmEnabled','tpmEnabled')
    $tpmVersion = Get-Field $d @('hardware.tpmVersion','tpmVersion')
    if ($isWin -and $tpmEnabled -eq $false) {
        Add-Finding 'ABR-07' $name $id 'MEDIUM' 'TPM not enabled' 'hardware.tpmEnabled = false.'
    } elseif ($tpmVersion) {
        $tv = $null; try { $tv = [double](("$tpmVersion" -split '[^0-9.]')[0]) } catch {}
        if ($null -ne $tv -and $tv -gt 0 -and $tv -lt 2.0) {
            Add-Finding 'ABR-07' $name $id 'MEDIUM' 'TPM below 2.0' ("tpmVersion = {0}" -f $tpmVersion)
        }
    }

    # ABR-08 Non-compliant device ------------------------------------
    $compliant = Get-Field $d @('hardware.isCompliant','isCompliant')
    if ($compliant -eq $false) {
        Add-Finding 'ABR-08' $name $id 'MEDIUM' 'Device not compliant' 'isCompliant = false.'
    }

    # ABR-09 End-of-life operating system ----------------------------
    if ($osName) {
        $eol = $false
        foreach ($p in $EolOsPatterns) { if ($osName -like "*$p*") { $eol = $true; break } }
        if ($eol) {
            Add-Finding 'ABR-09' $name $id 'HIGH' 'End-of-life operating system' $osName
        } elseif ($osName -match 'Windows 10') {
            Add-Finding 'ABR-09' $name $id 'MEDIUM' 'OS past end of support' ("{0} (Windows 10 end of support 2025-10-14 unless on ESU)." -f $osName)
        }
    }

    # ABR-10 Device without an owner ---------------------------------
    $owner = Get-Field $d @('owner.account','owner')
    if ($null -eq $owner -or "$owner" -eq '') {
        Add-Finding 'ABR-10' $name $id 'LOW' 'Device without an owner' 'owner is null (owner-based policies cannot apply).'
    }
}

# =====================================================================
# OUTPUT
# =====================================================================
$sevOrder = @{ 'CRITICAL'=0; 'HIGH'=1; 'MEDIUM'=2; 'LOW'=3; 'INFO'=4 }
$checkMeta = [ordered]@{
    'ABR-01' = 'Standing local admins'
    'ABR-04' = 'Stale / missing ABR client'
    'ABR-05' = 'Outdated ABR client'
    'ABR-06' = 'BitLocker disabled'
    'ABR-07' = 'TPM missing or old'
    'ABR-08' = 'Device not compliant'
    'ABR-09' = 'End-of-life / unsupported OS'
    'ABR-10' = 'Device without an owner'
}

if ($AsJson) {
    $summary = foreach ($cid in $checkMeta.Keys) {
        $rows = @($findings | Where-Object CheckId -eq $cid)
        [pscustomobject]@{ CheckId = $cid; Check = $checkMeta[$cid]; Affected = $rows.Count }
    }
    $out = [pscustomobject]@{
        ScannedAt = (Get-Date).ToString('u')
        ApiBase   = $ApiBase
        Devices   = $total
        Summary   = $summary
        Findings  = $findings
    }
    $json = $out | ConvertTo-Json -Depth 6
    if ($CsvPath -and -not $NoCsv) { $json | Out-File -FilePath $CsvPath -Encoding UTF8 }
    $json
    return
}

$colors = @{ CRITICAL='Red'; HIGH='Red'; MEDIUM='Yellow'; LOW='Gray'; INFO='Gray' }
Write-Host ''
Write-Host ("=== ABR Tenant Posture Scan ===  {0}  ({1} devices)" -f (Get-Date -Format 'yyyy-MM-dd HH:mm'), $total) -ForegroundColor Cyan
Write-Host ''

$any = $false
foreach ($cid in $checkMeta.Keys) {
    $rows = @($findings | Where-Object CheckId -eq $cid)
    if (-not $rows.Count) { continue }
    $any = $true
    $sev = ($rows | Sort-Object { $sevOrder[$_.Severity] } | Select-Object -First 1).Severity
    Write-Host ("[{0}] {1,-30} {2} device(s)" -f $sev, $checkMeta[$cid], $rows.Count) -ForegroundColor $colors[$sev]
    foreach ($r in ($rows | Select-Object -First 5)) {
        Write-Host ("        {0}  -  {1}" -f $r.Device, $r.Detail) -ForegroundColor DarkGray
    }
    if ($rows.Count -gt 5) { Write-Host ("        ... and {0} more (see the CSV)" -f ($rows.Count - 5)) -ForegroundColor DarkGray }
}
if (-not $any) { Write-Host 'No posture findings. All scanned devices passed the inventory checks.' -ForegroundColor Green }

Write-Host ''
$bySev = $findings | Group-Object Severity | Sort-Object { $sevOrder[$_.Name] } | ForEach-Object { "$($_.Name)=$($_.Count)" }
Write-Host ("Findings: {0}   across {1} devices" -f (($bySev -join '  ')), $total) -ForegroundColor Cyan

# OS spread (coverage context)
if ($osCount.Count) {
    $osTop = $osCount.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 6 |
             ForEach-Object { "$($_.Key): $($_.Value)" }
    Write-Host ("OS spread: {0}" -f ($osTop -join '  |  ')) -ForegroundColor DarkGray
}
Write-Host ''

# CSV
if (-not $NoCsv) {
    if (-not $CsvPath) { $CsvPath = ".\ABR-PostureScan-$(Get-Date -Format 'yyyy-MM-dd').csv" }
    $findings | Sort-Object { $sevOrder[$_.Severity] }, CheckId, Device |
        Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "Saved $($findings.Count) findings to $CsvPath" -ForegroundColor Cyan
    Write-Host ''
}
