<#
=====================================================================
 Admin By Request (ABR) - Threat Report   v1.0
=====================================================================
 Copyright (c) 2026 OnCloud Ltd. MIT License (see LICENSE in the repo root).
 https://github.com/oncloud-public/adminbyrequest-tools

 Community tool by OnCloud, an Admin By Request partner.
 Not an official Admin By Request product.

 Reads the ABR Events and Auditlog APIs for a time window and writes
 one self-contained HTML report of threat detections T-01 to T-14.
 READ-ONLY: it only sends GET requests and never approves, denies or
 changes anything in ABR.

 USAGE
   powershell -ExecutionPolicy Bypass -File .\ABR-ThreatReport.ps1 -Region dc1
   Options:
     -Region <dc1..dc6>   The prefix shown next to your API key in the ABR portal
                          (dc1 EU West, dc2 US East, dc3 UK, dc4 EU Central,
                          dc5 US West, dc6 Asia). Default dc1.
     -Days <n>            How far back to look. Default 30.
     -OutFile <path>      Where to write the HTML report.
                          Default .\ABR-Threat-Report-<date>.html
     -BadHashFile <path>  Optional text file with one SHA-256 per line (your threat
                          intel or Defender indicators) for T-10.
     -MaxPages <n>        Safety cap on pages per API stream (100 records each).
                          Default 200.
     -Sample              Build the report from made-up sample data (no API key,
                          no network) to see what it looks like.
   The API key is asked for with a hidden prompt (or read from the
   ABR_API_KEY environment variable). It is never written to disk or
   to the report. Use a dedicated key and disable it when you're done.
=====================================================================
#>

[CmdletBinding()]
param(
    [ValidateSet('dc1','dc2','dc3','dc4','dc5','dc6')][string]$Region = 'dc1',
    [ValidateRange(1,365)][int]$Days = 30,
    [string]$OutFile = (Join-Path (Get-Location) ("ABR-Threat-Report-{0}.html" -f (Get-Date -Format 'yyyyMMdd-HHmm'))),
    [string]$BadHashFile,
    [int]$Take = 100,
    [int]$MaxPages = 200,
    [switch]$Sample
)

$ErrorActionPreference = 'Stop'
$ApiBase  = "https://$($Region)api.adminbyrequest.com"
$Since    = (Get-Date).ToUniversalTime().AddDays(-$Days)
$script:Calls = 0
$script:Notes = New-Object System.Collections.Generic.List[string]

# ---------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------
function Get-Prop { param($Obj, [string]$Path)
    # Safe nested read: Get-Prop $x 'application.sha256'
    $cur = $Obj
    foreach ($p in $Path.Split('.')) { if ($null -eq $cur) { return $null }; $cur = $cur.$p }
    return $cur
}

function ConvertTo-Utc { param($Value)
    if (-not $Value) { return $null }
    try { return ([datetime]::Parse("$Value", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal)) } catch { return $null }
}

function Invoke-Abr { param([string]$Path, [hashtable]$Query)
    $qs = ($Query.GetEnumerator() | ForEach-Object { '{0}={1}' -f $_.Key, [uri]::EscapeDataString("$($_.Value)") }) -join '&'
    $uri = "$ApiBase$Path" + $(if ($qs) { "?$qs" } else { '' })
    $script:Calls++
    $attempt = 0
    while ($true) {
        try { return Invoke-RestMethod -Uri $uri -Headers @{ apikey = $script:ApiKey } -Method GET -TimeoutSec 60 }
        catch {
            $code = $null; try { $code = [int]$_.Exception.Response.StatusCode } catch {}
            if ($code -in 401,403) { throw "The API key was rejected (HTTP $code). Check that it is Active and that -Region ($Region) matches the prefix shown next to the key." }
            if (($code -eq 429 -or $code -ge 500) -and $attempt -lt 4) { $attempt++; Start-Sleep -Seconds ([math]::Pow(2,$attempt) * 5); continue }
            throw
        }
    }
}

function Get-AbrPaged { param([string]$Path, [hashtable]$Query, [string]$TimeField, [string]$Label)
    # Pages by id (startid = last id + 1) until a short page, the cap, or nothing newer.
    $all = New-Object System.Collections.Generic.List[object]
    $startId = 0; $pages = 0
    while ($true) {
        $q = @{} + $Query; $q.take = $Take; $q.startid = $startId
        $page = @(Invoke-Abr $Path $q)
        $pages++
        if ($page.Count -eq 0) { break }
        foreach ($r in $page) {
            $t = ConvertTo-Utc (Get-Prop $r $TimeField)
            if ($t -and $t -ge $Since) { $all.Add($r) }
        }
        $maxId = ($page | ForEach-Object { [long]$_.id } | Measure-Object -Maximum).Maximum
        $startId = $maxId + 1
        if ($page.Count -lt $Take) { break }
        if ($pages -ge $MaxPages) { $script:Notes.Add("$Label stopped at $MaxPages pages; raise -MaxPages if results look incomplete."); break }
    }
    return ,$all
}

function New-Finding { param($Id, $Name, $Severity, $Why, $Fix)
    [pscustomobject]@{ Id=$Id; Name=$Name; Severity=$Severity; Why=$Why; Fix=$Fix; Status='Clear'; Rows=(New-Object System.Collections.Generic.List[object]) }
}
function Add-Row { param($Finding, $Time, $Device, $User, $Detail, $Link)
    $Finding.Rows.Add([pscustomobject]@{ Time=$Time; Device=$Device; User=$User; Detail=$Detail; Link=$Link })
    $Finding.Status = 'Detected'
}
function Get-AppText { param($App)
    if (-not $App) { return '' }
    $n = @($App.file, $App.name) | Where-Object { $_ } | Select-Object -First 1
    $v = if ($App.vendor) { " ($($App.vendor))" } else { '' }
    return "$n$v"
}

# ---------------------------------------------------------------------
# data
# ---------------------------------------------------------------------
$EventCodes = 93,94,73,91,72,70,102,10,12,13,20,21,182,92,124,131

if ($Sample) {
    $now = (Get-Date).ToUniversalTime()
    function New-SampleEvent($id,$code,$h,$dev,$usr,$file,$text,$sha) { [pscustomobject]@{ id=$id; eventCode=$code; eventText=$text; eventTimeUTC=$now.AddHours(-$h).ToString('o'); computerName=$dev; userAccount=$usr; application=[pscustomobject]@{ file=$file; vendor=$null; sha256=$sha } } }
    $events = @(
        (New-SampleEvent 1 93 30 'WIN-SALES-07' 'CONTOSO\dana' 'invoice_viewer.exe' 'Blocked: detected malware' 'aa11')
        (New-SampleEvent 2 94 52 'WIN-FIN-02' 'CONTOSO\omer' 'setup_tool.exe' 'Blocked: suspected malware' 'bb22')
        (New-SampleEvent 3 72 70 'WIN-IT-01' 'WIN-IT-01\ABR-BreakGlass' '' 'Break glass account logged on' '')
        (New-SampleEvent 4 13 90 'WIN-HR-05' 'CONTOSO\maya' '' 'Local user created: support2' '')
        (New-SampleEvent 5 92 5.0 'WIN-DEV-11' 'CONTOSO\noa' 'nc.exe' 'Execution blocked' 'cc33')
        (New-SampleEvent 6 92 4.8 'WIN-DEV-11' 'CONTOSO\noa' 'psexec.exe' 'Execution blocked' 'dd44')
        (New-SampleEvent 7 131 4.6 'WIN-DEV-11' 'CONTOSO\noa' 'mimikatz.exe' 'Execution blocked' 'ee55')
    )
    $audit = @(
        [pscustomobject]@{ id=11; type='Run As Admin'; requestTimeUTC=$now.AddHours(-20).ToString('o'); startTimeUTC=$now.AddHours(-20).ToString('o'); endTimeUTC=$now.AddHours(-20).ToString('o'); user=[pscustomobject]@{account='CONTOSO\dana'}; computer=[pscustomobject]@{name='WIN-SALES-07'}; application=[pscustomobject]@{ file='pdfconvert.exe'; vendor=$null; scanResult='Malicious (3 engines)'; scanResultCode=2; threat='Trojan:Win32/Wacatac'; sha256='ff66' }; auditlogLink='https://www.adminbyrequest.com/' }
    )
    $script:ApiBase = 'SAMPLE DATA'
} else {
    $sec = $null
    if ($env:ABR_API_KEY) { $script:ApiKey = $env:ABR_API_KEY }
    else {
        $sec = Read-Host -Prompt 'ABR API key (input hidden; never stored)' -AsSecureString
        $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
        try { $script:ApiKey = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
    }
    if (-not $script:ApiKey) { throw 'No API key entered.' }
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

    Write-Host "Connecting to $ApiBase ..." -ForegroundColor Cyan
    $null = Invoke-Abr '/events' @{ take = 1 }   # fails fast on a bad key / region

    $startDate = $Since.ToString('yyyy-MM-dd')
    $events = New-Object System.Collections.Generic.List[object]
    foreach ($c in $EventCodes) {
        Write-Host "  Events code $c ..." -NoNewline
        $got = Get-AbrPaged '/events' @{ code = $c; startdate = $startDate } 'eventTimeUTC' "Events code $c"
        # Keep only the requested code, in case the API ignored the filter.
        $got = @($got | Where-Object { [int]$_.eventCode -eq $c })
        $got | ForEach-Object { $events.Add($_) }
        Write-Host " $($got.Count)"
    }
    Write-Host "  Auditlog ..." -NoNewline
    $audit = Get-AbrPaged '/auditlog' @{ startdate = $startDate; wantscandetails = 1 } 'requestTimeUTC' 'Auditlog'
    Write-Host " $($audit.Count)"
    $script:ApiKey = $null
}

$badHashes = @{}
if ($BadHashFile) {
    Get-Content -LiteralPath $BadHashFile | ForEach-Object { $h = $_.Trim().ToLower(); if ($h -match '^[0-9a-f]{64}$') { $badHashes[$h] = $true } }
}

# ---------------------------------------------------------------------
# detections
# ---------------------------------------------------------------------
$F = [ordered]@{}
$F['T-01'] = New-Finding 'T-01' 'Malware blocked' 'Critical' 'ABR blocked a file its scan engines flagged as malware (event 93). The file reached the device, so find where it came from.' 'Isolate the device in Defender, run a full scan, and trace the file to its source (email, download, USB). Check other devices for the same file.'
$F['T-02'] = New-Finding 'T-02' 'Suspected malware blocked' 'High' 'ABR blocked a file some engines flagged as suspicious (event 94).' 'Review the file and its source; submit it to Microsoft Defender for analysis; keep it blocked until cleared.'
$F['T-03'] = New-Finding 'T-03' 'Malicious app elevated' 'Critical' 'An application with a non-clean scan result or a named threat ran with admin rights (Auditlog).' 'Treat as an incident: isolate the device, review what the app installed or changed, and reset the user''s credentials.'
$F['T-04'] = New-Finding 'T-04' 'Clock tampering' 'Critical' 'The system clock was changed during a break-glass or Admin Session (events 73, 91) - a common way to stretch elevated time.' 'Investigate the user and device now; end any open sessions and review what ran with admin rights.'
$F['T-05'] = New-Finding 'T-05' 'Break-glass account used' 'High' 'A break-glass account logged on (event 72). Events 70 / 102 (created / issued) are listed for context.' 'Confirm with the person who requested it; review what was done; make sure the account was rotated afterwards.'
$F['T-06'] = New-Finding 'T-06' 'Local account manipulation' 'High' 'A local password was changed or a local user was enabled or created (events 10, 12, 13) outside any Admin Session on that device.' 'Confirm who made the change and why; disable unknown local accounts; use LAPS for local admin passwords.'
$F['T-07'] = New-Finding 'T-07' 'Policy registry tampering' 'High' 'ABR policy keys in the registry were changed (events 20, 21), overruling the portal settings.' 'Check whether a GPO or a person set them; remove unauthorized keys so the portal settings apply again.'
$F['T-08'] = New-Finding 'T-08' 'Rotating admin logon' 'Medium' 'A rotating admin account logged on (event 182).' 'Confirm the logon was planned and matches a ticket.'
$F['T-09'] = New-Finding 'T-09' 'Repeated blocked executions' 'Medium' 'One user hit 3 or more blocked executions within an hour (events 92, 124, 131) - someone trying tools that policy stops.' 'Talk to the user; check the device for malware or a compromised account.'
$F['T-10'] = New-Finding 'T-10' 'Known-bad hash' 'Critical' 'A file hash seen in ABR matches your threat intel list (-BadHashFile).' 'Isolate the device and remove the file; hunt for the same hash across the fleet.'
$F['T-11'] = New-Finding 'T-11' 'Remote Kill executed' 'High' 'An admin ended a user''s elevated session from the portal.' ''
$F['T-12'] = New-Finding 'T-12' 'Elevation during a Remote Kill blackout' 'High' 'The user tried to elevate again while blocked after a Remote Kill.' ''
$F['T-13'] = New-Finding 'T-13' 'Download blocked by the WAM malware scan' 'Critical' 'Web Access Management blocked or quarantined a download.' ''
$F['T-14'] = New-Finding 'T-14' 'Sudo tamper or bypass on macOS' 'Critical' 'Someone tried to tamper with or bypass Managed Sudo.' ''

foreach ($k in 'T-11','T-12','T-13','T-14') {
    $F[$k].Status = 'Not available'
    $F[$k].Fix = 'ABR logs this (Windows 9.0 / macOS 6.0) but has not published the event or audit codes yet, so this report cannot detect it. Check the ABR portal directly.'
}

# Admin Session windows per device (for T-06)
$sessions = @{}
foreach ($a in $audit) {
    if ("$($a.type)" -match 'Session') {
        $dev = "$(Get-Prop $a 'computer.name')".ToUpper()
        $s = ConvertTo-Utc $a.startTimeUTC; $e = ConvertTo-Utc $a.endTimeUTC
        if ($dev -and $s) { if (-not $e) { $e = $s.AddHours(8) }; if (-not $sessions[$dev]) { $sessions[$dev] = @() }; $sessions[$dev] += ,@($s, $e) }
    }
}
function Test-InSession { param($Dev, $Time)
    $list = $sessions["$Dev".ToUpper()]
    if (-not $list -or -not $Time) { return $false }
    foreach ($w in $list) { if ($Time -ge $w[0] -and $Time -le $w[1]) { return $true } }
    return $false
}

$blocked = New-Object System.Collections.Generic.List[object]
foreach ($e in $events) {
    $code = [int]$e.eventCode
    $t    = ConvertTo-Utc $e.eventTimeUTC
    $dev  = $e.computerName; $usr = $e.userAccount
    $app  = Get-AppText $e.application
    $txt  = (@($e.eventText, $app) | Where-Object { $_ }) -join ' - '
    switch ($code) {
        93  { Add-Row $F['T-01'] $t $dev $usr $txt $null }
        94  { Add-Row $F['T-02'] $t $dev $usr $txt $null }
        { $_ -in 73,91 } { Add-Row $F['T-04'] $t $dev $usr "Event $code - $txt" $null }
        72  { Add-Row $F['T-05'] $t $dev $usr $txt $null }
        { $_ -in 70,102 } { $F['T-05'].Rows.Add([pscustomobject]@{ Time=$t; Device=$dev; User=$usr; Detail="Context: event $code - $txt"; Link=$null }) }   # context only, does not raise T-05
        { $_ -in 10,12,13 } { if (-not (Test-InSession $dev $t)) { Add-Row $F['T-06'] $t $dev $usr "Event $code - $txt" $null } }
        { $_ -in 20,21 } { Add-Row $F['T-07'] $t $dev $usr "Event $code - $txt" $null }
        182 { Add-Row $F['T-08'] $t $dev $usr $txt $null }
        { $_ -in 92,124,131 } { $blocked.Add([pscustomobject]@{ Time=$t; Device=$dev; User=$usr; Detail="Event $code - $txt" }) }
    }
    $sha = "$(Get-Prop $e 'application.sha256')".ToLower()
    if ($sha -and $badHashes[$sha]) { Add-Row $F['T-10'] $t $dev $usr "$app - $sha" $null }
}

# T-09: 3+ blocked executions for one user inside any 1-hour window
foreach ($g in ($blocked | Where-Object { $_.User -and $_.Time } | Group-Object User)) {
    $list = @($g.Group | Sort-Object Time)
    for ($i = 0; $i -le $list.Count - 3; $i++) {
        if (($list[$i+2].Time - $list[$i].Time).TotalMinutes -le 60) {
            $j = $i; while ($j + 1 -lt $list.Count -and ($list[$j+1].Time - $list[$i].Time).TotalMinutes -le 60) { $j++ }
            $burst = $list[$i..$j]
            Add-Row $F['T-09'] $burst[0].Time $burst[0].Device $g.Name ("{0} blocked in {1:N0} min: {2}" -f $burst.Count, ($burst[-1].Time - $burst[0].Time).TotalMinutes, (($burst | ForEach-Object { $_.Detail }) -join '; '))
            $i = $j
        }
    }
}

# T-03 and T-10 from the Auditlog
function Test-NotClean { param($App)
    if (-not $App) { return $false }
    if ($App.threat) { return $true }
    $sr = "$($App.scanResult)"; $code = $App.scanResultCode
    if ($sr -match 'malicious|suspicious|threat|infected|malware') { return $true }
    if ($null -ne $code -and "$code" -ne '' -and "$code" -ne '0' -and $sr -notmatch 'clean|no threat|not scanned|unknown') { return $true }
    return $false
}
foreach ($a in $audit) {
    $t = ConvertTo-Utc $a.requestTimeUTC
    $dev = Get-Prop $a 'computer.name'; $usr = Get-Prop $a 'user.account'
    $link = @($a.auditlogLink, $a.auditLogURL) | Where-Object { $_ } | Select-Object -First 1
    $apps = @($a.application) + @($a.elevatedApplications) | Where-Object { $_ }
    foreach ($app in $apps) {
        if (Test-NotClean $app) {
            $d = (Get-AppText $app) + $(if ($app.threat) { " - threat: $($app.threat)" } elseif ($app.scanResult) { " - scan: $($app.scanResult)" } else { " - scan code $($app.scanResultCode)" })
            Add-Row $F['T-03'] $t $dev $usr $d $link
        }
        $sha = "$($app.sha256)".ToLower()
        if ($sha -and $badHashes[$sha]) { Add-Row $F['T-10'] $t $dev $usr ((Get-AppText $app) + " - $sha") $link }
    }
}
if (-not $BadHashFile) { $F['T-10'].Status = 'Not run'; $F['T-10'].Fix = 'Run again with -BadHashFile <file with one SHA-256 per line> to check hashes against your threat intel.' }

# ---------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------
function Enc { param($s) [System.Net.WebUtility]::HtmlEncode("$s") }
$sevRank = @{ Critical = 0; High = 1; Medium = 2; Low = 3 }
$stRank  = @{ Detected = 0; Clear = 1; 'Not run' = 2; 'Not available' = 3 }
$list = @($F.Values | Sort-Object @{e={$stRank[$_.Status]}}, @{e={$sevRank[$_.Severity]}}, Id)

$det   = @($list | Where-Object Status -eq 'Detected')
$crit  = @($det | Where-Object Severity -eq 'Critical').Count
$high  = @($det | Where-Object Severity -eq 'High').Count
$med   = @($det | Where-Object Severity -eq 'Medium').Count
$clear = @($list | Where-Object Status -eq 'Clear').Count
$na    = @($list | Where-Object { $_.Status -in 'Not run','Not available' }).Count
$verdict = if ($crit) { 'Critical threats found' } elseif ($high) { 'High-severity threats found' } elseif ($med) { 'Items to review' } else { 'No threats detected' }
$vclass  = if ($crit) { 'crit' } elseif ($high) { 'high' } elseif ($med) { 'med' } else { 'ok' }

$sb = New-Object System.Text.StringBuilder
foreach ($f in $list) {
    $sev = $f.Severity.ToLower(); $st = ($f.Status -replace ' ', '-').ToLower()
    [void]$sb.Append("<details class='card st-$st'" + $(if ($f.Status -eq 'Detected') { ' open' } else { '' }) + "><summary>")
    [void]$sb.Append("<span class='id'>$(Enc $f.Id)</span><span class='name'>$(Enc $f.Name)</span>")
    [void]$sb.Append("<span class='sev sev-$sev'>$(Enc $f.Severity)</span>")
    $cnt = if ($f.Status -eq 'Detected') { "$(@($f.Rows | Where-Object { $_.Detail -notlike 'Context:*' }).Count) found" } else { $f.Status }
    [void]$sb.Append("<span class='st'>$(Enc $cnt)</span></summary><div class='body'>")
    [void]$sb.Append("<p>$(Enc $f.Why)</p>")
    if ($f.Fix) { [void]$sb.Append("<p class='fix'><b>What to do:</b> $(Enc $f.Fix)</p>") }
    if ($f.Rows.Count) {
        [void]$sb.Append("<div class='tw'><table><thead><tr><th>Time (UTC)</th><th>Device</th><th>User</th><th>Detail</th></tr></thead><tbody>")
        foreach ($r in ($f.Rows | Sort-Object Time -Descending)) {
            $tt = if ($r.Time) { ([datetime]$r.Time).ToString('yyyy-MM-dd HH:mm') } else { '' }
            $detail = Enc $r.Detail
            if ($r.Link -and "$($r.Link)" -match '^https://') { $detail += " <a href='$(Enc $r.Link)' target='_blank' rel='noopener'>ABR record</a>" }
            [void]$sb.Append("<tr><td>$tt</td><td>$(Enc $r.Device)</td><td>$(Enc $r.User)</td><td>$detail</td></tr>")
        }
        [void]$sb.Append("</tbody></table></div>")
    }
    [void]$sb.Append("</div></details>")
}
$notesHtml = if ($script:Notes.Count) { '<ul class="notes">' + (($script:Notes | ForEach-Object { "<li>$(Enc $_)</li>" }) -join '') + '</ul>' } else { '' }
$sampleBanner = if ($Sample) { "<div class='banner'>SAMPLE DATA - made-up records to show the report layout. Not from any tenant.</div>" } else { '' }

$html = @"
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ABR Threat Report</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--text:#1b1f24;--muted:#5d6670;--line:#e2e5e9;--crit:#c62828;--high:#e8590c;--med:#b7791f;--ok:#2e7d32;--na:#8a929b;--accent:#f5b800}
@media (prefers-color-scheme:dark){:root{--bg:#121417;--card:#1b1e22;--text:#e8eaed;--muted:#9aa3ad;--line:#2c3137;--crit:#ef5350;--high:#ff8a3d;--med:#e0b04a;--ok:#66bb6a;--na:#7d858e}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 -apple-system,Segoe UI,Roboto,Arial,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:1.6rem;margin:0 0 4px}.meta{color:var(--muted);font-size:.9rem;margin-bottom:20px}
.banner{background:var(--accent);color:#1b1f24;font-weight:600;padding:8px 12px;border-radius:8px;margin-bottom:16px}
.verdict{border-left:6px solid var(--ok);background:var(--card);padding:14px 16px;border-radius:8px;font-size:1.2rem;font-weight:600;margin-bottom:16px}
.verdict.crit{border-color:var(--crit)}.verdict.high{border-color:var(--high)}.verdict.med{border-color:var(--med)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:24px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px}.tile b{display:block;font-size:1.6rem}
.tile.crit b{color:var(--crit)}.tile.high b{color:var(--high)}.tile.med b{color:var(--med)}.tile.ok b{color:var(--ok)}.tile.na b{color:var(--na)}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;margin-bottom:10px}
.card summary{display:flex;gap:12px;align-items:center;padding:12px 14px;cursor:pointer;list-style:none;flex-wrap:wrap}
.card summary::-webkit-details-marker{display:none}
.id{font-family:Consolas,monospace;color:var(--muted);min-width:44px}.name{font-weight:600;flex:1;min-width:180px}
.sev{font-size:.78rem;font-weight:700;padding:2px 8px;border-radius:99px;color:#fff}
.sev-critical{background:var(--crit)}.sev-high{background:var(--high)}.sev-medium{background:var(--med)}.sev-low{background:var(--na)}
.st{font-size:.85rem;color:var(--muted);min-width:90px;text-align:right}
.st-detected{border-left:4px solid var(--crit)}.st-detected .st{color:var(--text);font-weight:600}
.st-clear{border-left:4px solid var(--ok)}.st-not-run,.st-not-available{border-left:4px solid var(--na);opacity:.85}
.body{padding:0 14px 14px}.body p{margin:6px 0}.fix{color:var(--muted)}
.tw{overflow-x:auto;margin-top:8px}table{border-collapse:collapse;width:100%;font-size:.88rem}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:600;white-space:nowrap}
td:first-child{white-space:nowrap}a{color:inherit}
.notes{color:var(--muted);font-size:.85rem}footer{color:var(--muted);font-size:.8rem;margin-top:28px}
</style></head><body><div class="wrap">
$sampleBanner
<h1>Admin By Request - Threat Report</h1>
<div class="meta">Last $Days days (since $($Since.ToString('yyyy-MM-dd')) UTC) &middot; generated $((Get-Date).ToString('yyyy-MM-dd HH:mm')) &middot; source $(Enc $ApiBase) &middot; $($events.Count) events and $($audit.Count) audit records read &middot; $script:Calls API calls</div>
<div class="verdict $vclass">$(Enc $verdict)</div>
<div class="tiles">
<div class="tile crit"><b>$crit</b>Critical detected</div>
<div class="tile high"><b>$high</b>High detected</div>
<div class="tile med"><b>$med</b>Medium detected</div>
<div class="tile ok"><b>$clear</b>Clear</div>
<div class="tile na"><b>$na</b>Not run / not available</div>
</div>
$($sb.ToString())
$notesHtml
<footer>Read-only report built from the Admin By Request Events and Auditlog APIs. Community tool by OnCloud, an Admin By Request partner; not an official Admin By Request product. https://github.com/oncloud-public/adminbyrequest-tools</footer>
</div></body></html>
"@

$html | Out-File -FilePath $OutFile -Encoding UTF8
Write-Host ""
Write-Host "$verdict  (Critical $crit, High $high, Medium $med, Clear $clear)" -ForegroundColor $(if ($crit -or $high) { 'Red' } elseif ($med) { 'Yellow' } else { 'Green' })
Write-Host "Report: $OutFile" -ForegroundColor Cyan
try { if (-not $env:ABR_NO_OPEN) { Start-Process $OutFile } } catch {}
