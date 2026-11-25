# ABR Tenant Posture Scan

A read-only PowerShell scan across your **whole** [Admin By Request](https://www.adminbyrequest.com/) tenant. It reads the ABR Inventory API and reports the endpoints with weak posture, prints a grouped summary by severity, and writes a CSV you can hand to the customer.

> Community tool by OnCloud, an Admin By Request partner. Not an official Admin By Request product.

This is the tenant-wide companion to [ABR EPM Endpoint Health Check](../ABR-EPM-HealthCheck/), which checks a single endpoint from the inside. Use the health check to fix one machine; use this to find the machines that need looking at.

**It changes nothing.** The script only calls `GET /inventory`. It never approves, denies or changes anything in ABR.

## Run it

Run it as an **ABR admin**, on any machine with network access to the ABR API.

```powershell
powershell -ExecutionPolicy Bypass -File .\ABR-Tenant-PostureScan.ps1
```

It asks for your ABR API key with a hidden prompt, pulls the tenant inventory, prints the findings, and saves a CSV next to the script.

`-ExecutionPolicy Bypass` applies to this one run only, because the script isn't code-signed. Read the script before you run it.

### The API key: admins only

The ABR API key gives read access to your **whole** ABR tenant. So:

- **Only an ABR admin should run this.** Never give an API key to an end user, and never send one by email or chat.
- The script asks for the key with a hidden prompt. It isn't passed on the command line, so it doesn't land in PowerShell history, and it's never written to disk or to the report.
- Use a dedicated, read-only API key, and disable it when you're done.

Find or create the key in the ABR portal under **Settings > Tenant Settings > API Keys**. The portal shows your region prefix next to the key.

### Region

Pass `-ApiBase` for your tenant's region (the prefix shown next to your API key). A wrong region returns an error.

| Region | `-ApiBase` |
|--------|-----------|
| EU West (Netherlands) | `https://dc1api.adminbyrequest.com` (default) |
| US East (Virginia) | `https://dc2api.adminbyrequest.com` |
| UK (London) | `https://dc3api.adminbyrequest.com` |
| EU Central (Germany) | `https://dc4api.adminbyrequest.com` |
| US West (California) | `https://dc5api.adminbyrequest.com` |
| Asia (Singapore) | `https://dc6api.adminbyrequest.com` |

### Options

| Option | What it does |
|--------|--------------|
| `-ApiBase <url>` | API prefix for your region (see the table above). Default EU West. |
| `-ApprovedLocalAdmins <a,b>` | Account or group names allowed in local Administrators (break-glass, LAPS). The built-in `Administrator` and the two default Entra roles are always allowed. |
| `-StaleDays <n>` | Flag a device that hasn't reported in more than N days. Default 14. |
| `-CsvPath <path>` | Where to write the CSV. Default `.\ABR-PostureScan-<date>.csv`. |
| `-NoCsv` | Don't write a CSV. |
| `-AsJson` | Print findings and summary as JSON (for another tool to consume). |
| `-PageSize <n>` | Devices per API page. Default 500. |
| `-MaxDevices <n>` | Safety cap on devices scanned. Default 100000. |

## What it checks

Every check reads documented ABR Inventory fields. A device is flagged only when the field explicitly reports a problem; a missing or null field is skipped, not flagged.

| ID | Check | Flags | Severity |
|----|-------|-------|----------|
| ABR-01 | Standing local admins | Accounts or groups in `computer.localAdmins` beyond the built-in Administrator / break-glass, or the signed-in user shown as admin. Default Entra admin roles are ignored. | High |
| ABR-04 | Stale / missing ABR client | `inventoryAvailable = false`, or last inventory older than `-StaleDays`. | Medium |
| ABR-05 | Outdated ABR client | Client version a full release behind the newest version seen in the tenant. | Medium |
| ABR-06 | BitLocker disabled | `bitlockerEnabled = false` on Windows. | High |
| ABR-07 | TPM missing or old | `tpmEnabled = false`, or `tpmVersion` below 2.0. | Medium |
| ABR-08 | Device not compliant | `isCompliant = false`. | Medium |
| ABR-09 | End-of-life / unsupported OS | OS past vendor end of support (Windows 7/8, Server 2012 and older; Windows 10 flagged as past end of support). | High / Medium |
| ABR-10 | Device without an owner | `owner` is null, so owner-based policies can't apply. | Low |

The output groups findings by check, shows the first few affected devices for each, and writes every finding to the CSV (one row per device per finding).

## Sample output

```text
=== ABR Tenant Posture Scan ===  2026-11-25 11:20  (342 devices)

[HIGH]   Standing local admins          7 device(s)
        FIN-LT-014  -  CONTOSO\j.levi
        ENG-WS-233  -  Domain Admins
        ... and 5 more (see the CSV)
[HIGH]   BitLocker disabled             3 device(s)
        RECEPTION-01  -  hardware.bitlockerEnabled = false.
[MEDIUM] Outdated ABR client            19 device(s)
        ...
[MEDIUM] Device not compliant           12 device(s)
[LOW]    Device without an owner        5 device(s)

Findings: HIGH=10  MEDIUM=31  LOW=5   across 342 devices
OS spread: Windows 11 Pro: 201  |  Windows 10 Pro: 118  |  Windows Server 2022: 12
Saved 46 findings to .\ABR-PostureScan-2026-11-25.csv
```

## Requirements

- Windows PowerShell 5.1 (built in) or PowerShell 7
- Network access to your region's ABR API host
- A read-only ABR API key
- No modules to install

## Feedback

Found a bug or a false result? Open an [issue](../../../issues). Security problems: see [SECURITY.md](../SECURITY.md).

## License

[MIT](../LICENSE) © OnCloud Ltd. Provided as is, without warranty of any kind.
