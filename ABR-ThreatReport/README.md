# ABR Threat Report

A read-only PowerShell tool that reads the [Admin By Request](https://www.adminbyrequest.com/) Events and Auditlog APIs and writes **one HTML report** of threat detections across your whole tenant: malware, malicious apps that were elevated, clock tampering, break-glass use, local account changes, policy tampering and more.

> Community tool by OnCloud, an Admin By Request partner. Not an official Admin By Request product.

**It changes nothing.** The tool only sends `GET` requests. It never approves or denies requests and never touches ABR settings.

## Run it

```powershell
powershell -ExecutionPolicy Bypass -File .\ABR-ThreatReport.ps1 -Region dc1
```

It asks for your ABR API key (hidden input), reads the last 30 days, writes `ABR-Threat-Report-<date>.html` and opens it.

Want to see the report first, without a key? Run it with sample data:

```powershell
powershell -ExecutionPolicy Bypass -File .\ABR-ThreatReport.ps1 -Sample
```

### Options

| Option | What it does |
|--------|--------------|
| `-Region <dc1..dc6>` | The prefix shown next to your API key in the ABR portal: dc1 EU West, dc2 US East, dc3 UK, dc4 EU Central, dc5 US West, dc6 Asia. Default `dc1`. |
| `-Days <n>` | How far back to look (1 to 365). Default 30. |
| `-OutFile <path>` | Where to write the report. |
| `-BadHashFile <path>` | A text file with one SHA-256 per line (your threat intel or Defender indicators). Turns on T-10. |
| `-MaxPages <n>` | Safety cap on pages per API stream (100 records each). Default 200. |
| `-Sample` | Build the report from made-up sample data, with no key and no network. |

### The API key

- Create a dedicated key in the ABR portal: **Settings > Tenant Settings > API Keys**. Disable it when you're done.
- ABR keys can also approve and deny requests, so treat the key like an admin password. This tool never uses it for that.
- The key is read with a hidden prompt, or from the `ABR_API_KEY` environment variable for scheduled runs. It's never written to disk or to the report.
- ABR allows 100,000 API calls per tenant per day, shared with your other integrations. A 30-day run on a typical tenant uses well under a few hundred. The report shows how many calls it made.

## What it detects

| ID | Detection | Source | Severity |
|----|-----------|--------|----------|
| T-01 | Malware blocked (event 93) | Events | Critical |
| T-02 | Suspected malware blocked (event 94) | Events | High |
| T-03 | Malicious app elevated (non-clean scan result or a named threat) | Auditlog | Critical |
| T-04 | Clock tampering during break-glass or Admin Session (events 73, 91) | Events | Critical |
| T-05 | Break-glass account used (event 72; events 70 and 102 shown as context) | Events | High |
| T-06 | Local account manipulation outside an Admin Session (events 10, 12, 13) | Events + Auditlog | High |
| T-07 | Policy registry tampering (events 20, 21) | Events | High |
| T-08 | Rotating admin logon (event 182) | Events | Medium |
| T-09 | 3 or more blocked executions for one user within an hour (events 92, 124, 131) | Events | Medium |
| T-10 | Known-bad hash, from `-BadHashFile` | Events + Auditlog | Critical |
| T-11 | Remote Kill executed | Not available yet | High |
| T-12 | Elevation during a Remote Kill blackout | Not available yet | High |
| T-13 | Download blocked by the WAM malware scan | Not available yet | Critical |
| T-14 | Sudo tamper or bypass on macOS | Not available yet | Critical |

T-11 to T-14 are listed but show **Not available**: ABR logs these features (Windows 9.0, macOS 6.0) but hasn't published their event or audit codes yet. They'll be added once the codes are known.

## The report

- A verdict at the top and a count of Critical, High and Medium detections
- One card per detection, open when something was found: why it matters, what to do, and every hit (time, device, user, detail, with a link to the ABR audit record where ABR provides one)
- A single HTML file with no external files, so it can be sent as is. It contains device and user names, so share it accordingly.

## Notes and limits

- Scan results: ABR doesn't document all `scanResultCode` values. T-03 treats a named threat, or a scan result that says malicious, suspicious or infected, as not clean.
- T-06 treats any Auditlog entry whose type contains "Session" as an Admin Session window on that device.
- If ABR ignores the date filter on your tenant, the tool still filters by date itself, but it may need more pages. Raise `-MaxPages` if the report notes it stopped early.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7
- Network access to your ABR API region

## License

[MIT](../LICENSE) © OnCloud Ltd. Provided as is, without warranty of any kind.
