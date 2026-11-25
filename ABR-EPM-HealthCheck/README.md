# ABR EPM Endpoint Health Check (Windows)

A read-only PowerShell health check for Windows endpoints running [Admin By Request](https://www.adminbyrequest.com/) Endpoint Privilege Management (EPM). It finds the handful of known issues that break ABR on an endpoint and prints **PASS / WARN / FAIL / INFO** for each check, with the fix next to every problem.

> Community tool by OnCloud, an Admin By Request partner. Not an official Admin By Request product.

**It changes nothing.** The script only reads services, drivers, registry values, files, group membership and network reachability. Optionally, with `-UseApi`, it also reads the ABR portal.

## Run it

Copy `ABR-EPM-HealthCheck.ps1` to the endpoint and run it **as the signed-in end user, in a normal (non-elevated) PowerShell**. That's what lets it judge the user's rights correctly.

```powershell
powershell -ExecutionPolicy Bypass -File .\ABR-EPM-HealthCheck.ps1
```

As a standard user, a few items show as INFO instead of PASS (for example, ABR protects its own files, so they can't be read). That's expected. An admin can re-run the script elevated to verify those items; the local-admin check is skipped in an elevated run.

`-ExecutionPolicy Bypass` applies to this one run only, because the script isn't code-signed. Read the script before you run it.

### Options

| Option | What it does |
|--------|--------------|
| `-IncludeSRA` | Adds Secure Remote Access checks: `messagebus.exe`, MQTT (8883), Cloudflare tunnel (7844), RDP for unattended access, supported version, decrypting proxy. |
| `-IncludeWAM` | Adds Web Access Management checks: installed apps that WAM's TLS inspection commonly breaks. |
| `-UseApi` | Cross-checks **this device** against the ABR portal: is it registered, when it last reported, does the version match, does the portal see the user as admin. Prompts for an API key (see below). |
| `-ApiBase <url>` | ABR API prefix. Default `https://dc1api.adminbyrequest.com` (EU). US: `https://dc2api.adminbyrequest.com`. |
| `-StaleDays <n>` | Warn if the device hasn't reported to the portal in more than N days. Default 7. |
| `-MinAbrVersion <v>` | Lowest ABR for Windows version you support. Default `8.4.2.0`. |
| `-AsJson` | Print the results as JSON (for another tool to consume). |
| `-OutFile <path>` | Also save the report (text, or JSON with `-AsJson`) to a file. |

Only use `-IncludeSRA` / `-IncludeWAM` on endpoints that have those add-ons, or those checks will warn.

### The API key (`-UseApi`): admins only

The ABR API key gives read access to your **whole** ABR tenant. So:

- **Only an ABR admin should run `-UseApi`.** Never give an API key to an end user, and never send one by email or chat.
- The script asks for the key with a hidden prompt. It isn't passed on the command line, so it doesn't end up in PowerShell history, and it's never written to disk or to the report.
- To find this device, the script reads the portal inventory (up to 5,000 devices) in memory, keeps only this device's record and reports only on it.
- Use a dedicated, read-only API key, and disable it when you're done.

To check the user's rights correctly and also use the API, run the script twice: once as the end user without `-UseApi`, and once as an admin with `-UseApi` on the same machine.

## What it checks

**Core (EPM), always:**

- ABR is installed, on a supported version, and installed only once (duplicates cause MSI 1603 loops)
- ABR service and tray process are running, and the **elevation driver is loaded** (without it, elevations fall back to native Windows UAC)
- **The signed-in user is not a local admin**, including through a nested group, and isn't in any "problem group" (Power Users, Network Configuration Operators, Group Policy Creator Owners, domain admin groups)
- Broad or privileged groups sitting in local Administrators
- **Secondary Logon (seclogon)** is enabled (needed for Support Assist)
- Known conflicting AV/EDR products, and whether Microsoft Defender for Endpoint is present
- ABR core files are present and digitally signed
- ABR portal is reachable (api.adminbyrequest.com:443), so approvals don't fall back to offline PIN
- Windows build and MSI SecureRepair policy, pending reboot, DebugMode left on, auto-update override, and elevation mode (Confirmation vs Authentication)

**Secure Remote Access (`-IncludeSRA`):**

- `messagebus.exe` is running (without it, Remote Support pop-ups don't appear)
- MQTT brokers reachable on 8883 (`FastTrackHubEU1` / `FastTrackHubUS1.azure-devices.net`)
- Cloudflare tunnel reachable on 7844 (`region1` / `region2.v2.argotunnel.com`)
- RDP (3389) enabled, needed only for Unattended Access
- ABR version supports Remote Support (8.4.0 build 31936 or later)
- No WinHTTP proxy that decrypts TLS (it breaks MQTT and the tunnel)

**Web Access Management (`-IncludeWAM`):**

- Installed apps that WAM's TLS inspection commonly breaks (WhatsApp, Splashtop, AnyDesk, GlobalProtect, Cloudflare WARP, FortiClient, OpenVPN, Zscaler), so you can add bypasses

**Portal cross-check (`-UseApi`):**

- This device is registered in the ABR portal
- When it last reported (warns after `-StaleDays`, default 7)
- Portal version matches the installed version
- Whether the portal sees the user as admin
- Domain or privileged groups in local Administrators (WARN); the default Entra admin roles are shown as INFO

Group checks use well-known SIDs, so they work on Windows in any language.

## Sample output

```text
=== ABR EPM Endpoint Health Check ===  2026-11-25 10:42  on WIN-ENDPOINT-01

[PASS] ABR version (8.5.1.0)                  Installed.
[PASS] ABR elevation driver loaded            ABRNetFilter, ABRProcessMonitor
[PASS] Current user NOT a local admin         CONTOSO\dana is a standard user.
[PASS] Secondary Logon (seclogon) enabled     StartType: Manual, Status: Stopped.
[PASS] Conflicting AV/EDR present             None of the known aggressive-conflict EDRs detected.
[INFO] Microsoft Defender for Endpoint        Present. Usually coexists with ABR; ...
[PASS] ABR portal reachable (api:443)         TCP 443 to api.adminbyrequest.com OK.
[WARN] No pending reboot                      A reboot is pending (ABR driver may not be fully loaded ...).
        -> FIX: Reboot the endpoint.

Summary: PASS=14  INFO=5  WARN=1   =>  NEEDS ATTENTION
```

## Requirements

- Windows 10 / 11 with Windows PowerShell 5.1 (built in)
- No modules to install

## Feedback

Found a bug or a false result? Open an [issue](../../../issues). Security problems: see [SECURITY.md](../SECURITY.md).

## License

[MIT](../LICENSE) © OnCloud Ltd. Provided as is, without warranty of any kind.
