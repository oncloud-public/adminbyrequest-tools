# Admin By Request tools

Community tools for [Admin By Request](https://www.adminbyrequest.com/), built by [OnCloud](https://www.oncld.io).

> **Not an official Admin By Request product.** OnCloud is an Admin By Request partner. These tools are built and maintained by OnCloud, not by Admin By Request.

## Tools

Each tool lives in its own folder, with its own README covering what it does, what permissions it needs and how to run it.

| Tool | What it does |
|------|--------------|
| [ABR EPM Endpoint Health Check](ABR-EPM-HealthCheck/) | Read-only PowerShell check for a Windows endpoint running ABR EPM: agent, driver, local admin rights, EDR conflicts, portal connectivity, and optional SRA / WAM / portal cross-checks. |
| [ABR Threat Report](ABR-ThreatReport/) | Reads the ABR Events and Auditlog APIs and writes one HTML report of threat detections across the tenant: malware, malicious elevated apps, clock tampering, break-glass use, local account changes, policy tampering. |

## Before you run a tool

- Read the tool's README first, including the permissions it needs.
- Test it on a small group or a test tenant before running it in production.
- Never commit API keys or credentials to this repo or to a fork of it.

## Support and disclaimer

These tools are provided as is, without warranty of any kind (see [LICENSE](LICENSE)). For bugs and ideas, open an [issue](../../issues). To report a security problem, see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © OnCloud Ltd.
