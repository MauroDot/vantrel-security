# Kestermere Security

**Security & System Integrity for Windows**  
**By Mauro Interactive**

Kestermere Security is a pre-release Windows security and system-integrity application built around a non-elevated WPF desktop, a least-privilege Windows Service, hardened local IPC, Windows security posture observation, cryptographically authenticated installation integrity, and guarded offline release/update recovery.

> **Important:** Kestermere Security is development software. It is **not** currently a replacement for Microsoft Defender, Windows Firewall, or another supported endpoint-protection product. Keep your existing Windows security protections enabled.

## Current beta capabilities

The current committed beta can:

- Display service connectivity, version, heartbeat, uptime, Windows version/build, system uptime, and system-volume capacity.
- Observe Windows-reported antivirus and firewall health and retain a bounded in-memory activity history.
- Inventory Windows Security providers and observe Windows Firewall profile state.
- Hand users off to Windows Security without impersonating, controlling, or misrepresenting Windows Security scanning.
- Inspect bounded local files and folders using SHA-256 fingerprinting.
- Inspect embedded Authenticode publisher information and Windows catalog-signature information.
- Compare freshly observed SHA-256 values where the capability defines a trusted reference.
- Observe selected installed Kestermere/Vantrel components through fixed, bounded collectors rather than arbitrary filesystem authority.
- Authenticate a signed installation manifest and compare a closed set of installed service components against it.
- Authenticate signed release metadata, bind it to the signed manifest, and enforce a durable anti-rollback release policy.
- Record bounded integrity-refresh audit/history information.
- Perform an Administrator-operated, guarded offline service-release transaction with durable recovery state, independently verified predecessor backup, post-replacement health verification, and rollback protections.

The beta does **not** currently provide a Kestermere malware-detection engine, real-time threat blocking, quarantine, malware removal, arbitrary file scanning, behavioral detection, or a replacement firewall.

## Architecture

```text
┌──────────────────────────────────────────┐
│     Kestermere Security Desktop          │
│        WPF / normal user token           │
└───────────────────┬──────────────────────┘
                    │
          versioned local named pipes
          explicit ACLs + bounded framing
                    │
┌───────────────────▼──────────────────────┐
│       Windows Service / LocalService     │
│                                          │
│  • health and security observations      │
│  • integrity and provenance state        │
│  • bounded inspection capabilities       │
│  • guarded command authorization         │
│  • update/recovery coordination          │
└──────────┬───────────────────┬───────────┘
           │                   │
           ▼                   ▼
   Windows APIs / WSC    Fixed local trust data
                         manifests / release policy
```

The desktop and worker are separate processes. Closing the desktop does not stop the service. The installed worker runs as `NT AUTHORITY\LocalService`, while the desktop remains non-elevated.

Kestermere deliberately separates Windows-reported security posture, Kestermere observations, cryptographic integrity/provenance, and future detection/remediation capabilities. An observation or successful signature check is not presented as a malware verdict.

For the detailed design, see:

- [Architecture](docs/ARCHITECTURE.md)
- [Security design](docs/SECURITY.md)
- [Deployment](docs/DEPLOYMENT.md)
- [Service manual](docs/SERVICE-MANUAL.md)

## Security model

Kestermere is being built with narrow authority and fail-closed behavior as core design constraints.

The local status boundary uses versioned named-pipe protocols with explicit Windows ACLs, bounded messages, deadlines, typed requests and responses, and no arbitrary CLR deserialization. Network and anonymous logons are not granted access to the service's local IPC boundary.

Privileged operations are kept separate from ordinary read-only status requests. Release and installation integrity use externally signed metadata and manifests. The service does not contain release-signing private keys.

The offline update design verifies the installed predecessor and staged candidate before service replacement, maintains durable transaction state, independently verifies the predecessor backup, verifies the resulting installation after replacement, and constrains rollback according to authenticated release policy.

These mechanisms reduce attack surface and protect the application's own update/integrity workflow. They do not make Kestermere an independent root of trust against an attacker who already controls Administrator or SYSTEM.

## Technology

| Area | Current implementation |
| --- | --- |
| Desktop | WPF / .NET 10 |
| Service | .NET Worker hosted as a Windows Service |
| Service identity | `NT AUTHORITY\LocalService` |
| IPC | Local Windows named pipes |
| Integrity hashing | SHA-256 |
| Release authentication | ECDSA P-256 signed metadata/manifests |
| Platform | Windows 11 x64 |
| Current product version | 0.1.0 |
| Publisher | Mauro Interactive |

The current development baseline uses .NET 10 LTS. `Core` remains platform-neutral where possible; Windows-specific service, desktop, infrastructure, and IPC projects target Windows.

## Repository layout

| Project | Responsibility |
| --- | --- |
| `src/Vantrel.Security.Desktop` | Kestermere WPF desktop |
| `src/Vantrel.Security.Service` | LocalService worker and service-owned collectors |
| `src/Vantrel.Security.Core` | Typed models, protocols, validation, and security-domain logic |
| `src/Vantrel.Security.Infrastructure` | Windows IPC and infrastructure implementation |
| `src/Vantrel.Security.ManifestTool` | Trusted-manifest tooling |
| `src/Vantrel.Security.OfflineUpdateTool` | Administrator-operated guarded offline update entry point |
| `tests/` | Unit, integration, security-boundary, update/recovery, and Windows-specific tests |
| `scripts/` | Publishing, service management, signing/verification, and release-support scripts |
| `docs/` | Architecture, security, deployment, and operational documentation |

## Build and test

From a Windows development environment with the repository's required .NET 10 SDK:

```powershell
dotnet restore Vantrel.Security.sln
dotnet build Vantrel.Security.sln --no-restore
dotnet test Vantrel.Security.sln --no-build
```

Some integration tests exercise real Windows ACL, named-pipe, Service Control Manager, or LocalService behavior and therefore require an appropriate Windows environment. A restricted sandbox token can fail tests that pass under the intended Windows security context.

## Interactive development

The service can run as a console-hosted development worker:

```powershell
dotnet run --project src/Vantrel.Security.Service
```

In another terminal under the same Windows account:

```powershell
$env:DOTNET_ENVIRONMENT = 'Development'
dotnet run --project src/Vantrel.Security.Desktop
```

The development environment enables the explicitly designed development IPC path. Release behavior expects the installed Windows Service.

## Publishing and service management

Publish the service:

```powershell
.\scripts\Publish-Service.ps1
```

Service-management operations are performed from a separate elevated Windows PowerShell session:

```powershell
.\scripts\Manage-Service.ps1 -Action Install
.\scripts\Manage-Service.ps1 -Action Start
.\scripts\Manage-Service.ps1 -Action Status
.\scripts\Manage-Service.ps1 -Action Stop
.\scripts\Manage-Service.ps1 -Action Restart
.\scripts\Manage-Service.ps1 -Action Uninstall
```

Use `-WhatIf` where supported to inspect an operation before changing the machine. Review [DEPLOYMENT.md](docs/DEPLOYMENT.md) and [SERVICE-MANUAL.md](docs/SERVICE-MANUAL.md) before performing installed-service or signed-release work.

Do not weaken PowerShell execution policy merely to run development scripts. The service-management and release procedures intentionally require explicit operator/admin boundaries.

## Windows Security integration

Kestermere observes selected Windows-reported security state and provides an external handoff to Windows Security. It does not claim ownership of Microsoft Defender or Windows Firewall results.

A Windows Security Center status such as `Good` describes Windows' reported category state. It is not a Kestermere malware verdict, and Kestermere's own active-protection status remains unavailable until an actual protection engine exists.

## Project status

Kestermere is under active development. The current repository represents a security-focused beta foundation rather than a finished consumer antivirus product.

The architecture has progressed beyond the original service-health prototype into bounded local inspection, Windows security posture visibility, signed installation integrity, signed release provenance, anti-rollback policy, and guarded offline update/recovery infrastructure.

The next stages continue toward a broader endpoint-security product while preserving the project's narrow-authority, explicit-trust, and fail-closed design.

## Public brand and compatibility identities

**Kestermere Security — Security & System Integrity** is the public product name. **Mauro Interactive** is the publisher.

The repository intentionally retains `Vantrel` in several internal and installed identities. These are compatibility identities, not stale public branding. Existing signed releases and trust relationships depend on names such as:

- `VantrelSecurityService`
- `Vantrel.Security.*` assemblies and namespaces
- `Vantrel.Security.Status.v1`
- `Vantrel.Security.Command.v1`
- existing signed sidecars and schemas
- fixed Program Files and ProgramData locations
- signing key identifiers
- the release metadata product identifier `vantrel-security`

Those identities should not be casually renamed because doing so would cross installation, protocol, cryptographic, update, and backward-compatibility boundaries.

## License and distribution

This repository currently represents pre-release development work. Do not interpret repository availability as a claim that Kestermere is production-ready, certified antivirus software, or suitable as the sole security control for a Windows system.
