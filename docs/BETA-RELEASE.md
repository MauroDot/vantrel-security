# Beta release layout foundation

`New-BetaReleaseLayout.ps1` is a build-time, two-phase release-layout tool. It does not install software, control a service, sign code, open a private key, contact a signing service, or create an installer.

The beta gate requires the exact SDK in `global.json` and a clean immutable checkout. It rejects tracked, untracked, and ignored checkout content before it restores, builds, or publishes. It runs `dotnet restore --locked-mode` against the committed package lock files; ordinary development restores remain unlocked.

`Prepare` requires a checked-out immutable commit, a Release version, release sequence, canonical UTC publication time, and release-notes file. It validates and records those descriptor inputs before publishing. The descriptor version and full source commit are bound to published Service, Desktop, and OfflineUpdateTool informational/build metadata while preserving the existing numeric assembly and file-version behavior. Deterministic and path-independent source settings apply to release publishing.

`Prepare` publishes raw Service output into temporary release-root staging, projects only the seven canonical Service components into `service`, and publishes framework-dependent `win-x64` Desktop and OfflineUpdateTool outputs into fixed `desktop` and `offline-update-tool` directories below an empty caller-supplied root. It writes a canonical descriptor and copies release notes as `release-notes.md`.

After `Prepare`, an external signing system signs only the documented Vantrel-owned PE allowlist using a non-secret signing-profile alias. The repository has no signing backend, certificate, private key, thumbprint, token, or provisioned publisher policy. Authenticode signing therefore occurs outside this repository. The four signed Vantrel Service PE files are then covered by the existing trusted manifest with the descriptor release version; separately signed release metadata follows with the same display version.

`Record` requires the non-secret signing-profile alias and verifies Authenticode before the existing public custom-signature checks. It requires the source-owned publisher policy, exactly one approved primary embedded signature, SHA-256 file digest, and a valid supported RFC 3161 timestamp under normal online whole-chain revocation behavior. The production publisher policy is intentionally unconfigured, so it cannot approve a release until a separately reviewed policy provision is added. `Record` then confirms manifest release and metadata display version, hashes every distributable file, and writes only relative safe verification evidence. It writes no partial record on failure.

Reproducible build inputs establish what was built; later external Authenticode signing and existing manifest/metadata signing establish separate signature evidence. This tool verifies but does not create Authenticode signatures.

A completed release layout can be passed to the build-only InstallerPreflight tool with an explicit Windows Installer numeric product version. It verifies the canonical release record, final layout hashes, exact nine-file Service payload, and eligible Desktop and OfflineUpdateTool artifacts, then emits an installer-input plan. The plan is not an MSI and cannot install, repair, upgrade, downgrade, uninstall, start a service, create ProgramData, or coordinate an offline update transaction.

No installer is produced yet. Existing development management scripts remain separate and are not beta installer tooling.
