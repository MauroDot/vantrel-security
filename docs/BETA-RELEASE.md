# Beta release layout foundation

`New-BetaReleaseLayout.ps1` is a build-time, two-phase release-layout tool. It does not install software, control a service, sign code, open a private key, contact a signing service, or create an installer.

The beta gate requires the exact SDK in `global.json` and a clean immutable checkout. It rejects tracked, untracked, and ignored checkout content before it restores, builds, or publishes. It runs `dotnet restore --locked-mode` against the committed package lock files; ordinary development restores remain unlocked.

`Prepare` requires a checked-out immutable commit, a Release version, release sequence, canonical UTC publication time, and release-notes file. It validates and records those descriptor inputs before publishing. The descriptor version and full source commit are bound to published Service, Desktop, and OfflineUpdateTool informational/build metadata while preserving the existing numeric assembly and file-version behavior. Deterministic and path-independent source settings apply to release publishing.

`Prepare` publishes raw Service output into temporary release-root staging, projects only the seven canonical Service components into `service`, and publishes framework-dependent `win-x64` Desktop and OfflineUpdateTool outputs into fixed `desktop` and `offline-update-tool` directories below an empty caller-supplied root. It writes a canonical descriptor and copies release notes as `release-notes.md`.

External Authenticode signing occurs after Prepare. The fixed nine-file Service payload is then given its existing trusted manifest with the descriptor release version and separately signed release metadata with the same display version. `Record` verifies that final payload with public keys only, confirms the manifest release and metadata display version equal the descriptor version, hashes every distributable file, and writes a canonical release record with relative paths only. It writes no partial record on failure.

Reproducible build inputs establish what was built; later external Authenticode signing and existing manifest/metadata signing establish the separate signature evidence. This tool neither creates nor verifies Authenticode signatures.

No installer is produced yet. Existing development management scripts remain separate and are not beta installer tooling.