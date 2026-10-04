# Beta release layout foundation

`New-BetaReleaseLayout.ps1` is a build-time, two-phase release-layout tool. It does not install software, control a service, sign code, open a private key, contact a signing service, or create an installer.

`Prepare` requires a checked-out immutable commit, a Release version, release sequence, canonical UTC publication time, and release-notes file. It builds the solution and ManifestTool, then publishes the raw Service output into temporary release-root staging, projects only the seven canonical Service components into `service`, and publishes framework-dependent `win-x64` Desktop and OfflineUpdateTool outputs into fixed `desktop` and `offline-update-tool` directories below an empty caller-supplied root. It writes a canonical descriptor and copies release notes as `release-notes.md`.

External Authenticode signing occurs after Prepare. The fixed nine-file Service payload is then given its existing trusted manifest with the descriptor release version and separately signed release metadata with the same display version. `Record` verifies that final payload with public keys only, confirms the manifest release and metadata display version equal the descriptor version, hashes every distributable file, and writes a canonical release record with relative paths only. It writes no partial record on failure.

Authenticode publisher signatures and timestamps identify the distributed Windows binaries and future installer. The existing trusted-manifest signer authenticates the seven fixed Service component hashes. The separate release-metadata signer binds that manifest hash and release sequence. This layout tool only validates the resulting post-signing payload; it does not verify or create Authenticode signatures.

No installer is produced yet. Existing development management scripts remain separate and are not beta installer tooling.
