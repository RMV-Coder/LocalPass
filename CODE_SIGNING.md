# Code signing policy

Free code signing provided by [SignPath.io](https://about.signpath.io/),
certificate by [SignPath Foundation](https://signpath.org/).

## What is signed

| Artifact | Signed with |
|---|---|
| `LocalPass_<version>_x64_en-US.msi` (Windows installer), and the `localpass-desktop.exe` and `localpass-daemon.exe` inside it | Authenticode, SignPath Foundation certificate |
| `LocalPass_<version>_x64-setup.exe` (Windows installer, NSIS) | Authenticode, SignPath Foundation certificate |
| `LocalPass_<version>_aarch64.apk` (Android) | The project's own Android release key (not SignPath) |
| Every desktop installer, for the in-app updater | A minisign signature (`<installer>.sig`); the public key is in [`apps/desktop/src-tauri/tauri.conf.json`](apps/desktop/src-tauri/tauri.conf.json) |

Only software built from this repository is signed. Third-party components are
included as they are, never signed by this project.

## How a release is signed

1. A version bump merges to `main` through a reviewed pull request.
2. GitHub Actions ([`.github/workflows/desktop-release.yml`](.github/workflows/desktop-release.yml))
   builds the installers from that commit on GitHub-hosted runners. Nothing is
   built or signed on a personal machine.
3. The workflow submits the unsigned installers to SignPath. SignPath checks
   that they were built by this repository's workflow and that every file
   carries the product name `LocalPass` and the release version
   ([artifact configuration](.signpath/artifact-configurations/windows-installers.xml)).
4. An approver reviews the request and approves it in SignPath. **Every release
   is approved by hand.**
5. The signed installers are verified (Authenticode status must be valid), the
   updater signatures are made over the signed files, and the release is
   published.

## Team roles

- **Committers and reviewers:** [@RMV-Coder](https://github.com/RMV-Coder).
  Changes from anyone else arrive as pull requests and are reviewed before they
  merge; `main` is protected and needs passing CI.
- **Approvers** (approve each signing request): [@RMV-Coder](https://github.com/RMV-Coder).

All team members use multi-factor authentication for GitHub and SignPath.

## Privacy policy

This program will not transfer any information to other networked systems
unless specifically requested by the user or the person installing or
operating it.

In detail:

- **Your vault stays on your devices.** There are no accounts, no servers and
  no telemetry.
- **Sync** writes encrypted, signed files only to a folder you choose (for
  example a Syncthing, OneDrive or USB folder). Moving that folder between
  devices is up to you and the tool you pick.
- **Update checks** contact GitHub only when you press *Check for updates*, or
  at unlock if you turned on *Check when LocalPass unlocks* (off by default).
  The request carries nothing about you or your vault; GitHub's handling of it
  is covered by the
  [GitHub General Privacy Statement](https://docs.github.com/site-policy/privacy-policies/github-general-privacy-statement).
- **The browser extension** talks only to the LocalPass app on the same
  computer (native messaging); it makes no network requests of its own.

## Verifying a download

- **Windows:** right-click the installer, open *Properties → Digital
  Signatures*, and check that it is signed by **SignPath Foundation** and the
  signature is valid. Or in PowerShell:
  `Get-AuthenticodeSignature .\LocalPass_<version>_x64_en-US.msi`.
- **Any file:** compare its SHA-256 with the digest shown on the
  [release page](https://github.com/RMV-Coder/LocalPass/releases).

Report a signing or security problem as described in [SECURITY.md](SECURITY.md).
