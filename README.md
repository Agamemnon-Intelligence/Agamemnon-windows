# Agamemnon for Windows

Agamemnon is an open-source antivirus app. It covers four areas:

- encrypted DNS
- malware scanning
- archive and installer scanning
- blocking unsafe downloads

It also warns you when something gets administrator rights. It is released under the
[GPL-2.0](LICENSE).

This repository contains **Agamemnon for Windows** (`windows/`) and the **design tokens shared with
the Mac app** (`design/`; the Mac app is
[Agamemnon-macOS](https://github.com/Agamemnon-Intelligence/Agamemnon-macOS)).

## Windows features

| Area | What Agamemnon does on Windows | macOS counterpart |
|---|---|---|
| **Encrypted DNS** | Applied directly by the Agamemnon service, with no configuration profile or Group Policy. The one-time approval is the installer's UAC prompt. | `NEDNSSettingsManager` + approval in System Settings |
| | **DNS-over-HTTPS** on Windows 11 uses Windows' own DoH client (auto-upgrade on, plain-text fallback off). | |
| | **DNS-over-TLS**, and DoH on Windows 10, use Agamemnon's local resolver on `127.0.0.1`/`::1`. It **fails closed**: if the encrypted server can't be reached, lookups fail instead of leaking. | |
| | Presets: Cloudflare, Quad9, Mullvad, Google, Control D, NextDNS (with your configuration ID), and a custom server. Security filtering: Cloudflare 1.1.1.2, Quad9 and AdGuard. | same |
| | Rules: turn DNS off on chosen Wi-Fi networks; exclude domains (sent to the network's own resolver through NRPT rules or the local resolver). | same |
| | Live status, a leak test (which resolvers really answer, and which network owns them), and one-click on/off from the window or the tray icon. | same |
| **Malware scanning** | ClamAV signatures, updated every 2 hours by `freshclam`. | same |
| | YARA rules for Windows threats: download cradles, encoded PowerShell, AMSI bypasses, Defender tampering, shadow-copy deletion, credential stealers, malicious shortcuts and HTA files, Office template injection, LOLBin abuse. You can add your own `.yar` files. | YARA rules for Mac families |
| | Hash lookups against MalwareBazaar (free abuse.ch Auth-Key), plus VirusTotal with your own API key. Only the SHA-256 is sent, never the file. | same |
| | Code checks: unsigned programs, self-signed or untrusted certificates (Windows' version of ad-hoc signing), signatures broken by tampering, revoked certificates, and blocked publishers. Uses Authenticode and the Windows security catalogs. | unsigned / ad-hoc / notarization checks |
| **Archive and installer scanning** | zip (and MSIX/APPX/Office/JAR), 7z, rar, tar, gz, bz2, xz, ISO images, CAB. Windows Installer packages are opened read-only and their custom-action binaries, scripts, command lines and cabinets are scanned. | DMG, PKG, zip… |
| | Nested up to 3 levels. Also flags archive bombs, password-protected archives that contain programs, and disguised names (`invoice.pdf.exe`, right-to-left override). | |
| **Unsafe downloads** | Watches Downloads (plus folders you add). Each file is scanned once the browser finishes writing it, and threats go straight to the encrypted quarantine. | same |
| | Optionally blocks unsigned programs from the internet, and files from hosts on abuse.ch's URLhaus list (read from the file's Mark-of-the-Web). | |
| **Admin-rights warnings** | Notifies you when a program is elevated by UAC (prompt or silent auto-elevation) or installs a system service. The alert says who signed it and whether it is known malware. Windows' own components are not reported. | authorization-request alerts |

### UI

- Dark theme only.
- Sidebar: Dashboard, Scan, DNS, Downloads, Quarantine, Settings. The About page credits
  [github.com/mirazbakis](https://github.com/mirazbakis) and
  [github.com/mertyesileducation](https://github.com/mertyesileducation).
- The **notification-area (tray) icon** is the Windows counterpart of the menu bar icon:
  - The shield's colour shows overall protection: green for protected, amber for warnings, red for threats.
  - A dot shows that DNS is encrypted.
  - Its menu shows protection and DNS status and can toggle DNS or start a quick scan.

## Shared design tokens

[`design/tokens.json`](design/tokens.json) is the single source for colours, radii, spacing and
font sizes on both platforms:

| Token | Value |
|---|---|
| Background | `#0B1020` |
| Panels | `#121A2E` |
| Buttons | `#1E3A8A` |
| Buttons, hover | `#2545A8` |
| Protected | `#22C55E` |
| Warning | `#F59E0B` |
| Threat | `#EF4444` |

```sh
python3 design/generate_tokens.py          # regenerate after editing tokens.json
python3 design/generate_tokens.py --check  # CI: fail if generated files are stale
```

It generates:

- `windows/src/Agamemnon.App/Themes/Tokens.g.xaml` (WPF resources)
- `windows/src/Agamemnon.App/Themes/DesignTokens.g.cs` (C#, for the tray icon)
- `mac/Shared/DesignTokens.swift` (SwiftUI)

## How it fits together

```
Agamemnon.exe (WPF, runs as you)            Agamemnon service (LocalSystem)
  ├─ UI + notification-area icon      pipe    ├─ applies encrypted DNS, Wi-Fi rules, exclusions
  ├─ scanning (ClamAV, YARA, hashes,  ◄────►  ├─ local DoH/DoT resolver when needed
  │   signatures, archives)                   └─ administrator-rights monitor
  ├─ download watcher
  └─ encrypted per-user quarantine          AgamemnonScanEngine service (LocalService)
                                              └─ clamd on 127.0.0.1:3310 + freshclam updates
```

| Project | Contents |
|---|---|
| `windows/src/Agamemnon.Core` | Platform-neutral logic, unit-tested on any OS: DNS presets/rules, DoH/DoT/forwarder, leak test, scan engines and coordinator, archive expansion, quarantine store, download watcher, IPC contract. |
| `windows/src/Agamemnon.Platform.Windows` | Authenticode and catalog verification, Mark-of-the-Web, DPAPI, `DnsQuery`, Wi-Fi name, MSI/CAB extraction, Windows DNS configuration, the elevation monitor. |
| `windows/src/Agamemnon.Service` | One executable for both Windows services, plus `--restore-dns` (run on uninstall). |
| `windows/src/Agamemnon.App` | The WPF app. |
| `windows/rules` | Bundled YARA rules and their test samples. |
| `windows/installer` | WiX v5 MSI. |

### Security model

- **Least privilege.**
  - Scanning runs as the signed-in user. ClamAV only receives file contents the user can read,
    streamed over `INSTREAM`.
  - `clamd`, which parses untrusted files, runs as LocalService, not SYSTEM.
  - Only DNS configuration and elevation monitoring run as SYSTEM.
- **The service pipe.**
  - Remote (network) logons are denied by the pipe's ACL.
  - The app only talks to a pipe served from session 0, so a program that grabs the name first
    can't pose as the service.
  - Clients connect at *identification* level, so the service can check who is calling but
    can't act as them.
- **Who can change DNS.**
  - Any signed-in user can switch DNS on or off and choose a preset.
  - A custom DNS server can redirect every lookup on the PC, so it needs an elevated
    administrator: the app asks Windows for approval (UAC) just for that change.
- **Quarantine.**
  - Files are encrypted with AES-256-GCM in 1 MiB chunks. Each chunk is bound to its item,
    position and finality, so a quarantined copy can't be tampered with or truncated.
  - The key is protected by DPAPI for your Windows account.
  - Restoring checks the SHA-256 and marks the file as trusted, so it isn't immediately blocked again.
- **Archives.**
  - Members are extracted under random names, so path traversal is impossible.
  - Sizes and compression ratios are enforced while the data is being copied, not taken from archive headers.
- **Restoring DNS.**
  - Before the first change, the service records each adapter's DNS settings and any Windows
    DoH entries it changes.
  - Switching DNS off, stopping the service, or uninstalling puts all of them back.

## Building

Requirements: .NET 10 SDK. The installer additionally needs Windows.

```sh
cd windows
dotnet build Agamemnon.Windows.slnx        # builds on Windows, macOS and Linux
dotnet test tests/Agamemnon.Core.Tests     # 81 tests
python3 rules/test_rules.py                # pip install yara-python
```

### Release (signed MSI)

On Windows:

```powershell
$env:AGAMEMNON_SIGN_PFX = 'C:\path\codesign.pfx'
$env:AGAMEMNON_SIGN_PASSWORD = '…'
./windows/build/package.ps1 -Version 1.0.0
```

The script:

1. Publishes the app and the service as self-contained `win-x64` builds.
2. Downloads ClamAV and YARA as pinned in [`windows/build/deps.json`](windows/build/deps.json) and
   checks their SHA-256.
3. Signs Agamemnon's executables and DLLs.
4. Builds `windows/artifacts/Agamemnon-<version>-x64.msi` and signs it, with an RFC 3161 timestamp.

The GitHub Actions workflow (`.github/workflows/windows.yml`):

- On every push and pull request: checks the design tokens, tests the YARA rules, and builds and tests the solution.
- On a `v*` tag: builds the MSI. To sign it, set two repository secrets:
  `WINDOWS_SIGN_PFX_BASE64` (the base64-encoded .pfx) and `WINDOWS_SIGN_PASSWORD`.

> **Before the first release:** confirm the ClamAV and YARA download URLs in `deps.json` and fill in
> their `sha256` values. `fetch-deps.ps1` refuses unpinned downloads. Run it once with
> `-AllowUnpinned` on a trusted machine to print the hashes.

## Notes and limits

- **Agamemnon works alongside Microsoft Defender.** It does not register with Windows Security
  Center or replace Defender's real-time file-system protection; that requires Microsoft's
  antimalware programme (ELAM). Keep Defender on.
- **Admin-rights alerts arrive just after an elevation, not before it.** Windows already shows its
  own UAC prompt. Agamemnon adds the publisher and a malware check, and also catches silent
  auto-elevations and new services.
- **Download blocking and alerts need `Agamemnon.exe` running.** It starts with Windows by
  default; turn this off in Settings. Each Windows user starts it once from the Start menu.
- **Wi-Fi rules need the network name.** On Windows 11 24H2 and later, Windows may only reveal it
  when location services are allowed.
- **Captive portals** (hotel or café sign-in pages) usually need their own DNS. Add those networks
  to the Wi-Fi rule.

## License

Agamemnon is free software: you can redistribute it and/or modify it under the terms of the GNU
General Public License, version 2, as published by the Free Software Foundation. See
[LICENSE](LICENSE).

Bundled and used components:

- ClamAV (GPL-2.0)
- YARA (BSD-3-Clause)
- SharpCompress (MIT)
- DiscUtils (MIT)
- WiX Toolset DTF (MS-RL)
- CommunityToolkit.Mvvm (MIT)
- MalwareBazaar and URLhaus are services of [abuse.ch](https://abuse.ch/).
