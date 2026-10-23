# Agamemnon for Windows

Agamemnon is an open-source antivirus app created by **mertyesileducation** and **mirazbakis** for research purposes.

## General Features

- encrypted DNS
- malware scanning against **more than 50 million known threats** (new in 2.0)
- archive and installer scanning
- blocking unsafe downloads
- **Turkish and English**, and a design anyone can use without computer knowledge (new in 3.0)
- **real-time protection**: a ransomware shield, scanning files as they're saved, a paste-command guard, USB
  protection, camera and microphone alerts, startup-item alerts and self-protection (new in 4.0)
- a **Security Checkup** of Windows' own protection settings, and Microsoft Defender's engine as an extra
  scan engine (new in 4.0)

It also warns you when something gets administrator rights. It is released under the
[GPL-2.0](LICENSE).

## New in 4.0

The biggest update yet. Most of it comes from the Mac app (Agamemnon for macOS 3.0 and 3.1), rebuilt
for Windows.

**Real-time protection** (new *Real-time protection* page, every guard has its own switch):

- **Scan files as they're saved.** Programs, scripts, shortcuts, installers, archives, disk images and
  macro documents saved anywhere in your user folder (and `C:\Users\Public`) are scanned within a couple
  of seconds. Known malware goes straight to quarantine. Caches, `node_modules`, build output and package
  folders are skipped.
- **Ransomware shield.** Watches Documents, Desktop and Pictures (and folders you add). When 25 or more
  files change within 15 seconds it looks closer: do they still start like real JPEGs, PDFs, Office files
  and text? Did ten or more get the same new extension (`photo.jpg.locked`)? Did a ransom note appear?
  Then it asks Windows' Restart Manager which programs have those files open. An **unsigned** culprit is
  stopped and quarantined; a signed one is only named.
- **Paste guard (ClickFix).** Fake "I'm not a robot", "fix this error" and fake-update pages tell people
  to press Win+R and paste a command. Agamemnon looks at the shape of copied text (download-and-run
  cradles, encoded PowerShell, `mshta` with a link, the "# I am not a robot" comment trick, `^` and
  backtick tricks), warns you, and by default replaces the clipboard with a harmless warning. Official
  installers fetched from their own sites (Chocolatey, Scoop, uv, Bun, Deno, rustup…) are left alone.
- **USB protection.** When a USB drive or memory card is connected, its programs, scripts and archives
  are scanned with every engine, and the tricks infected drives use are looked for: the user's files
  hidden and replaced by a shortcut, programs named like documents, hidden programs at the top of the
  drive, and `autorun.inf` files that start something. Infected drives are ejected (optional).
- **Camera and microphone alerts.** Unlike macOS, Windows records *which* app uses them; Agamemnon tells
  you when one starts (at most once per app every 30 minutes).
- **Startup-item alerts.** Run keys, the Startup folders, Winlogon and scheduled tasks are compared every
  minute; anything new is scanned and reported, and malware is quarantined.
- **Self-protection.** The settings lock puts back Agamemnon's settings if another program edits them. The
  service watches the **hosts file** (security and update sites blocked or redirected) and **Microsoft
  Defender exclusions** (a classic way to hide malware) and alerts every signed-in user.

**Security Checkup** (new page): Windows still supported (with the real end-of-support dates for Windows
10 and each Windows 11 release, Home/Pro and Enterprise), Defender real-time protection and definitions,
tamper protection, controlled folder access, SmartScreen, the firewall's three profiles, UAC, BitLocker,
Secure Boot, memory integrity, LSA protection, Remote Desktop, SMBv1, automatic updates and the Wi-Fi
network's encryption (open/WEP/WPA/WPA2/WPA3). The service reads them as SYSTEM; Agamemnon never changes
them, each **Fix** button opens the right Windows Settings page. The page also lists **everything that
starts with Windows** (with a check for hidden scripts, temporary folders and fake Windows names) and
**programs with updates waiting** (from `winget`, with *Update all*).

**Stronger scanning:**

- **Microsoft Defender (AMSI)** joins as an engine: through Windows' Antimalware Scan Interface, Windows'
  registered antivirus checks scripts, documents and programs up to 16 MB. This is the Windows
  counterpart of the Mac app using Apple's XProtect rules.
- **Hidden scripts.** A decoder undoes base64 (UTF-8 and PowerShell's UTF-16), gzip/deflate inside
  base64, reversed strings, hex, `\xNN`/`%NN` escapes, split strings, `[char]` lists and `^`/backtick
  tricks, up to three layers deep, then looks for hidden download-and-run commands.
- **Quick scans also check every running program** outside the Windows folder.
- **Scan logs.** The last 50 scans are kept on the Scan page and can be exported as text.

**Everyday use:** *Scan with Agamemnon* on files and folders in File Explorer's right-click menu (on
Windows 11 under *Show more options*); **automatic updates** (once a day, the setup is only downloaded from
this repository's releases, must match the SHA-256 GitHub publishes and, for signed builds, be signed by
the same publisher); dashboard switches for the ransomware shield and paste guard; the welcome guide is
shown once more with a *Real-time protection* switch; new Help answers.

### Upgrading from 3.0

Run `Agamemnon-4.0.0-Setup.exe` or the `.msi` over 3.0 (no need to uninstall). Everything from 3.0 is kept;
the new protections start switched on.

## New in 3.0

- **Türkçe ve English.** The whole app (pages, notifications, tray menu) is available in Turkish
  and English. Switch at any time with the *English / Türkçe* buttons at the bottom of the sidebar
  or in Settings; everything changes at once, without restarting. On first start Agamemnon picks
  Turkish on Turkish Windows and English elsewhere.
- **Welcome guide.** Three short steps after installing or upgrading: choose the language, accept
  the recommended protection with one click (download blocking, encrypted DNS with Cloudflare's
  malware-blocking server, weekly scans, admin-rights alerts, start with Windows), and run the
  first quick scan. People upgrading from 2.0 see their current settings, not the defaults. It
  can be opened again from Settings or Help.
- **One-click fixes.** When something is wrong, the dashboard lists it in plain words with a
  button that fixes it (*Quarantine them*, *Turn on*, *How to fix*), plus *Fix all*.
- **Protection switches on the dashboard** for download blocking, encrypted DNS and admin-rights
  alerts, and a large *Scan now* button.
- **Automatic scans.** A quick scan runs by itself every week (or every day, or never), and only
  notifies you when it finds something.
- **Simple mode.** Hides the technical DNS and Downloads pages from the sidebar; they stay one
  click away in Settings. On by default for new installs.
- **Help page** with short answers to the questions people ask most ("A threat was found. What
  should I do?", "What is quarantine?", …).
- Plainer scan choices with time estimates, a "what should I do?" line on every finding, and a
  confirmation before deleting a quarantined file.

### Upgrading from 2.0

Run the 3.0 `Agamemnon-3.0.0-Setup.exe` or `.msi` over the installed 2.0; there is no need to
uninstall first. The installer keeps the same upgrade code, so Windows replaces 2.0 in place. Your
settings, API keys, trusted files, quarantine, activity log, encrypted-DNS settings and the
downloaded threat database are all kept. During the upgrade the old service restores the
network's DNS as it stops, and the new one switches encrypted DNS back on as soon as it starts.

## Türkçe: hızlı başlangıç

1. `Agamemnon-4.0.0-Setup.exe` dosyasını çalıştırın ve Windows'un sorduğu izni onaylayın.
   Bilgisayarınızda eski bir sürüm kuruluysa önce kaldırmanıza gerek yok: 4.0 onun üzerine kurulur,
   ayarlarınız ve karantinanız korunur.
2. Açılan karşılama rehberinde **Türkçe**'yi seçin, ardından **Önerilen ayarları kullan** düğmesine
   basın.
3. Hepsi bu. Saatin yanındaki kalkan **yeşilse** korunuyorsunuz. **Turuncu** veya **kırmızı** olursa
   Agamemnon'u açın: Ana sayfa sorunu sade bir dille anlatır ve yanında onu düzelten bir düğme
   gösterir.

**4.0'da yeni:** fidye yazılımı kalkanı, kaydedilen dosyaların anında taranması, sahte "Ben robot
değilim" komutlarına karşı yapıştırma koruması, USB koruması, kamera/mikrofon uyarıları, Windows ile
başlayan programlar için uyarılar ve Windows'un kendi koruma ayarlarını kontrol eden **Güvenlik kontrolü**
sayfası. Bunların hepsi **Gerçek zamanlı koruma** sayfasından tek tek açılıp kapatılabilir.

Dili istediğiniz zaman sol menünün altındaki **English / Türkçe** düğmeleriyle değiştirebilirsiniz.
Sorularınız için uygulamadaki **Yardım** sayfasına bakın.

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
| | **Offline threat database (2.0):** every file is checked against VirusShare's MD5 lists and abuse.ch MalwareBazaar's full SHA-256 export, tens of millions of known malware samples. Together with ClamAV and the YARA rules that is more than **50 million known threats**. The lookup is local: no hash leaves the PC. The dashboard shows the live count per source. | |
| | YARA rules for Windows threats: download cradles, encoded PowerShell, AMSI bypasses, Defender tampering, shadow-copy deletion, credential stealers, malicious shortcuts and HTA files, Office template injection, LOLBin abuse. You can add your own `.yar` files. | YARA rules for Mac families |
| | Hash lookups against MalwareBazaar (free abuse.ch Auth-Key), plus VirusTotal with your own API key. Only the SHA-256 is sent, never the file. | same |
| | Code checks: unsigned programs, self-signed or untrusted certificates (Windows' version of ad-hoc signing), signatures broken by tampering, revoked certificates, and blocked publishers. Uses Authenticode and the Windows security catalogs. | unsigned / ad-hoc / notarization checks |
| **Archive and installer scanning** | zip (and MSIX/APPX/Office/JAR), 7z, rar, tar, gz, bz2, xz, ISO images, CAB. Windows Installer packages are opened read-only and their custom-action binaries, scripts, command lines and cabinets are scanned. | DMG, PKG, zip… |
| | Nested up to 3 levels. Also flags archive bombs, password-protected archives that contain programs, and disguised names (`invoice.pdf.exe`, right-to-left override). | |
| **Unsafe downloads** | Watches Downloads (plus folders you add). Each file is scanned once the browser finishes writing it, and threats go straight to the encrypted quarantine. | same |
| | Optionally blocks unsigned programs from the internet, and files from hosts on abuse.ch's URLhaus list (read from the file's Mark-of-the-Web). | |
| **Real-time protection (4.0)** | On-access scanning of files saved in the user folder, the ransomware shield (type checks, mass renames, ransom notes; culprit found with the Restart Manager), paste guard, USB drive checks and eject, camera/microphone alerts, startup-item alerts, settings lock. | same (FSEvents, Endpoint Security, IOKit) |
| | Hosts-file and Defender-exclusion tamper alerts from the service. | settings lock, helper watchdog |
| **Security Checkup (4.0)** | Windows support dates, Defender, tamper protection, controlled folder access, SmartScreen, firewall, UAC, BitLocker, Secure Boot, memory integrity, LSA protection, RDP, SMBv1, updates, Wi-Fi encryption; startup items; winget updates; Agamemnon's own updates. | FileVault, firewall, Gatekeeper, SIP… |
| **Extra engines (4.0)** | Microsoft Defender through AMSI; a script decoder for hidden commands. | Apple XProtect rules; deobfuscator |
| **Admin-rights warnings** | Notifies you when a program is elevated by UAC (prompt or silent auto-elevation) or installs a system service. The alert says who signed it and whether it is known malware. Windows' own components are not reported. | authorization-request alerts |

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
  ├─ offline threat database lookups        AgamemnonScanEngine service (LocalService)
  └─ encrypted per-user quarantine            ├─ clamd on 127.0.0.1:3310 + freshclam updates
                                              └─ downloads VirusShare + MalwareBazaar hash lists
                                                 into %ProgramData%\Agamemnon\ThreatIntel
```

| Project | Contents |
|---|---|
| `windows/src/Agamemnon.Core` | Platform-neutral logic, unit-tested on any OS: DNS presets/rules, DoH/DoT/forwarder, leak test, scan engines and coordinator, offline threat database and feed updater, archive expansion, quarantine store, download watcher, IPC contract. |
| `windows/src/Agamemnon.Platform.Windows` | Authenticode and catalog verification, Mark-of-the-Web, DPAPI, `DnsQuery`, Wi-Fi name, MSI/CAB extraction, Windows DNS configuration, the elevation monitor. |
| `windows/src/Agamemnon.Service` | One executable for both Windows services, plus `--restore-dns` (run on uninstall). |
| `windows/src/Agamemnon.App` | The WPF app. Text comes from `Agamemnon.Core/Localization` (English and Turkish side by side); the tests check every key the app uses exists in both languages with matching placeholders. |
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
- **Offline threat database.**
  - Written only by the LocalService scan engine; signed-in users can read it but not change it.
  - Each update writes a new database file and then switches the manifest to it, so a scan in
    progress never sees a half-written file.
  - Hashes are stored as sorted 64-bit keys (about 400 MB for 50 million) and memory-mapped, so
    lookups take about a microsecond and almost no memory. With 50 million entries the chance
    that a clean file matches by accident is about 3 in a trillion per file.
- **Restoring DNS.**
  - Before the first change, the service records each adapter's DNS settings and any Windows
    DoH entries it changes.
  - Switching DNS off, stopping the service, or uninstalling puts all of them back.

## Building

Requirements: .NET 10 SDK. The installer additionally needs Windows.

```sh
cd windows
dotnet build Agamemnon.Windows.slnx        # builds on Windows, macOS and Linux
dotnet test tests/Agamemnon.Core.Tests     # 181 tests
python3 rules/test_rules.py                # pip install yara-python
```

### Release (signed MSI)

On Windows:

```powershell
$env:AGAMEMNON_SIGN_PFX = 'C:\path\codesign.pfx'
$env:AGAMEMNON_SIGN_PASSWORD = '…'
./windows/build/package.ps1 -Version 4.0.0
```

The script:

1. Publishes the app and the service as self-contained `win-x64` builds.
2. Downloads ClamAV and YARA as pinned in [`windows/build/deps.json`](windows/build/deps.json) and
   checks their SHA-256.
3. Signs Agamemnon's executables and DLLs.
4. Builds `windows/artifacts/Agamemnon-<version>-x64.msi` and signs it, with an RFC 3161 timestamp.

The GitHub Actions workflow (`.github/workflows/windows.yml`):

- On every push and pull request: checks the design tokens, tests the YARA rules, and builds and tests the solution.
- On a `v*` tag: builds the MSI and `Agamemnon-<version>-Setup.exe` (a WiX bundle that installs the
  MSI) and attaches both to that tag's GitHub Release (creating the release
  if needed). To sign it, set two repository secrets: `WINDOWS_SIGN_PFX_BASE64` (the base64-encoded
  .pfx) and `WINDOWS_SIGN_PASSWORD`.
- Run manually (**Actions → Windows → Run workflow**) with a `release_tag` such as `v1.0.0` to build
  the current branch and attach the installers to that release.

ClamAV and YARA are pinned by URL and SHA-256 in `deps.json`; `fetch-deps.ps1` refuses unpinned
downloads. When you bump a version, run it once with `-AllowUnpinned` on a trusted machine to print
the new hash.

## Notes and limits

- **The first threat-database download takes a while.** VirusShare publishes its hashes as several
  hundred numbered lists (about 1.5 GB of text in total). The scan engine downloads 40 lists every
  few minutes in the background, so the count climbs to over 50 million during the first hours
  after installation; ClamAV and MalwareBazaar protect you from the start. Afterwards only new
  lists are fetched. The finished database takes about 400 MB of disk.
- **"Known threats" means known samples and signatures, not 50 million different families.** Most
  entries are individual malware files identified by their hash; new, never-seen malware is caught
  by ClamAV's heuristics, the YARA rules and the code-signature checks instead.

- **Agamemnon works alongside Microsoft Defender.** It does not register with Windows Security
  Center or replace Defender's real-time file-system protection; that requires Microsoft's
  antimalware programme (ELAM). Keep Defender on.
- **Admin-rights alerts arrive just after an elevation, not before it.** Windows already shows its
  own UAC prompt. Agamemnon adds the publisher and a malware check, and also catches silent
  auto-elevations and new services.
- **Download blocking and alerts need `Agamemnon.exe` running.** It starts with Windows by
  default; turn this off in Settings. Each Windows user starts it once from the Start menu.
- **The 4.0 guards react just after something happens, not before.** Blocking a file or program before
  it runs needs a kernel driver signed through Microsoft's antimalware programme. The ransomware shield
  acts within seconds, so a few files may already be damaged: keep File History or OneDrive backups, and
  consider turning on Defender's *controlled folder access* (the Security Checkup shows it). The shield can
  only name a program that still has the files open.
- **The AMSI engine uses whichever antivirus is registered with Windows.** When Defender finds something
  through it, Defender's own history may also list it.
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
- The VirusShare hash lists are published by [VirusShare.com](https://virusshare.com/).

  **Copyright (c) 2026 mirazbakis and mertyesileducation**
