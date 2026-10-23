using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using Agamemnon.App.Localization;
using Agamemnon.Core.Downloads;
using Agamemnon.Core.Protection;
using Agamemnon.Core.Quarantine;
using Agamemnon.Core.Scanning;
using Agamemnon.Core.Startup;
using Agamemnon.Platform.Windows;

namespace Agamemnon.App.Services;

/// <summary>
/// Agamemnon 4.0's real-time protection beyond downloads, ported from the Mac app and adapted
/// to Windows. Every guard runs as the signed-in user, follows its switch in Settings, and only
/// stops or quarantines things that nobody vouches for (unsigned programs outside Windows):
/// <list type="bullet">
/// <item>on-access scanning of programs and scripts saved anywhere in the user's folder;</item>
/// <item>the ransomware shield for Documents, Desktop, Pictures and chosen folders;</item>
/// <item>the paste-command guard (ClickFix);</item>
/// <item>USB protection: drives are checked as they're connected;</item>
/// <item>camera and microphone alerts;</item>
/// <item>new startup items;</item>
/// <item>the settings lock.</item>
/// </list>
/// </summary>
public sealed partial class RealTimeGuards : IDisposable
{
    private readonly AppServices _services;
    private readonly Notifier _notifier;
    private readonly SemaphoreSlim _scanSlots = new(2);
    private readonly RansomwareDetector _ransomware = new();
    private readonly DeviceUsageTracker _devices = new();
    private readonly List<FileSystemWatcher> _ransomwareWatchers = [];
    private readonly Lock _gate = new();
    private readonly System.Threading.Timer _fastTimer;
    private readonly System.Threading.Timer _slowTimer;
    private DownloadWatcher? _onAccess;
    private ManagementEventWatcher? _volumes;
    private FileSystemWatcher? _settingsWatcher;
    private HwndSource? _clipboardWindow;
    private IReadOnlyList<StartupItem>? _startupBaseline;
    private int _slowTicks;
    private int _analysing;

    public RealTimeGuards(AppServices services, Notifier notifier)
    {
        _services = services;
        _notifier = notifier;
        _fastTimer = new System.Threading.Timer(_ => FastTick(), null, Timeout.Infinite, Timeout.Infinite);
        _slowTimer = new System.Threading.Timer(_ => SlowTick(), null, Timeout.Infinite, Timeout.Infinite);
    }

    public event EventHandler? StateChanged;

    public int OnAccessChecked { get; private set; }

    public bool OnAccessRunning => _onAccess is not null;

    public bool RansomwareRunning => _ransomwareWatchers.Count > 0;

    public bool PasteGuardRunning => _clipboardWindow is not null;

    public bool UsbRunning => _volumes is not null;

    /// <summary>Documents, Desktop and Pictures, plus the folders chosen in Settings.</summary>
    public IReadOnlyList<string> RansomwareFolders
    {
        get
        {
            string[] defaults =
            [
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                Environment.GetFolderPath(Environment.SpecialFolder.MyPictures),
            ];
            return [.. defaults.Concat(_services.Settings.RansomwareFolders).Where(f => !string.IsNullOrEmpty(f)).Distinct(StringComparer.OrdinalIgnoreCase)];
        }
    }

    /// <summary>Starts or stops each guard to match the settings. Must be called on the UI thread.</summary>
    public void Restart()
    {
        var settings = _services.Settings;
        lock (_gate)
        {
            _onAccess?.Dispose();
            _onAccess = null;
            if (settings.OnAccessScanning)
            {
                string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                string publicFolder = Environment.GetEnvironmentVariable("PUBLIC") ?? string.Empty;
                _onAccess = new DownloadWatcher([profile, publicFolder], TimeSpan.FromSeconds(1.5), includeSubdirectories: true, filter: OnAccessFilter.ShouldScan);
                _onAccess.FileReady += (_, path) => _ = OnAccessAsync(path);
                _onAccess.Start();
            }

            foreach (FileSystemWatcher watcher in _ransomwareWatchers)
            {
                watcher.Dispose();
            }

            _ransomwareWatchers.Clear();
            if (settings.RansomwareShield)
            {
                foreach (string folder in RansomwareFolders.Where(Directory.Exists))
                {
                    var watcher = new FileSystemWatcher(folder)
                    {
                        IncludeSubdirectories = true,
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                        InternalBufferSize = 64 * 1024,
                    };
                    watcher.Changed += (_, e) => _ransomware.Record(e.FullPath);
                    watcher.Created += (_, e) => _ransomware.Record(e.FullPath);
                    watcher.Renamed += (_, e) => _ransomware.Record(e.FullPath);
                    watcher.EnableRaisingEvents = true;
                    _ransomwareWatchers.Add(watcher);
                }
            }

            StopUsb();
            if (settings.UsbProtection)
            {
                StartUsb();
            }

            _settingsWatcher?.Dispose();
            _settingsWatcher = null;
            if (settings.SettingsLock && Path.GetDirectoryName(_services.SettingsPath) is { } settingsFolder && Directory.Exists(settingsFolder))
            {
                _settingsWatcher = new FileSystemWatcher(settingsFolder, Path.GetFileName(_services.SettingsPath))
                {
                    NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.FileName,
                };
                _settingsWatcher.Changed += (_, _) => _ = CheckSettingsAsync();
                _settingsWatcher.Renamed += (_, _) => _ = CheckSettingsAsync();
                _settingsWatcher.EnableRaisingEvents = true;
            }
        }

        if (settings.PasteGuard)
        {
            StartPasteGuard();
        }
        else
        {
            StopPasteGuard();
        }

        _fastTimer.Change(TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(2));
        _slowTimer.Change(TimeSpan.FromSeconds(20), TimeSpan.FromMinutes(1));
        StateChanged?.Invoke(this, EventArgs.Empty);
    }

    // ---- On-access scanning ----

    private async Task OnAccessAsync(string path)
    {
        // Downloads have their own guard with download-specific rules.
        if (path.StartsWith(KnownFolders.Downloads + "\\", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        await _scanSlots.WaitAsync().ConfigureAwait(false);
        try
        {
            var (result, _, _) = await _services.CreateScanner(forDownloads: false)
                .ScanFileAsync(path, _services.CreateScanOptions(), CancellationToken.None).ConfigureAwait(false);
            OnAccessChecked++;
            if (result.Verdict == Severity.Malicious)
            {
                Detection worst = result.Detections.MaxBy(d => d.Severity)!;
                string name = Path.GetFileName(path);
                if (TryQuarantine(path, result.Detections, "Real-time"))
                {
                    Log(ActivityKind.RealTime, ActivityLevel.Threat, L.F("protection.onAccess.blocked", name), $"{worst.Name}. {path}");
                    _notifier.Show(NotificationLevel.Threat, L.F("protection.onAccess.blocked", name), L.F("protection.onAccess.blocked.text", worst.Name), NavigationTarget.Quarantine);
                }
                else
                {
                    Log(ActivityKind.RealTime, ActivityLevel.Threat, L.F("protection.onAccess.found", name), $"{worst.Name}. {path}");
                    _notifier.Show(NotificationLevel.Threat, L.F("protection.onAccess.found", name), worst.Name, NavigationTarget.Protection);
                }
            }

            StateChanged?.Invoke(this, EventArgs.Empty);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
        finally
        {
            _scanSlots.Release();
        }
    }

    // ---- Timers: ransomware bursts, camera and microphone, startup items ----

    private void FastTick()
    {
        if (_services.Settings.RansomwareShield && _ransomware.TakeBurst() is { } burst && Interlocked.Exchange(ref _analysing, 1) == 0)
        {
            _ = Task.Run(() =>
            {
                try
                {
                    AnalyseBurst(burst);
                }
                finally
                {
                    Volatile.Write(ref _analysing, 0);
                }
            });
        }

        if (_services.Settings.PrivacyAlerts)
        {
            foreach (DeviceUse use in _devices.Update(DeviceUsageReader.Read()))
            {
                string device = use.Device == PrivacyDevice.Camera ? L.T("protection.privacy.camera") : L.T("protection.privacy.microphone");
                Log(ActivityKind.Privacy, ActivityLevel.Info, L.F("protection.privacy.started", use.AppName, device), use.AppPath);
                _notifier.Show(NotificationLevel.Info, L.F("protection.privacy.started", use.AppName, device), L.T("protection.privacy.text"), NavigationTarget.Protection);
            }
        }
    }

    private void SlowTick()
    {
        _slowTicks++;
        if (!_services.Settings.StartupAlerts)
        {
            _startupBaseline = null;
            return;
        }

        // Scheduled tasks are slower to read: every tenth minute.
        IReadOnlyList<StartupItem> now = StartupEnumerator.List(includeTasks: _slowTicks % 10 == 1);
        if (_slowTicks % 10 != 1 && _startupBaseline is not null)
        {
            now = [.. now, .. _startupBaseline.Where(i => i.Location == StartupLocation.ScheduledTask)];
        }

        IReadOnlyList<StartupItem>? before = _startupBaseline;
        _startupBaseline = now;
        if (before is null)
        {
            return;
        }

        foreach (StartupItem item in StartupAudit.NewOrChanged(before, now))
        {
            if (_services.Settings.TrustedStartupItems.Contains(item.Key, StringComparer.OrdinalIgnoreCase))
            {
                continue;
            }

            _ = ReportStartupItemAsync(item);
        }
    }

    private async Task ReportStartupItemAsync(StartupItem item)
    {
        Detection? finding = StartupAudit.Inspect(item, Environment.ExpandEnvironmentVariables);
        string? program = item.Program ?? StartupAudit.ProgramOf(Environment.ExpandEnvironmentVariables(item.Command));
        FileScanResult? scan = null;
        if (program is not null && File.Exists(program))
        {
            try
            {
                scan = (await _services.CreateScanner(forDownloads: false).ScanFileAsync(program, _services.CreateScanOptions(), CancellationToken.None).ConfigureAwait(false)).Result;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
            }
        }

        string name = item.Name.Split('\\')[^1];
        if (scan?.Verdict == Severity.Malicious && program is not null)
        {
            Detection worst = scan.Detections.MaxBy(d => d.Severity)!;
            bool quarantined = TryQuarantine(program, scan.Detections, "Real-time");
            Log(ActivityKind.Startup, ActivityLevel.Threat, L.F("protection.startup.malware", name), $"{worst.Name}. {item.Command}");
            _notifier.Show(NotificationLevel.Threat, L.F("protection.startup.malware", name),
                quarantined ? L.T("protection.startup.malware.quarantined") : worst.Name, NavigationTarget.Checkup);
            return;
        }

        bool suspicious = finding is not null || scan?.Verdict == Severity.Suspicious;
        Log(ActivityKind.Startup, suspicious ? ActivityLevel.Warning : ActivityLevel.Info, L.F("protection.startup.new", name), item.Command);
        _notifier.Show(suspicious ? NotificationLevel.Warning : NotificationLevel.Info, L.F("protection.startup.new", name),
            suspicious ? L.T("protection.startup.suspicious") : L.T("protection.startup.text"), NavigationTarget.Checkup);
    }

    private void AnalyseBurst(IReadOnlyList<string> paths)
    {
        RansomwareVerdict? verdict = RansomwareDetector.Analyse(paths, ReadHead);
        if (verdict is null)
        {
            return;
        }

        _ransomware.MarkIncident();
        string[] existing = [.. paths.Where(File.Exists).Take(64)];
        var stopped = new List<string>();
        string? culprit = null;
        var verifier = new AuthenticodeVerifier();
        foreach (FileUser user in FileUsers.Find(existing).Where(u => u.Path is not null && u.ProcessId != Environment.ProcessId))
        {
            string path = user.Path!;
            if (IsWindowsOrAgamemnon(path))
            {
                continue;
            }

            culprit ??= path;
            bool vouchedFor = verifier.Verify(path, onlineRevocationCheck: false).State == SignatureState.Trusted;
            if (vouchedFor || !_services.Settings.StopDangerousPrograms)
            {
                continue;
            }

            try
            {
                using var process = Process.GetProcessById(user.ProcessId);
                process.Kill(entireProcessTree: true);
                stopped.Add(Path.GetFileName(path));
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException)
            {
            }

            TryQuarantine(path, [new Detection("Ransomware shield", "Ransomware behaviour", Severity.Malicious)], "Real-time");
        }

        string what = verdict.Sign switch
        {
            RansomwareSign.MassRenamed => L.F("protection.ransomware.renamed", verdict.FilesAffected, verdict.Extension),
            RansomwareSign.RansomNote => L.F("protection.ransomware.note", verdict.Note),
            _ => L.F("protection.ransomware.scrambled", verdict.FilesAffected),
        };
        string outcome = stopped.Count > 0 ? L.F("protection.ransomware.stopped", string.Join(", ", stopped))
            : culprit is not null ? L.F("protection.ransomware.signed", Path.GetFileName(culprit))
            : L.T("protection.ransomware.unknown");
        Log(ActivityKind.Ransomware, ActivityLevel.Threat, L.T("protection.ransomware.title"), $"{what} {outcome}");
        _notifier.Show(NotificationLevel.Threat, L.T("protection.ransomware.title"), $"{what} {outcome}", NavigationTarget.Protection);
    }

    private static byte[]? ReadHead(string path)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            byte[] head = new byte[512];
            int read = stream.ReadAtLeast(head, head.Length, throwOnEndOfStream: false);
            return head[..read];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    // ---- USB protection ----

    private void StartUsb()
    {
        try
        {
            // EventType 2: a volume arrived.
            _volumes = new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM Win32_VolumeChangeEvent WHERE EventType = 2"));
            _volumes.EventArrived += (_, e) =>
            {
                if (e.NewEvent["DriveName"] is string drive && drive.Length >= 2)
                {
                    _ = CheckDriveAsync(drive.TrimEnd('\\') + "\\");
                }
            };
            _volumes.Start();
        }
        catch (Exception ex) when (ex is ManagementException or COMException or UnauthorizedAccessException)
        {
            _volumes = null;
        }
    }

    private void StopUsb()
    {
        try
        {
            _volumes?.Stop();
        }
        catch (ManagementException)
        {
        }

        _volumes?.Dispose();
        _volumes = null;
    }

    private async Task CheckDriveAsync(string root)
    {
        DriveInfo drive;
        try
        {
            drive = new DriveInfo(root);
            if (drive.DriveType != DriveType.Removable || !drive.IsReady)
            {
                return;
            }
        }
        catch (Exception ex) when (ex is ArgumentException or IOException)
        {
            return;
        }

        string label = string.IsNullOrWhiteSpace(drive.VolumeLabel) ? root : $"{drive.VolumeLabel} ({root.TrimEnd('\\')})";
        IReadOnlyList<DriveFinding> lures = await Task.Run(() => RemovableDriveInspector.Inspect(root)).ConfigureAwait(false);
        string[] files = [.. OnAccessFilter.RiskyFiles(root, 20_000)];
        ScanReport report = await Task.Run(() => _services.CreateScanner(forDownloads: false)
            .ScanAsync(files, _services.CreateScanOptions(), null, CancellationToken.None)).ConfigureAwait(false);

        var threats = report.Findings.Where(f => f.IsThreat && !f.IsArchiveMember).ToList();
        int malicious = threats.Count(t => t.Verdict == Severity.Malicious) + lures.Count(l => l.Detection.Severity == Severity.Malicious);
        int suspicious = threats.Count(t => t.Verdict == Severity.Suspicious) + lures.Count(l => l.Detection.Severity == Severity.Suspicious);
        if (malicious == 0 && suspicious == 0)
        {
            Log(ActivityKind.Usb, ActivityLevel.Good, L.F("protection.usb.clean", label), L.F("activity.scan.files", report.FilesScanned));
            return;
        }

        foreach (FileScanResult threat in threats.Where(t => t.Verdict == Severity.Malicious && t.OnDiskPath is not null))
        {
            TryQuarantine(threat.OnDiskPath!, threat.Detections, "USB");
        }

        foreach (DriveFinding lure in lures.Where(l => l.Detection.Severity == Severity.Malicious))
        {
            TryQuarantine(lure.Path, [lure.Detection], "USB");
        }

        bool ejected = malicious > 0 && _services.Settings.EjectInfectedDrives && DriveEjector.TryEject(root);
        string detail = string.Join(" · ", threats.Select(t => $"{Path.GetFileName(t.DisplayPath)}: {t.Detections[0].Name}")
            .Concat(lures.Select(l => $"{Path.GetFileName(l.Path)}: {l.Detection.Name}")).Take(6));
        Log(ActivityKind.Usb, malicious > 0 ? ActivityLevel.Threat : ActivityLevel.Warning, L.F("protection.usb.found", label, malicious + suspicious), detail);
        _notifier.Show(malicious > 0 ? NotificationLevel.Threat : NotificationLevel.Warning, L.F("protection.usb.found", label, malicious + suspicious),
            ejected ? L.T("protection.usb.ejected") : L.T("protection.usb.text"), NavigationTarget.Protection);
    }

    // ---- Paste-command guard ----

    private const int WmClipboardUpdate = 0x031D;

    private void StartPasteGuard()
    {
        if (_clipboardWindow is not null)
        {
            return;
        }

        // A message-only window (parent HWND_MESSAGE) receives clipboard notifications without showing anything.
        var parameters = new HwndSourceParameters("Agamemnon paste guard") { ParentWindow = new IntPtr(-3), WindowStyle = 0 };
        _clipboardWindow = new HwndSource(parameters);
        _clipboardWindow.AddHook(ClipboardHook);
        if (!AddClipboardFormatListener(_clipboardWindow.Handle))
        {
            _clipboardWindow.Dispose();
            _clipboardWindow = null;
        }
    }

    private void StopPasteGuard()
    {
        if (_clipboardWindow is null)
        {
            return;
        }

        RemoveClipboardFormatListener(_clipboardWindow.Handle);
        _clipboardWindow.Dispose();
        _clipboardWindow = null;
    }

    private IntPtr ClipboardHook(IntPtr hwnd, int message, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (message == WmClipboardUpdate)
        {
            // Let the copying app finish; then look at the text once.
            Application.Current.Dispatcher.BeginInvoke(CheckClipboard, System.Windows.Threading.DispatcherPriority.Background);
        }

        return IntPtr.Zero;
    }

    private void CheckClipboard()
    {
        // Text copied inside Agamemnon (paths, logs) isn't checked.
        if (Application.Current.Windows.OfType<Window>().Any(w => w.IsActive))
        {
            return;
        }

        string? text;
        try
        {
            text = Clipboard.ContainsText() ? Clipboard.GetText() : null;
        }
        catch (COMException)
        {
            return; // another app has the clipboard open
        }

        if (ClipboardCommandGuard.Assess(text) is not { } danger)
        {
            return;
        }

        bool cleared = false;
        if (_services.Settings.PasteGuardClears)
        {
            try
            {
                Clipboard.SetText(L.T("protection.paste.replacement"));
                cleared = true;
            }
            catch (COMException)
            {
            }
        }

        string reason = danger switch
        {
            PasteDanger.HiddenCommand => L.T("protection.paste.hidden"),
            PasteDanger.RemoteHta => L.T("protection.paste.hta"),
            PasteDanger.FakeVerification => L.T("protection.paste.fake"),
            _ => L.T("protection.paste.download"),
        };
        string preview = text!.Trim();
        preview = preview.Length > 160 ? preview[..160] + "…" : preview;
        Log(ActivityKind.Paste, ActivityLevel.Threat, L.T("protection.paste.title"), preview);
        _notifier.Show(NotificationLevel.Threat, L.T("protection.paste.title"),
            L.F("protection.paste.text", reason) + (cleared ? " " + L.T("protection.paste.cleared") : string.Empty), NavigationTarget.Protection);
    }

    // ---- Settings lock ----

    private async Task CheckSettingsAsync()
    {
        await Task.Delay(500).ConfigureAwait(false);
        if (_services.Settings.SettingsLock && _services.RestoreSettingsIfTampered())
        {
            Log(ActivityKind.Tamper, ActivityLevel.Threat, L.T("protection.lock.title"), _services.SettingsPath);
            _notifier.Show(NotificationLevel.Threat, L.T("protection.lock.title"), L.T("protection.lock.text"), NavigationTarget.Protection);
        }
    }

    // ---- Shared ----

    private bool TryQuarantine(string path, IReadOnlyList<Detection> detections, string source)
    {
        try
        {
            _services.Quarantine.Add(path, detections, source);
            return true;
        }
        catch (QuarantineException)
        {
            return false;
        }
    }

    private void Log(ActivityKind kind, ActivityLevel level, string title, string? detail) =>
        _services.Activity.Add(new ActivityEntry(DateTimeOffset.Now, kind, level, title, detail));

    private static bool IsWindowsOrAgamemnon(string path) =>
        path.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Windows) + "\\", StringComparison.OrdinalIgnoreCase)
        || path.StartsWith(AgamemnonPaths.InstallDirectory, StringComparison.OrdinalIgnoreCase)
        || path.Equals(Environment.ProcessPath, StringComparison.OrdinalIgnoreCase)
        || path.EndsWith(@"\explorer.exe", StringComparison.OrdinalIgnoreCase);

    public void Dispose()
    {
        _fastTimer.Dispose();
        _slowTimer.Dispose();
        _onAccess?.Dispose();
        foreach (FileSystemWatcher watcher in _ransomwareWatchers)
        {
            watcher.Dispose();
        }

        StopUsb();
        _settingsWatcher?.Dispose();
        StopPasteGuard();
        _scanSlots.Dispose();
    }

    [LibraryImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool AddClipboardFormatListener(IntPtr hwnd);

    [LibraryImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool RemoveClipboardFormatListener(IntPtr hwnd);
}
