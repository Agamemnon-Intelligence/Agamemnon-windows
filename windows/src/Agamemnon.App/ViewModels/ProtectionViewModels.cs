using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using Agamemnon.App.Localization;
using Agamemnon.App.Services;
using Agamemnon.Core.Checkup;
using Agamemnon.Core.Ipc;
using Agamemnon.Core.Settings;
using Agamemnon.Core.Startup;
using Agamemnon.Core.Updates;
using Agamemnon.Platform.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;

namespace Agamemnon.App.ViewModels;

/// <summary>The Real-time protection page: one switch per guard, protected folders, and what the guards did.</summary>
public sealed partial class ProtectionViewModel : PageViewModel
{
    private static readonly HashSet<ActivityKind> Kinds =
    [
        ActivityKind.RealTime, ActivityKind.Ransomware, ActivityKind.Usb, ActivityKind.Paste, ActivityKind.Privacy,
        ActivityKind.Startup, ActivityKind.Tamper, ActivityKind.AdminRights,
    ];

    private readonly AppServices _services;
    private readonly RealTimeGuards _guards;

    public ProtectionViewModel(AppServices services, RealTimeGuards guards)
    {
        _services = services;
        _guards = guards;
        Incidents = new ListCollectionView(services.Activity.Entries)
        {
            Filter = item => item is ActivityEntry entry && Kinds.Contains(entry.Kind),
        };
        guards.StateChanged += (_, _) => Application.Current.Dispatcher.BeginInvoke(() => OnPropertyChanged(nameof(OnAccessText)));
    }

    public override NavigationTarget Target => NavigationTarget.Protection;

    public ICollectionView Incidents { get; }

    public ObservableCollection<FolderRow> Folders { get; } = [];

    public string OnAccessText => L.F("protection.onAccess.checked", _guards.OnAccessChecked);

    public bool OnAccessScanning { get => _services.Settings.OnAccessScanning; set => Set(s => s with { OnAccessScanning = value }); }

    public bool RansomwareShield { get => _services.Settings.RansomwareShield; set => Set(s => s with { RansomwareShield = value }); }

    public bool StopDangerousPrograms { get => _services.Settings.StopDangerousPrograms; set => Set(s => s with { StopDangerousPrograms = value }); }

    public bool PasteGuard { get => _services.Settings.PasteGuard; set => Set(s => s with { PasteGuard = value }); }

    public bool PasteGuardClears { get => _services.Settings.PasteGuardClears; set => Set(s => s with { PasteGuardClears = value }); }

    public bool UsbProtection { get => _services.Settings.UsbProtection; set => Set(s => s with { UsbProtection = value }); }

    public bool EjectInfectedDrives { get => _services.Settings.EjectInfectedDrives; set => Set(s => s with { EjectInfectedDrives = value }); }

    public bool PrivacyAlerts { get => _services.Settings.PrivacyAlerts; set => Set(s => s with { PrivacyAlerts = value }); }

    public bool StartupAlerts { get => _services.Settings.StartupAlerts; set => Set(s => s with { StartupAlerts = value }); }

    public bool SettingsLock { get => _services.Settings.SettingsLock; set => Set(s => s with { SettingsLock = value }); }

    public override void OnShown()
    {
        Folders.Clear();
        foreach (string folder in _guards.RansomwareFolders)
        {
            Folders.Add(new FolderRow(folder, _services.Settings.RansomwareFolders.Contains(folder, StringComparer.OrdinalIgnoreCase)));
        }

        OnPropertyChanged(string.Empty);
    }

    /// <summary>Turns every real-time guard on (the dashboard's "Fix all" and the welcome guide).</summary>
    public void TurnEverythingOn() => Set(s => s with
    {
        OnAccessScanning = true, RansomwareShield = true, PasteGuard = true, UsbProtection = true, PrivacyAlerts = true,
        StartupAlerts = true, SettingsLock = true,
    });

    private void Set(Func<AppSettings, AppSettings> change)
    {
        _services.UpdateSettings(change);
        _guards.Restart();
        OnShown();
    }

    [RelayCommand]
    private void AddFolder()
    {
        var dialog = new OpenFolderDialog { Title = L.T("protection.ransomware.addFolder") };
        if (dialog.ShowDialog() == true)
        {
            Set(s => s with { RansomwareFolders = [.. s.RansomwareFolders.Append(dialog.FolderName).Distinct(StringComparer.OrdinalIgnoreCase)] });
        }
    }

    [RelayCommand]
    private void RemoveFolder(FolderRow row) =>
        Set(s => s with { RansomwareFolders = [.. s.RansomwareFolders.Where(f => !f.Equals(row.Path, StringComparison.OrdinalIgnoreCase))] });
}

public sealed partial class CheckRow(SecurityCheck check) : ObservableObject
{
    public string Title => L.T($"checkup.{check.Id}.title");

    public string Advice => check.State == CheckState.Unknown
        ? L.T("checkup.unknown")
        : L.F($"checkup.{check.Id}.{check.State.ToString().ToLowerInvariant()}", check.Value ?? string.Empty);

    public string StateText => check.State switch
    {
        CheckState.Good => L.T("checkup.state.good"),
        CheckState.Warning => L.T("checkup.state.warning"),
        CheckState.Bad => L.T("checkup.state.bad"),
        _ => L.T("checkup.state.unknown"),
    };

    public Brush Brush => check.State switch
    {
        CheckState.Good => StatusBrushes.For(ProtectionLevel.Protected),
        CheckState.Warning => StatusBrushes.For(ProtectionLevel.Warning),
        CheckState.Bad => StatusBrushes.For(ProtectionLevel.Threat),
        _ => StatusBrushes.Neutral,
    };

    public bool CanFix => check.State is CheckState.Warning or CheckState.Bad && check.FixUri is not null;

    [RelayCommand]
    private void Fix()
    {
        if (check.FixUri is { } uri)
        {
            Shell.Open(uri);
        }
    }
}

public sealed partial class StartupRow(StartupItem item, Agamemnon.Core.Scanning.Detection? finding, CheckupViewModel owner) : ObservableObject
{
    public StartupItem Item => item;

    public string Name => item.Name.Split('\\')[^1];

    public string Command => item.Command;

    public string Where => L.T($"checkup.startup.location.{item.Location}");

    public string? Finding => finding?.Name;

    public bool HasFinding => finding is not null;

    public Brush Brush => finding is null ? StatusBrushes.For(ProtectionLevel.Protected) : StatusBrushes.For(ProtectionLevel.Warning);

    [RelayCommand]
    private void Trust() => owner.TrustStartupItem(this);

    [RelayCommand]
    private void Reveal()
    {
        string? program = item.Program ?? StartupAudit.ProgramOf(Environment.ExpandEnvironmentVariables(item.Command));
        if (program is not null && File.Exists(program))
        {
            Shell.RevealInExplorer(program);
        }
    }
}

/// <summary>
/// The Security Checkup page: Windows' own protection settings (read by the service), the Wi-Fi
/// network, everything that starts with Windows, programs with updates waiting, and
/// Agamemnon's own update. Agamemnon only reads settings; each row's button opens the Windows
/// page that changes it.
/// </summary>
public sealed partial class CheckupViewModel(AppServices services, UpdateService updates, MainViewModel main) : PageViewModel
{
    private DateTimeOffset _lastRun = DateTimeOffset.MinValue;

    public override NavigationTarget Target => NavigationTarget.Checkup;

    public ObservableCollection<CheckRow> Checks { get; } = [];

    public ObservableCollection<StartupRow> StartupItems { get; } = [];

    public ObservableCollection<string> SoftwareUpdates { get; } = [];

    /// <summary>Settings the last checkup rated "fix this", for the dashboard ("worth a look" stays on this page).</summary>
    public int ProblemCount { get; private set; }

    [ObservableProperty]
    public partial string Summary { get; set; } = L.T("checkup.notRun");

    [ObservableProperty]
    public partial Brush SummaryBrush { get; set; } = StatusBrushes.Neutral;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(RunCommand))]
    public partial bool IsRunning { get; set; }

    [ObservableProperty]
    public partial string StartupSummary { get; set; } = string.Empty;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(CheckSoftwareCommand))]
    public partial bool CheckingSoftware { get; set; }

    [ObservableProperty]
    public partial string SoftwareSummary { get; set; } = L.T("checkup.software.hint");

    [ObservableProperty]
    public partial string? UpdateMessage { get; set; }

    public bool UpdateAvailable => updates.Available is not null;

    public string UpdateText => updates.Available is { } u
        ? L.F("update.available", u.Version.ToString(3), AppServices.Version)
        : updates.Checking ? L.T("update.checking") : L.F("update.current", AppServices.Version);

    public bool CheckForUpdates
    {
        get => services.Settings.CheckForUpdates;
        set
        {
            services.UpdateSettings(s => s with { CheckForUpdates = value });
            OnPropertyChanged();
        }
    }

    public override void OnShown()
    {
        if (DateTimeOffset.Now - _lastRun > TimeSpan.FromMinutes(5) && !IsRunning)
        {
            RunCommand.Execute(null);
        }

        OnPropertyChanged(nameof(UpdateText));
        OnPropertyChanged(nameof(UpdateAvailable));
    }

    public void OnUpdatesChanged()
    {
        OnPropertyChanged(nameof(UpdateText));
        OnPropertyChanged(nameof(UpdateAvailable));
    }

    private bool CanRun => !IsRunning;

    [RelayCommand(CanExecute = nameof(CanRun))]
    public async Task RunAsync()
    {
        IsRunning = true;
        _lastRun = DateTimeOffset.Now;
        try
        {
            IReadOnlyList<SecurityCheck> checks = [];
            try
            {
                SecuritySnapshot snapshot = await services.Service.CallAsync<SecuritySnapshot>(IpcMethods.SecurityCheckup, null, CancellationToken.None).ConfigureAwait(true);
                checks = SecurityCheckup.Evaluate(snapshot, DateTimeOffset.Now);
            }
            catch (Exception ex) when (ex is IpcException or IOException or TimeoutException or System.Text.Json.JsonException or UnauthorizedAccessException)
            {
                Summary = L.T("checkup.noService");
                SummaryBrush = StatusBrushes.For(ProtectionLevel.Warning);
            }

            Checks.Clear();
            foreach (SecurityCheck check in checks.OrderByDescending(c => c.State switch { CheckState.Bad => 3, CheckState.Warning => 2, CheckState.Good => 1, _ => 0 }))
            {
                Checks.Add(new CheckRow(check));
            }

            if (checks.Count > 0)
            {
                ProblemCount = checks.Count(c => c.State == CheckState.Bad);
                int toImprove = checks.Count(c => c.State is CheckState.Bad or CheckState.Warning);
                CheckState overall = SecurityCheckup.Overall(checks);
                Summary = toImprove == 0 ? L.T("checkup.summary.good") : L.F("checkup.summary.problems", toImprove);
                SummaryBrush = StatusBrushes.For(overall switch { CheckState.Bad => ProtectionLevel.Threat, CheckState.Warning => ProtectionLevel.Warning, _ => ProtectionLevel.Protected });
            }

            var items = await Task.Run(() => StartupEnumerator.List(includeTasks: true)
                .Select(i => (Item: i, Finding: StartupAudit.Inspect(i, Environment.ExpandEnvironmentVariables)))
                .ToList()).ConfigureAwait(true);
            StartupItems.Clear();
            foreach ((StartupItem item, Agamemnon.Core.Scanning.Detection? finding) in items
                         .Where(i => !services.Settings.TrustedStartupItems.Contains(i.Item.Key, StringComparer.OrdinalIgnoreCase) || i.Finding is null)
                         .OrderByDescending(i => i.Finding is not null).ThenBy(i => i.Item.Name, StringComparer.CurrentCultureIgnoreCase))
            {
                StartupItems.Add(new StartupRow(item, services.Settings.TrustedStartupItems.Contains(item.Key, StringComparer.OrdinalIgnoreCase) ? null : finding, this));
            }

            int flagged = StartupItems.Count(r => r.HasFinding);
            StartupSummary = flagged == 0 ? L.F("checkup.startup.clean", StartupItems.Count) : L.F("checkup.startup.flagged", StartupItems.Count, flagged);
        }
        finally
        {
            IsRunning = false;
            main.RefreshStatus();
        }
    }

    public void TrustStartupItem(StartupRow row)
    {
        services.UpdateSettings(s => s with { TrustedStartupItems = [.. s.TrustedStartupItems.Append(row.Item.Key).Distinct(StringComparer.OrdinalIgnoreCase)] });
        int index = StartupItems.IndexOf(row);
        if (index >= 0)
        {
            StartupItems[index] = new StartupRow(row.Item, null, this);
        }
    }

    private bool CanCheckSoftware => !CheckingSoftware;

    [RelayCommand(CanExecute = nameof(CanCheckSoftware))]
    private async Task CheckSoftwareAsync()
    {
        CheckingSoftware = true;
        SoftwareSummary = L.T("checkup.software.checking");
        try
        {
            IReadOnlyList<SoftwareUpdate>? found = await UpdateService.ListSoftwareUpdatesAsync(CancellationToken.None).ConfigureAwait(true);
            SoftwareUpdates.Clear();
            foreach (SoftwareUpdate update in found ?? [])
            {
                SoftwareUpdates.Add(WingetOutput.Format(update));
            }

            SoftwareSummary = found is null ? L.T("checkup.software.noWinget")
                : found.Count == 0 ? L.T("checkup.software.none")
                : L.F("checkup.software.found", found.Count);
        }
        finally
        {
            CheckingSoftware = false;
        }
    }

    [RelayCommand]
    private static void UpdateAllSoftware()
    {
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("winget.exe", "upgrade --all --accept-source-agreements") { UseShellExecute = true })?.Dispose();
        }
        catch (System.ComponentModel.Win32Exception)
        {
        }
    }

    [RelayCommand]
    private static void OpenWindowsUpdate() => Shell.Open("ms-settings:windowsupdate");

    [RelayCommand]
    private async Task CheckAgamemnonUpdateAsync()
    {
        UpdateMessage = null;
        await updates.CheckAsync(force: true, CancellationToken.None).ConfigureAwait(true);
        OnUpdatesChanged();
        if (updates.Available is null)
        {
            UpdateMessage = L.T("update.none");
        }
    }

    [RelayCommand]
    private async Task InstallUpdateAsync()
    {
        UpdateMessage = L.T("update.downloading");
        string? error = await updates.InstallAsync(CancellationToken.None).ConfigureAwait(true);
        UpdateMessage = error ?? L.T("update.started");
    }

    [RelayCommand]
    private void OpenReleasePage()
    {
        if (updates.Available is { } u)
        {
            Shell.Open(u.Page.AbsoluteUri);
        }
    }
}
