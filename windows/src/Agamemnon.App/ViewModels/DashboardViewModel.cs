using System.Collections.ObjectModel;
using System.Globalization;
using System.Windows.Media;
using Agamemnon.App.Localization;
using Agamemnon.App.Services;
using Agamemnon.Core.Intelligence;
using Agamemnon.Core.Scanning;
using Agamemnon.Core.Settings;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Agamemnon.App.ViewModels;

public sealed partial class DashboardViewModel : PageViewModel
{
    private const int RecentCount = 8;
    private readonly AppServices _services;
    private readonly MainViewModel _main;

    public DashboardViewModel(AppServices services, MainViewModel main)
    {
        _services = services;
        _main = main;
        services.Activity.Entries.CollectionChanged += (_, _) => RefreshActivity();
        RefreshActivity();
    }

    public override NavigationTarget Target => NavigationTarget.Dashboard;

    public MainViewModel Main => _main;

    /// <summary>The latest few entries of the activity log.</summary>
    public ObservableCollection<ActivityEntry> Activity { get; } = [];

    [ObservableProperty]
    public partial string EngineText { get; set; } = L.T("dashboard.checkingEngine");

    /// <summary>The quick switches: the same settings as on the Downloads, DNS and Settings pages.</summary>
    public bool DownloadProtection
    {
        get => _services.Settings.DownloadProtection;
        set => _main.DownloadsPage.IsEnabled = value;
    }

    public bool AdminRightsAlerts
    {
        get => _services.Settings.AdminRightsAlerts;
        set => _main.Settings.AdminRightsAlerts = value;
    }

    public bool HasProblems => _main.Problems.Count > 0;

    public bool CanFixAll => _main.Problems.Count > 1;

    /// <summary>Known threats Agamemnon can recognise, refreshed by <see cref="MainViewModel.MonitorEnginesAsync"/>.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CoverageTitle), nameof(CoverageDetail), nameof(CoverageBrush), nameof(CoverageSources), nameof(CoverageProgress))]
    public partial ThreatCoverage? Coverage { get; set; }

    public string CoverageTitle => Coverage is { Total: > 0 } c
        ? L.F("dashboard.coverage.title", c.Total)
        : L.T("dashboard.coverage.preparing");

    public string CoverageDetail => Coverage switch
    {
        null or { Total: 0 } => L.T("dashboard.coverage.none"),
        { MeetsGoal: true, Downloading: false } => L.T("dashboard.coverage.complete"),
        { MeetsGoal: true } => L.T("dashboard.coverage.addingNewest"),
        { Downloading: true } c => L.F("dashboard.coverage.downloading", (double)c.Total / ThreatCoverage.Goal, ThreatCoverage.Goal),
        _ => L.T("dashboard.coverage.retrying"),
    };

    public double CoverageProgress => Coverage is { } c ? Math.Min(1, (double)c.Total / ThreatCoverage.Goal) * 100 : 0;

    public Brush CoverageBrush => StatusBrushes.For(Coverage is { MeetsGoal: true } ? ProtectionLevel.Protected : ProtectionLevel.Warning);

    public IReadOnlyList<string> CoverageSources => Coverage is null
        ? []
        : [.. Coverage.Sources.Select(s => string.Format(CultureInfo.CurrentCulture, "{0}: {1:N0} {2}", s.Name, s.Count, SourceKind(s.What)))];

    public string DnsTitle => _main.Dns.IsProtecting ? L.T("common.on") : _main.Dns.HasError ? L.T("common.problem") : L.T("common.off");

    public string DnsDetail => _main.Dns.Summary;

    public Brush DnsBrush => _main.DnsBrush;

    public string DownloadsTitle => _services.Settings.DownloadProtection ? L.T("common.on") : L.T("common.off");

    public string DownloadsDetail => _services.Settings.DownloadProtection
        ? L.F("dashboard.downloads.checked", _main.Downloads.CheckedToday)
        : L.T("dashboard.downloads.off");

    public Brush DownloadsBrush => _services.Settings.DownloadProtection
        ? StatusBrushes.For(ProtectionLevel.Protected)
        : StatusBrushes.For(ProtectionLevel.Warning);

    public string LastScanTitle => _services.Settings.LastScanAt is { } at
        ? at.ToLocalTime().ToString("g", CultureInfo.CurrentCulture)
        : L.T("dashboard.lastScan.never");

    public string LastScanDetail => _services.Settings.LastScanAt is null
        ? L.T("dashboard.lastScan.hint")
        : L.F("dashboard.lastScan.detail", ScanViewModel.KindName(_services.Settings.LastScanKind), _services.Settings.LastScanFiles, _services.Settings.LastScanThreats);

    public string AutoScanText => ScanSchedule.Next(_services.Settings.AutoScan, _services.Settings.LastScanAt, DateTimeOffset.Now) is { } next
        ? L.F(_services.Settings.AutoScan == AutoScanFrequency.Daily ? "dashboard.autoScan.daily" : "dashboard.autoScan.weekly",
            next <= DateTimeOffset.Now ? L.T("dashboard.autoScan.soon") : next.ToLocalTime().ToString("g", CultureInfo.CurrentCulture))
        : L.T("dashboard.autoScan.off");

    public string QuarantineTitle => L.F("dashboard.quarantine.count", _services.Quarantine.List().Count);

    public void Refresh()
    {
        OnPropertyChanged(nameof(DnsTitle));
        OnPropertyChanged(nameof(DnsDetail));
        OnPropertyChanged(nameof(DnsBrush));
        OnPropertyChanged(nameof(DownloadsTitle));
        OnPropertyChanged(nameof(DownloadsDetail));
        OnPropertyChanged(nameof(DownloadsBrush));
        OnPropertyChanged(nameof(LastScanTitle));
        OnPropertyChanged(nameof(LastScanDetail));
        OnPropertyChanged(nameof(QuarantineTitle));
        OnPropertyChanged(nameof(AutoScanText));
        OnPropertyChanged(nameof(DownloadProtection));
        OnPropertyChanged(nameof(AdminRightsAlerts));
        OnPropertyChanged(nameof(HasProblems));
        OnPropertyChanged(nameof(CanFixAll));
    }

    private static string SourceKind(string what) => what switch
    {
        "signatures" => L.T("dashboard.source.signatures"),
        "MD5 malware hashes" => L.T("dashboard.source.md5"),
        "SHA-256 malware hashes" => L.T("dashboard.source.sha256"),
        "behaviour rules" => L.T("dashboard.source.yara"),
        _ => what,
    };

    public override void OnShown() => Refresh();

    private void RefreshActivity()
    {
        Activity.Clear();
        foreach (ActivityEntry entry in _services.Activity.Entries.Take(RecentCount))
        {
            Activity.Add(entry);
        }
    }

    [RelayCommand]
    private void QuickScan()
    {
        _main.Navigate(NavigationTarget.Scan);
        _main.Scan.QuickScanCommand.Execute(null);
    }

    [RelayCommand]
    private void Open(NavigationTarget target) => _main.Navigate(target);
}
