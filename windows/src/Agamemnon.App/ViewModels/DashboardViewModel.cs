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

/// <summary>One protection layer on the dashboard's score card.</summary>
public sealed record ScoreLayerRow(string Name, bool On)
{
    public Brush Brush => On ? StatusBrushes.For(ProtectionLevel.Protected) : StatusBrushes.Neutral;

    public string Mark => On ? "\uE73E" : "\uE711";
}

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

    public bool RansomwareShield
    {
        get => _services.Settings.RansomwareShield;
        set => _main.RealTime.RansomwareShield = value;
    }

    public bool PasteGuard
    {
        get => _services.Settings.PasteGuard;
        set => _main.RealTime.PasteGuard = value;
    }

    public bool UpdateAvailable => _main.Updates.Available is not null;

    public string UpdateText => _main.Updates.Available is { } u ? L.F("update.available", u.Version.ToString(3), Services.AppServices.Version) : string.Empty;

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

    // 5.0: the protection score.

    public int ScoreValue => _main.Score.Score;

    public string ScoreTitle => L.F("score.title", _main.Score.Score);

    public string ScoreGrade => L.T($"score.grade.{_main.Score.Grade}");

    public Brush ScoreBrush => StatusBrushes.For(_main.Score.Score >= 85 ? ProtectionLevel.Protected : _main.Score.Score >= 60 ? ProtectionLevel.Warning : ProtectionLevel.Threat);

    public string ScoreNextStep => _main.Score.NextStep is { } next
        ? L.F("score.next", L.T($"score.layer.{next.Id}"), next.Weight)
        : L.T("score.allOn");

    public IReadOnlyList<ScoreLayerRow> ScoreLayers => [.. _main.Score.Layers.Select(l => new ScoreLayerRow(L.T($"score.layer.{l.Id}"), l.On))];

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
        OnPropertyChanged(nameof(RansomwareShield));
        OnPropertyChanged(nameof(PasteGuard));
        OnPropertyChanged(nameof(UpdateAvailable));
        OnPropertyChanged(nameof(UpdateText));
        OnPropertyChanged(nameof(HasProblems));
        OnPropertyChanged(nameof(CanFixAll));
        OnPropertyChanged(nameof(ScoreValue));
        OnPropertyChanged(nameof(ScoreTitle));
        OnPropertyChanged(nameof(ScoreGrade));
        OnPropertyChanged(nameof(ScoreBrush));
        OnPropertyChanged(nameof(ScoreNextStep));
        OnPropertyChanged(nameof(ScoreLayers));
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
