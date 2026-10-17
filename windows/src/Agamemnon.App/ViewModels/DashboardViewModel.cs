using System.Collections.ObjectModel;
using System.Globalization;
using System.Windows.Media;
using Agamemnon.App.Services;
using Agamemnon.Core.Intelligence;
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

    public override string Title => "Dashboard";

    public MainViewModel Main => _main;

    /// <summary>The latest few entries of the activity log.</summary>
    public ObservableCollection<ActivityEntry> Activity { get; } = [];

    [ObservableProperty]
    public partial string EngineText { get; set; } = "Checking ClamAV…";

    /// <summary>Known threats Agamemnon can recognise, refreshed by <see cref="MainViewModel.MonitorEnginesAsync"/>.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CoverageTitle), nameof(CoverageDetail), nameof(CoverageBrush), nameof(CoverageSources), nameof(CoverageProgress))]
    public partial ThreatCoverage? Coverage { get; set; }

    public string CoverageTitle => Coverage is { Total: > 0 } c
        ? string.Format(CultureInfo.CurrentCulture, "{0:N0} known threats", c.Total)
        : "Preparing the threat database…";

    public string CoverageDetail => Coverage switch
    {
        null or { Total: 0 } => "The scan engine service downloads ClamAV signatures and the offline malware hash databases after installation.",
        { MeetsGoal: true, Downloading: false } => "Every file is checked against all of them offline; nothing is sent anywhere.",
        { MeetsGoal: true } => "Still adding the newest lists. Every file is checked against all of them offline.",
        { Downloading: true } c => string.Format(CultureInfo.CurrentCulture,
            "Downloading the offline threat database ({0:P0} of the {1:N0} target). It finishes in the background.",
            (double)c.Total / ThreatCoverage.Goal, ThreatCoverage.Goal),
        _ => "Some feeds couldn't be downloaded yet; Agamemnon keeps retrying.",
    };

    public double CoverageProgress => Coverage is { } c ? Math.Min(1, (double)c.Total / ThreatCoverage.Goal) * 100 : 0;

    public Brush CoverageBrush => StatusBrushes.For(Coverage is { MeetsGoal: true } ? ProtectionLevel.Protected : ProtectionLevel.Warning);

    public IReadOnlyList<string> CoverageSources => Coverage is null
        ? []
        : [.. Coverage.Sources.Select(s => string.Format(CultureInfo.CurrentCulture, "{0}: {1:N0} {2}", s.Name, s.Count, s.What))];

    public string DnsTitle => _main.Dns.IsProtecting ? "On" : _main.Dns.HasError ? "Problem" : "Off";

    public string DnsDetail => _main.Dns.Summary;

    public Brush DnsBrush => _main.DnsBrush;

    public string DownloadsTitle => _services.Settings.DownloadProtection ? "On" : "Off";

    public string DownloadsDetail => _services.Settings.DownloadProtection
        ? $"{_main.Downloads.CheckedToday} file(s) checked since Agamemnon started"
        : "New downloads aren't being checked";

    public Brush DownloadsBrush => _services.Settings.DownloadProtection
        ? StatusBrushes.For(ProtectionLevel.Protected)
        : StatusBrushes.For(ProtectionLevel.Warning);

    public string LastScanTitle => _services.Settings.LastScanAt is { } at
        ? at.ToLocalTime().ToString("g", CultureInfo.CurrentCulture)
        : "Never";

    public string LastScanDetail => _services.Settings.LastScanAt is null
        ? "Run a quick scan to check the places malware usually lands"
        : $"{_services.Settings.LastScanKind} scan · {_services.Settings.LastScanFiles:N0} files · {_services.Settings.LastScanThreats} threat(s)";

    public string QuarantineTitle => _services.Quarantine.List().Count.ToString(CultureInfo.CurrentCulture);

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
    }

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
