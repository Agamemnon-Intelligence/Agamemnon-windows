using System.Collections.ObjectModel;
using System.Globalization;
using System.Windows;
using System.Windows.Media;
using Agamemnon.App.Localization;
using Agamemnon.App.Services;
using Agamemnon.Core.Intelligence;
using Agamemnon.Core.Ipc;
using Agamemnon.Core.Localization;
using Agamemnon.Core.Scanning;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Agamemnon.App.ViewModels;

public abstract partial class PageViewModel : ObservableObject
{
    public abstract NavigationTarget Target { get; }

    /// <summary>Called whenever the page is shown.</summary>
    public virtual void OnShown()
    {
    }

    /// <summary>Called after the language changes: refreshes every binding that code builds text for.</summary>
    public virtual void OnLanguageChanged() => OnPropertyChanged(string.Empty);
}

/// <summary>Something wrong with protection, explained plainly, with a button that fixes it (or shows how).</summary>
public sealed partial class ProblemViewModel(ProtectionLevel level, string title, string detail, string fixLabel, Action fix) : ObservableObject
{
    public string Title => title;

    public string Detail => detail;

    public string FixLabel => fixLabel;

    public Brush Brush => StatusBrushes.For(level);

    [RelayCommand]
    private void Fix() => fix();
}

/// <summary>Brushes for status colours, from the shared design tokens.</summary>
public static class StatusBrushes
{
    public static Brush For(ProtectionLevel level) => Get(level switch
    {
        ProtectionLevel.Protected => "StatusProtectedBrush",
        ProtectionLevel.Warning => "StatusWarningBrush",
        _ => "StatusThreatBrush",
    });

    public static Brush For(Severity? severity) => Get(severity switch
    {
        Severity.Malicious => "StatusThreatBrush",
        Severity.Suspicious => "StatusWarningBrush",
        Severity.Info => "StatusInfoBrush",
        _ => "StatusProtectedBrush",
    });

    public static Brush For(ActivityLevel level) => Get(level switch
    {
        ActivityLevel.Threat => "StatusThreatBrush",
        ActivityLevel.Warning => "StatusWarningBrush",
        ActivityLevel.Info => "StatusInfoBrush",
        _ => "StatusProtectedBrush",
    });

    public static Brush Neutral => Get("TextSecondaryBrush");

    private static Brush Get(string key) => (Brush)Application.Current.FindResource(key);
}

/// <summary>The window shell: sidebar navigation, overall status, and the link to the service.</summary>
public sealed partial class MainViewModel : ObservableObject
{
    private readonly AppServices _services;
    private readonly TrayIcon _tray;
    private readonly Notifier _notifier;

    public MainViewModel(AppServices services, TrayIcon tray, Notifier notifier, DownloadGuard downloads)
    {
        _services = services;
        _tray = tray;
        _notifier = notifier;
        Downloads = downloads;
        Scan = new ScanViewModel(services, this);
        Dns = new DnsViewModel(services, this);
        DownloadsPage = new DownloadsViewModel(services, downloads);
        Quarantine = new QuarantineViewModel(services);
        Settings = new SettingsViewModel(services, this);
        About = new AboutViewModel();
        Help = new HelpViewModel(this);
        Dashboard = new DashboardViewModel(services, this);
        CurrentPage = Dashboard;

        Loc.Instance.LanguageChanged += (_, _) => OnLanguageChanged();
        services.SettingsChanged += (_, _) => Application.Current.Dispatcher.BeginInvoke(RefreshStatus);
        services.Quarantine.Changed += (_, _) => Application.Current.Dispatcher.BeginInvoke(RefreshStatus);
        downloads.StateChanged += (_, _) => Application.Current.Dispatcher.BeginInvoke(RefreshStatus);
        RefreshStatus();
    }

    public DashboardViewModel Dashboard { get; }

    public ScanViewModel Scan { get; }

    public DnsViewModel Dns { get; }

    public DownloadsViewModel DownloadsPage { get; }

    public QuarantineViewModel Quarantine { get; }

    public SettingsViewModel Settings { get; }

    public AboutViewModel About { get; }

    public HelpViewModel Help { get; }

    public DownloadGuard Downloads { get; }

    /// <summary>Problems shown on the dashboard, each with its own Fix button.</summary>
    public ObservableCollection<ProblemViewModel> Problems { get; } = [];

    /// <summary>False in simple mode: the DNS and Downloads pages leave the sidebar.</summary>
    public bool ShowAdvancedPages => !_services.Settings.SimpleMode;

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822", Justification = "Bound from XAML, which needs an instance property; the change is raised per instance.")]
    public bool IsEnglish => Loc.Instance.Language == AppLanguage.English;

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822", Justification = "Bound from XAML, which needs an instance property; the change is raised per instance.")]
    public bool IsTurkish => Loc.Instance.Language == AppLanguage.Turkish;

    [ObservableProperty]
    public partial PageViewModel CurrentPage { get; set; }

    [ObservableProperty]
    public partial ProtectionLevel Protection { get; set; }

    [ObservableProperty]
    public partial string ProtectionHeadline { get; set; } = L.T("status.protected");

    [ObservableProperty]
    public partial string ProtectionDetail { get; set; } = string.Empty;

    [ObservableProperty]
    public partial bool ServiceAvailable { get; set; } = true;

    [ObservableProperty]
    public partial bool ScanEngineAvailable { get; set; } = true;

    public Brush ProtectionBrush => StatusBrushes.For(Protection);

    public Brush DnsBrush => Dns.IsProtecting ? StatusBrushes.For(ProtectionLevel.Protected)
        : Dns.HasError ? StatusBrushes.For(ProtectionLevel.Warning) : StatusBrushes.Neutral;

    public string DnsSummary => Dns.Summary;

    partial void OnProtectionChanged(ProtectionLevel value) => OnPropertyChanged(nameof(ProtectionBrush));

    partial void OnCurrentPageChanged(PageViewModel value) => value.OnShown();

    [RelayCommand]
    public void Navigate(NavigationTarget target) => CurrentPage = target switch
    {
        NavigationTarget.Scan => Scan,
        NavigationTarget.Dns => Dns,
        NavigationTarget.Downloads => DownloadsPage,
        NavigationTarget.Quarantine => Quarantine,
        NavigationTarget.Settings => Settings,
        NavigationTarget.About => About,
        NavigationTarget.Help => Help,
        _ => Dashboard,
    };

    /// <summary>Switches the language ("en" or "tr") everywhere at once and remembers it.</summary>
    [RelayCommand]
    public void SetLanguage(string code)
    {
        AppLanguage language = Translations.Parse(code, CultureInfo.CurrentUICulture);
        _services.UpdateSettings(s => s with { Language = Translations.Code(language) });
        Loc.Instance.SetLanguage(language);
    }

    /// <summary>Fixes everything that can be fixed with one click, in order of importance.</summary>
    [RelayCommand]
    private async Task FixAllAsync()
    {
        if (Scan.UnresolvedThreats > 0)
        {
            await Scan.QuarantineAllThreatsCommand.ExecuteAsync(null).ConfigureAwait(true);
        }

        if (!_services.Settings.DownloadProtection)
        {
            DownloadsPage.IsEnabled = true;
        }

        RefreshStatus();
    }

    private void OnLanguageChanged()
    {
        OnPropertyChanged(nameof(IsEnglish));
        OnPropertyChanged(nameof(IsTurkish));
        foreach (PageViewModel page in new PageViewModel[] { Dashboard, Scan, Dns, DownloadsPage, Quarantine, Settings, About, Help })
        {
            page.OnLanguageChanged();
        }

        RefreshStatus();
    }

    /// <summary>Recomputes the overall status (green / amber / red), the dashboard's problem list and the tray icon.</summary>
    public void RefreshStatus()
    {
        var problems = new List<ProblemViewModel>();
        int unresolved = Scan.UnresolvedThreats;
        if (unresolved > 0)
        {
            problems.Add(new ProblemViewModel(ProtectionLevel.Threat,
                unresolved == 1 ? L.T("problem.threat.one") : L.F("problem.threat.many", unresolved),
                L.T("problem.threat.detail"), L.T("problem.threat.fix"),
                () =>
                {
                    Navigate(NavigationTarget.Scan);
                    Scan.QuarantineAllThreatsCommand.Execute(null);
                }));
        }

        if (!_services.Settings.DownloadProtection)
        {
            problems.Add(new ProblemViewModel(ProtectionLevel.Warning, L.T("problem.downloads.title"), L.T("problem.downloads.detail"),
                L.T("problem.turnOn"), () => DownloadsPage.IsEnabled = true));
        }

        if (!ScanEngineAvailable)
        {
            problems.Add(new ProblemViewModel(ProtectionLevel.Warning, L.T("problem.engine.title"), L.T("problem.engine.detail"),
                L.T("problem.howToFix"), () => Navigate(NavigationTarget.Help)));
        }

        if (!ServiceAvailable)
        {
            problems.Add(new ProblemViewModel(ProtectionLevel.Warning, L.T("problem.service.title"), L.T("problem.service.detail"),
                L.T("problem.howToFix"), () => Navigate(NavigationTarget.Help)));
        }

        if (Dns.HasError)
        {
            problems.Add(new ProblemViewModel(ProtectionLevel.Warning, L.T("problem.dns.title"), L.T("problem.dns.detail"),
                L.T("problem.dns.fix"), () => Navigate(NavigationTarget.Dns)));
        }

        Problems.Clear();
        foreach (ProblemViewModel problem in problems)
        {
            Problems.Add(problem);
        }

        if (unresolved > 0)
        {
            Protection = ProtectionLevel.Threat;
            ProtectionHeadline = unresolved == 1 ? L.T("problem.threat.one") : L.F("problem.threat.many", unresolved);
            ProtectionDetail = L.T("status.threat.detail");
        }
        else if (problems.Count > 0)
        {
            Protection = ProtectionLevel.Warning;
            ProtectionHeadline = L.T("status.attention");
            ProtectionDetail = problems.Count == 1 ? problems[0].Title : L.F("status.attention.many", problems.Count);
        }
        else
        {
            Protection = ProtectionLevel.Protected;
            ProtectionHeadline = L.T("status.protected");
            ProtectionDetail = L.T("status.protected.detail");
        }

        OnPropertyChanged(nameof(DnsBrush));
        OnPropertyChanged(nameof(DnsSummary));
        OnPropertyChanged(nameof(ShowAdvancedPages));
        Dashboard.Refresh();
        _tray.Update(new TrayState(
            Protection,
            Protection switch
            {
                ProtectionLevel.Protected => L.T("tray.protected"),
                ProtectionLevel.Warning => L.T("status.attention"),
                _ => L.T("tray.threats"),
            },
            Dns.IsProtecting,
            Dns.Summary));
    }

    /// <summary>
    /// Runs the automatic quick scan when it is due (daily or weekly, see Settings). The first
    /// check waits a few minutes so it doesn't slow down signing in.
    /// </summary>
    public async Task RunScheduledScansAsync(CancellationToken cancellationToken)
    {
        TimeSpan wait = TimeSpan.FromMinutes(5);
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(wait, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            wait = TimeSpan.FromMinutes(30);
            await Application.Current.Dispatcher.InvokeAsync(async () =>
            {
                // Wait while threats from the last scan are still on screen: a new scan would replace that list.
                if (!Scan.IsScanning && Scan.UnresolvedThreats == 0
                    && ScanSchedule.IsDue(_services.Settings.AutoScan, _services.Settings.LastScanAt, DateTimeOffset.Now))
                {
                    await Scan.RunAutomaticScanAsync().ConfigureAwait(true);
                }
            }).Task.Unwrap().ConfigureAwait(false);
        }
    }

    /// <summary>Keeps a live subscription to the service's event stream, reconnecting if it restarts.</summary>
    public async Task ListenToServiceAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await foreach (ServiceEvent serviceEvent in _services.Service.SubscribeAsync(cancellationToken).ConfigureAwait(false))
                {
                    await Application.Current.Dispatcher.InvokeAsync(() =>
                    {
                        if (!ServiceAvailable)
                        {
                            ServiceAvailable = true;
                            RefreshStatus();
                        }

                        Handle(serviceEvent);
                    });
                }
            }
            catch (Exception ex) when (ex is IpcException or IOException or InvalidDataException or System.Text.Json.JsonException
                                       or UnauthorizedAccessException or TimeoutException)
            {
            }
            catch (OperationCanceledException)
            {
                return;
            }

            await Application.Current.Dispatcher.InvokeAsync(() =>
            {
                if (ServiceAvailable)
                {
                    ServiceAvailable = false;
                    Dns.ServiceUnavailable();
                    RefreshStatus();
                }
            });

            try
            {
                await Task.Delay(TimeSpan.FromSeconds(5), cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    /// <summary>Checks the scan engine every few minutes so the status reflects reality.</summary>
    public async Task MonitorEnginesAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            EngineStatus status = await _services.ClamAv.GetStatusAsync(cancellationToken).ConfigureAwait(false);
            await _services.ThreatDatabase.GetStatusAsync(cancellationToken).ConfigureAwait(false);
            ThreatCoverage coverage = ThreatCoverage.From(_services.ThreatDatabase.Manifest, _services.Yara.CountRules());
            await Application.Current.Dispatcher.InvokeAsync(() =>
            {
                Dashboard.EngineText = status.Description;
                Dashboard.Coverage = coverage;
                if (ScanEngineAvailable != status.Available)
                {
                    ScanEngineAvailable = status.Available;
                    RefreshStatus();
                }
            });

            try
            {
                await _services.MalwareHosts.RefreshAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is System.Net.Http.HttpRequestException or IOException or TaskCanceledException && !cancellationToken.IsCancellationRequested)
            {
            }

            try
            {
                await Task.Delay(TimeSpan.FromMinutes(3), cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    public void NotifyAutomaticScanThreats(int threats) =>
        _notifier.Show(NotificationLevel.Threat, L.F("autoScan.threats.title", threats), L.T("autoScan.threats.text"), NavigationTarget.Scan);

    private void Handle(ServiceEvent serviceEvent)
    {
        switch (serviceEvent.Kind)
        {
            case ServiceEventKind.DnsStatusChanged when serviceEvent.Dns is { } status:
                Dns.ApplyStatus(status);
                RefreshStatus();
                break;

            case ServiceEventKind.ElevationGranted when _services.Settings.AdminRightsAlerts:
                _ = ReportElevationAsync(serviceEvent);
                break;

            case ServiceEventKind.ServiceInstalled when _services.Settings.AdminRightsAlerts:
                string service = serviceEvent.ProgramName ?? L.T("admin.aNewService");
                string publisher = serviceEvent.Publisher is { } p ? L.F("admin.signedBy", p) : L.T("admin.notSigned");
                _services.Activity.Add(new ActivityEntry(serviceEvent.At, ActivityKind.AdminRights,
                    serviceEvent.Publisher is null ? ActivityLevel.Warning : ActivityLevel.Info,
                    L.F("admin.serviceInstalled.activity", service), $"{serviceEvent.ProgramPath} ({publisher})"));
                _notifier.Show(serviceEvent.Publisher is null ? NotificationLevel.Warning : NotificationLevel.Info,
                    L.T("admin.serviceInstalled.title"), L.F("admin.serviceInstalled.text", service, publisher),
                    NavigationTarget.Dashboard);
                break;
        }
    }

    /// <summary>Tells the user something got administrator rights, and checks that program for malware.</summary>
    private async Task ReportElevationAsync(ServiceEvent alert)
    {
        string name = alert.ProgramName ?? L.T("admin.aProgram");
        bool trusted = alert.SignatureState == nameof(SignatureState.Trusted);
        string who = trusted && alert.Publisher is { } publisher ? L.F("admin.signedBy", publisher) : L.T("admin.notSigned");
        string from = alert.ParentName is { } parent ? " " + L.F("admin.startedBy", parent) : string.Empty;

        FileScanResult? scan = null;
        if (alert.ProgramPath is { } path && File.Exists(path))
        {
            try
            {
                scan = (await _services.CreateScanner(forDownloads: false).ScanFileAsync(path, _services.CreateScanOptions(), CancellationToken.None).ConfigureAwait(false)).Result;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
            }
        }

        if (scan?.Verdict == Severity.Malicious)
        {
            Detection worst = scan.Detections.MaxBy(d => d.Severity)!;
            _services.Activity.Add(new ActivityEntry(alert.At, ActivityKind.AdminRights, ActivityLevel.Threat,
                L.F("admin.malware.title", name), $"{worst.Name}. {alert.ProgramPath}"));
            _notifier.Show(NotificationLevel.Threat, L.F("admin.malware.title", name),
                L.F("admin.malware.text", worst.Name), NavigationTarget.Scan);
            return;
        }

        _services.Activity.Add(new ActivityEntry(alert.At, ActivityKind.AdminRights, trusted ? ActivityLevel.Info : ActivityLevel.Warning,
            L.F("admin.granted.activity", name), $"{alert.ProgramPath} ({who}).{from}"));
        _notifier.Show(trusted ? NotificationLevel.Info : NotificationLevel.Warning,
            L.F("admin.granted.title", name),
            L.F("admin.granted.text", who) + from,
            NavigationTarget.Dashboard);
    }
}
