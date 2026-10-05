using System.Windows;
using System.Windows.Media;
using Agamemnon.App.Services;
using Agamemnon.Core.Ipc;
using Agamemnon.Core.Scanning;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Agamemnon.App.ViewModels;

public abstract partial class PageViewModel : ObservableObject
{
    public abstract string Title { get; }

    /// <summary>Called whenever the page is shown.</summary>
    public virtual void OnShown()
    {
    }
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
        Dashboard = new DashboardViewModel(services, this);
        CurrentPage = Dashboard;

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

    public DownloadGuard Downloads { get; }

    [ObservableProperty]
    public partial PageViewModel CurrentPage { get; set; }

    [ObservableProperty]
    public partial ProtectionLevel Protection { get; set; }

    [ObservableProperty]
    public partial string ProtectionHeadline { get; set; } = "You're protected";

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
        _ => Dashboard,
    };

    /// <summary>Recomputes the overall status (green / amber / red) and pushes it to the tray icon.</summary>
    public void RefreshStatus()
    {
        var warnings = new List<string>();
        if (!_services.Settings.DownloadProtection)
        {
            warnings.Add("Download protection is off.");
        }

        if (!ScanEngineAvailable)
        {
            warnings.Add("The ClamAV scan engine isn't running.");
        }

        if (!ServiceAvailable)
        {
            warnings.Add("The Agamemnon service isn't running.");
        }

        if (Dns.HasError)
        {
            warnings.Add("Encrypted DNS hit a problem.");
        }

        int unresolved = Scan.UnresolvedThreats;
        if (unresolved > 0)
        {
            Protection = ProtectionLevel.Threat;
            ProtectionHeadline = unresolved == 1 ? "1 threat needs your attention" : $"{unresolved} threats need your attention";
            ProtectionDetail = "Review the scan results and move threats to quarantine.";
        }
        else if (warnings.Count > 0)
        {
            Protection = ProtectionLevel.Warning;
            ProtectionHeadline = "Attention needed";
            ProtectionDetail = string.Join(" ", warnings);
        }
        else
        {
            Protection = ProtectionLevel.Protected;
            ProtectionHeadline = "You're protected";
            ProtectionDetail = "Downloads are checked as they arrive.";
        }

        OnPropertyChanged(nameof(DnsBrush));
        OnPropertyChanged(nameof(DnsSummary));
        Dashboard.Refresh();
        _tray.Update(new TrayState(
            Protection,
            Protection switch
            {
                ProtectionLevel.Protected => "Protected",
                ProtectionLevel.Warning => "Attention needed",
                _ => "Threats found",
            },
            Dns.IsProtecting,
            Dns.Summary));
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
            await Application.Current.Dispatcher.InvokeAsync(() =>
            {
                Dashboard.EngineText = status.Description;
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
                string service = serviceEvent.ProgramName ?? "A new service";
                string publisher = serviceEvent.Publisher is { } p ? $"signed by {p}" : "not signed by a trusted publisher";
                _services.Activity.Add(new ActivityEntry(serviceEvent.At, ActivityKind.AdminRights,
                    serviceEvent.Publisher is null ? ActivityLevel.Warning : ActivityLevel.Info,
                    $"New system service installed: {service}", $"{serviceEvent.ProgramPath} ({publisher})"));
                _notifier.Show(serviceEvent.Publisher is null ? NotificationLevel.Warning : NotificationLevel.Info,
                    "A program installed a system service", $"{service}, {publisher}. Services run with full control of this PC.",
                    NavigationTarget.Dashboard);
                break;
        }
    }

    /// <summary>Tells the user something got administrator rights, and checks that program for malware.</summary>
    private async Task ReportElevationAsync(ServiceEvent alert)
    {
        string name = alert.ProgramName ?? "A program";
        bool trusted = alert.SignatureState == nameof(SignatureState.Trusted);
        string who = trusted && alert.Publisher is { } publisher ? $"signed by {publisher}" : "not signed by a trusted publisher";
        string from = alert.ParentName is { } parent ? $" Started by {parent}." : string.Empty;

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
                $"Malware got administrator rights: {name}", $"{worst.Name}. {alert.ProgramPath}"));
            _notifier.Show(NotificationLevel.Threat, $"Malware got administrator rights: {name}",
                $"{worst.Name}. Disconnect from the internet and run a full scan.", NavigationTarget.Scan);
            return;
        }

        _services.Activity.Add(new ActivityEntry(alert.At, ActivityKind.AdminRights, trusted ? ActivityLevel.Info : ActivityLevel.Warning,
            $"{name} was given administrator rights", $"{alert.ProgramPath} ({who}).{from}"));
        _notifier.Show(trusted ? NotificationLevel.Info : NotificationLevel.Warning,
            $"{name} now has administrator rights",
            $"It is {who} and can change anything on this PC.{from}",
            NavigationTarget.Dashboard);
    }
}
