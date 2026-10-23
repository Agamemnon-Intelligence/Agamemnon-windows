using System.Globalization;
using System.Windows;
using System.Windows.Threading;
using Agamemnon.App.Localization;
using Agamemnon.App.Services;
using Agamemnon.App.ViewModels;
using Agamemnon.App.Views;
using Agamemnon.Core.Dns;
using Agamemnon.Core.Ipc;
using Agamemnon.Core.Localization;
using Agamemnon.Core.Quarantine;
using Agamemnon.Core.Scanning;
using Agamemnon.Platform.Windows;

namespace Agamemnon.App;

/// <summary>
/// Agamemnon.exe lives in the notification area while the user is signed in (download blocking
/// and alerts need it running); the window opens on demand. Two extra modes run elevated for a
/// moment and exit: applying a custom DNS server and quarantining a protected file.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1001", Justification = "Disposed in OnExit, the Application lifetime hook.")]
public partial class App : Application
{
    private const string InstanceName = @"Local\Agamemnon.App";
    private const string ActivateName = @"Local\Agamemnon.App.Activate";

    private readonly CancellationTokenSource _lifetime = new();
    private Mutex? _instance;
    private EventWaitHandle? _activate;
    private AppServices? _services;
    private TrayIcon? _tray;
    private DownloadGuard? _downloads;
    private RealTimeGuards? _guards;
    private MainViewModel? _model;
    private MainWindow? _window;
    private bool _upgradedFrom2;
    private bool _welcomeOpen;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        string[] args = e.Args;

        if (args.Length == 2 && args[0] == ElevatedActions.ApplyDnsSwitch)
        {
            Shutdown(await ApplyDnsElevatedAsync(args[1]).ConfigureAwait(true));
            return;
        }

        if (args.Length == 2 && args[0] == ElevatedActions.QuarantineSwitch)
        {
            Shutdown(QuarantineElevated(args[1]));
            return;
        }

        // "Scan with Agamemnon" from File Explorer's right-click menu: Agamemnon.exe --scan <paths>.
        string[] scanPaths = args.Length > 1 && args[0] == ScanRequests.Switch ? args[1..] : [];

        _instance = new Mutex(initiallyOwned: true, InstanceName, out bool firstInstance);
        if (!firstInstance)
        {
            if (scanPaths.Length > 0)
            {
                ScanRequests.Queue(scanPaths);
            }

            // Already running in the notification area: ask it to show its window.
            try
            {
                using EventWaitHandle existing = EventWaitHandle.OpenExisting(ActivateName);
                existing.Set();
            }
            catch (WaitHandleCannotBeOpenedException)
            {
            }

            Shutdown();
            return;
        }

        DispatcherUnhandledException += OnUnhandledException;

        _services = new AppServices();
        Loc.Instance.SetLanguage(Translations.Parse(_services.Settings.Language, CultureInfo.CurrentUICulture));
        _tray = new TrayIcon();
        var notifier = new Notifier(_tray);
        _downloads = new DownloadGuard(_services, notifier);
        _guards = new RealTimeGuards(_services, notifier);
        _model = new MainViewModel(_services, _tray, notifier, _downloads, _guards, new UpdateService(_services));

        _tray.OpenRequested += (_, target) => ShowMain(target);
        _tray.QuickScanRequested += (_, _) =>
        {
            ShowMain(NavigationTarget.Scan);
            _model.Scan.QuickScanCommand.Execute(null);
        };
        _tray.ToggleDnsRequested += (_, _) => _model.Dns.ToggleCommand.Execute(null);
        _tray.QuitRequested += (_, _) => Quit();
        _model.Settings.WelcomeRequested += (_, _) => ShowWelcome();

        _upgradedFrom2 = FirstRunSetup(_services);
        _downloads.Restart();
        _guards.Restart();
        _ = _model.ListenToServiceAsync(_lifetime.Token);
        _ = _model.MonitorEnginesAsync(_lifetime.Token);
        _ = _model.RunScheduledScansAsync(_lifetime.Token);
        _ = _model.RunPeriodicChecksAsync(_lifetime.Token);
        ListenForActivation();

        if (scanPaths.Length > 0)
        {
            ScanRequests.Queue(scanPaths);
            ShowMain(NavigationTarget.Scan);
            RunQueuedScans();
        }
        else if (!args.Contains("--background"))
        {
            ShowMain(NavigationTarget.Dashboard);
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _lifetime.Cancel();
        _downloads?.Dispose();
        _guards?.Dispose();
        _tray?.Dispose();
        _services?.Dispose();
        _activate?.Dispose();
        _instance?.Dispose();
        _lifetime.Dispose();
        base.OnExit(e);
    }

    /// <summary>One-time setup for this Windows user; returns true when they already used an earlier version.</summary>
    private static bool FirstRunSetup(AppServices services)
    {
        string marker = Path.Combine(AgamemnonPaths.UserSettings, ".initialized");
        if (File.Exists(marker))
        {
            return true;
        }

        if (services.Settings.StartAtLogin)
        {
            AutoStart.Set(true);
        }

        Directory.CreateDirectory(AgamemnonPaths.UserSettings);
        File.WriteAllText(marker, DateTimeOffset.Now.ToString("O"));
        return false;
    }

    private void ShowMain(NavigationTarget target)
    {
        if (_model is null)
        {
            return;
        }

        _window ??= new MainWindow(_model);
        _model.Navigate(target);
        if (_window.WindowState == WindowState.Minimized)
        {
            _window.WindowState = WindowState.Normal;
        }

        _window.Show();
        _window.Activate();

        if (_services?.Settings.WelcomeVersion < WelcomeViewModel.CurrentWelcome)
        {
            ShowWelcome();
        }
    }

    /// <summary>The welcome guide: once after installing or upgrading, and again from Settings or Help.</summary>
    private void ShowWelcome()
    {
        if (_model is null || _services is null || _welcomeOpen)
        {
            return;
        }

        _welcomeOpen = true;
        try
        {
            var welcome = new WelcomeWindow(new WelcomeViewModel(_services, _model, _upgradedFrom2));
            if (_window is { IsVisible: true })
            {
                welcome.Owner = _window;
            }
            else
            {
                welcome.WindowStartupLocation = WindowStartupLocation.CenterScreen;
            }

            welcome.ShowDialog();
        }
        finally
        {
            _welcomeOpen = false;
        }
    }

    private void ListenForActivation()
    {
        _activate = new EventWaitHandle(false, EventResetMode.AutoReset, ActivateName);
        var thread = new Thread(() =>
        {
            while (!_lifetime.IsCancellationRequested)
            {
                if (WaitHandle.WaitAny([_activate, _lifetime.Token.WaitHandle]) == 0)
                {
                    Dispatcher.BeginInvoke(() =>
                    {
                        if (ScanRequests.HasPending)
                        {
                            ShowMain(NavigationTarget.Scan);
                            RunQueuedScans();
                        }
                        else
                        {
                            ShowMain(NavigationTarget.Dashboard);
                        }
                    });
                }
            }
        })
        { IsBackground = true, Name = "Agamemnon activation" };
        thread.Start();
    }

    /// <summary>Scans files and folders sent from File Explorer (several requests become one scan).</summary>
    private void RunQueuedScans()
    {
        IReadOnlyList<string> paths = ScanRequests.TakeAll();
        if (_model is not null && paths.Count > 0)
        {
            _ = _model.Scan.ScanDroppedAsync(paths);
        }
    }

    private void Quit()
    {
        if (_window is not null)
        {
            _window.AllowClose = true;
            _window.Close();
        }

        Shutdown();
    }

    private void OnUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        // Keep protection running; tell the user what went wrong.
        e.Handled = true;
        _tray?.Notify(NotificationLevel.Warning, L.T("app.unexpectedProblem"), e.Exception.Message, NavigationTarget.Dashboard);
    }

    /// <summary>Elevated helper: apply a custom DNS server (the service requires an elevated caller for that).</summary>
    private static async Task<int> ApplyDnsElevatedAsync(string argument)
    {
        try
        {
            DnsSettings settings = ElevatedActions.DecodeDns(argument);
            await new IpcClient(verifyServer: PipeServerCheck.IsService).CallAsync<DnsStatus>(IpcMethods.ApplyDns, settings, CancellationToken.None).ConfigureAwait(false);
            return 0;
        }
        catch (Exception ex) when (ex is IpcException or FormatException or InvalidDataException or System.Text.Json.JsonException or DnsConfigurationException)
        {
            MessageBox.Show(ex.Message, "Agamemnon", MessageBoxButton.OK, MessageBoxImage.Error);
            return 1;
        }
    }

    /// <summary>Elevated helper: quarantine a file the user can't move themselves (e.g. under Program Files).</summary>
    private static int QuarantineElevated(string argument)
    {
        try
        {
            string path = ElevatedActions.DecodePath(argument);
            var store = new QuarantineStore(AgamemnonPaths.Quarantine, new DpapiKeyProtector());
            store.Add(path, [new Detection("Agamemnon", "Quarantined with administrator approval", Severity.Suspicious)]);
            return 0;
        }
        catch (Exception ex) when (ex is QuarantineException or FormatException or IOException or UnauthorizedAccessException)
        {
            MessageBox.Show(ex.Message, "Agamemnon", MessageBoxButton.OK, MessageBoxImage.Error);
            return 1;
        }
    }
}
