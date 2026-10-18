using Agamemnon.App.Localization;
using Agamemnon.App.Services;
using Agamemnon.Core.Localization;
using Agamemnon.Core.Settings;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Agamemnon.App.ViewModels;

/// <summary>
/// The welcome guide, shown once after installing or upgrading to 3.0: pick a language, accept
/// the recommended protection with one click, and optionally run the first scan.
/// </summary>
public sealed partial class WelcomeViewModel : ObservableObject
{
    private const int LastStep = 2;
    private readonly AppServices _services;
    private readonly MainViewModel _main;

    public WelcomeViewModel(AppServices services, MainViewModel main, bool upgrading)
    {
        _services = services;
        _main = main;
        IsUpgrade = upgrading;

        // People upgrading from 2.0 keep what they set up; new installs get every protection on.
        AppSettings settings = services.Settings;
        DownloadProtection = !upgrading || settings.DownloadProtection;
        StartWithWindows = !upgrading || settings.StartAtLogin;
        AdminRightsAlerts = !upgrading || settings.AdminRightsAlerts;
        EncryptedDns = !upgrading || main.Dns.IsEnabled;
        AutomaticScans = !upgrading || settings.AutoScan != AutoScanFrequency.Off;
        SimpleMode = !upgrading || settings.SimpleMode;
        ScanNow = settings.LastScanAt is null;
        Loc.Instance.LanguageChanged += OnLanguageChanged;
        main.Dns.PropertyChanged += OnDnsChanged;
    }

    /// <summary>Raised when the guide is finished; the window closes.</summary>
    public event EventHandler? Finished;

    public bool IsUpgrade { get; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsLanguageStep), nameof(IsSetupStep), nameof(IsDoneStep), nameof(CanGoBack), nameof(StepText), nameof(NextLabel))]
    public partial int Step { get; set; }

    public bool IsLanguageStep => Step == 0;

    public bool IsSetupStep => Step == 1;

    public bool IsDoneStep => Step == LastStep;

    public bool CanGoBack => Step > 0;

    public string StepText => L.F("welcome.step", Step + 1, LastStep + 1);

    public string NextLabel => Step == LastStep ? L.T("welcome.finish") : L.T("welcome.next");

    public string Headline => IsUpgrade ? L.T("welcome.headline.upgrade") : L.T("welcome.headline.new");

    public bool IsEnglish
    {
        get => Loc.Instance.Language == AppLanguage.English;
        set
        {
            if (value)
            {
                _main.SetLanguage("en");
            }
        }
    }

    public bool IsTurkish
    {
        get => Loc.Instance.Language == AppLanguage.Turkish;
        set
        {
            if (value)
            {
                _main.SetLanguage("tr");
            }
        }
    }

    [ObservableProperty]
    public partial bool DownloadProtection { get; set; }

    [ObservableProperty]
    public partial bool StartWithWindows { get; set; }

    [ObservableProperty]
    public partial bool AdminRightsAlerts { get; set; }

    [ObservableProperty]
    public partial bool EncryptedDns { get; set; }

    [ObservableProperty]
    public partial bool AutomaticScans { get; set; }

    [ObservableProperty]
    public partial bool SimpleMode { get; set; }

    [ObservableProperty]
    public partial bool ScanNow { get; set; }

    public bool DnsAvailable => _main.Dns.ServiceReady;

    [RelayCommand]
    private void Recommended()
    {
        DownloadProtection = true;
        StartWithWindows = true;
        AdminRightsAlerts = true;
        EncryptedDns = DnsAvailable;
        AutomaticScans = true;
        Step = LastStep;
    }

    [RelayCommand]
    private void Back()
    {
        if (Step > 0)
        {
            Step--;
        }
    }

    [RelayCommand]
    private async Task NextAsync()
    {
        if (Step < LastStep)
        {
            Step++;
            return;
        }

        await FinishAsync().ConfigureAwait(true);
    }

    private async Task FinishAsync()
    {
        AppSettings before = _services.Settings;
        _services.UpdateSettings(s => s with
        {
            Language = Translations.Code(Loc.Instance.Language),
            DownloadProtection = DownloadProtection,
            StartAtLogin = StartWithWindows,
            AdminRightsAlerts = AdminRightsAlerts,
            AutoScan = !AutomaticScans ? AutoScanFrequency.Off
                : s.AutoScan == AutoScanFrequency.Off ? AutoScanFrequency.Weekly : s.AutoScan,
            SimpleMode = SimpleMode,
            WelcomeCompleted = true,
        });
        AutoStart.Set(StartWithWindows);
        if (before.DownloadProtection != DownloadProtection)
        {
            _main.Downloads.Restart();
        }

        Finished?.Invoke(this, EventArgs.Empty);
        _main.Navigate(NavigationTarget.Dashboard);

        if (EncryptedDns && DnsAvailable && !_main.Dns.IsEnabled)
        {
            // Cloudflare's security resolver also refuses to look up known malware and phishing sites.
            await _main.Dns.TurnOnAsync("cloudflare-security").ConfigureAwait(true);
        }
        else if (!EncryptedDns && _main.Dns.IsEnabled)
        {
            _main.Dns.IsEnabled = false;
        }

        if (ScanNow)
        {
            _main.Navigate(NavigationTarget.Scan);
            _main.Scan.QuickScanCommand.Execute(null);
        }
    }

    /// <summary>Stops following language changes once the window is gone.</summary>
    public void Detach()
    {
        Loc.Instance.LanguageChanged -= OnLanguageChanged;
        _main.Dns.PropertyChanged -= OnDnsChanged;
    }

    private void OnLanguageChanged(object? sender, EventArgs e) => OnPropertyChanged(string.Empty);

    /// <summary>The service usually answers a moment after the guide opens.</summary>
    private void OnDnsChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(DnsViewModel.ServiceReady))
        {
            OnPropertyChanged(nameof(DnsAvailable));
        }
        else if (e.PropertyName == nameof(DnsViewModel.IsEnabled) && IsUpgrade && _main.Dns.IsEnabled)
        {
            EncryptedDns = true;
        }
    }

    /// <summary>Closing the window early still counts: the guide shouldn't come back at every start.</summary>
    public void Dismiss() =>
        _services.UpdateSettings(s => s with { WelcomeCompleted = true, Language = Translations.Code(Loc.Instance.Language) });
}
