using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using Agamemnon.App.Localization;
using Agamemnon.App.Services;
using Agamemnon.Core.Localization;
using Agamemnon.Core.Quarantine;
using Agamemnon.Core.Scanning;
using Agamemnon.Core.Settings;
using Agamemnon.Platform.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;

namespace Agamemnon.App.ViewModels;

public sealed record FolderRow(string Path, bool CanRemove);

public sealed partial class DownloadsViewModel : PageViewModel
{
    private readonly AppServices _services;
    private readonly DownloadGuard _guard;

    public DownloadsViewModel(AppServices services, DownloadGuard guard)
    {
        _services = services;
        _guard = guard;
        RecentDownloads = new ListCollectionView(services.Activity.Entries)
        {
            Filter = item => item is ActivityEntry { Kind: ActivityKind.Download },
        };
        guard.StateChanged += (_, _) => Application.Current.Dispatcher.BeginInvoke(() => OnPropertyChanged(nameof(CheckedText)));
    }

    public override NavigationTarget Target => NavigationTarget.Downloads;

    public ICollectionView RecentDownloads { get; }

    public ObservableCollection<FolderRow> Folders { get; } = [];

    public bool IsEnabled
    {
        get => _services.Settings.DownloadProtection;
        set
        {
            _services.UpdateSettings(s => s with { DownloadProtection = value });
            _guard.Restart();
            OnPropertyChanged();
        }
    }

    public bool BlockUnsigned
    {
        get => _services.Settings.UnsignedDownloads == UnsignedDownloadPolicy.Block;
        set
        {
            _services.UpdateSettings(s => s with { UnsignedDownloads = value ? UnsignedDownloadPolicy.Block : UnsignedDownloadPolicy.Warn });
            OnPropertyChanged();
            OnPropertyChanged(nameof(WarnUnsigned));
        }
    }

    public bool WarnUnsigned
    {
        get => !BlockUnsigned;
        set => BlockUnsigned = !value;
    }

    public bool CheckSource
    {
        get => _services.Settings.CheckDownloadSource;
        set
        {
            _services.UpdateSettings(s => s with { CheckDownloadSource = value });
            OnPropertyChanged();
        }
    }

    public string CheckedText => L.F("downloads.checked", _guard.CheckedToday)
        + (_services.MalwareHosts.Count > 0 ? " " + L.F("downloads.blocklist", _services.MalwareHosts.Count) : string.Empty);

    public override void OnShown()
    {
        Folders.Clear();
        foreach (string folder in _guard.WatchedFolders)
        {
            Folders.Add(new FolderRow(folder, !folder.Equals(DownloadGuard.DefaultDownloadsFolder, StringComparison.OrdinalIgnoreCase)));
        }

        OnPropertyChanged(nameof(CheckedText));
    }

    [RelayCommand]
    private void AddFolder()
    {
        var dialog = new OpenFolderDialog { Title = L.T("downloads.dialog.addFolder") };
        if (dialog.ShowDialog() != true)
        {
            return;
        }

        _services.UpdateSettings(s => s with { ExtraDownloadFolders = [.. s.ExtraDownloadFolders.Append(dialog.FolderName).Distinct(StringComparer.OrdinalIgnoreCase)] });
        _guard.Restart();
        OnShown();
    }

    [RelayCommand]
    private void RemoveFolder(FolderRow row)
    {
        _services.UpdateSettings(s => s with { ExtraDownloadFolders = [.. s.ExtraDownloadFolders.Where(f => !f.Equals(row.Path, StringComparison.OrdinalIgnoreCase))] });
        _guard.Restart();
        OnShown();
    }
}

public sealed partial class QuarantineRow(QuarantineItem item, QuarantineViewModel owner)
{
    public QuarantineItem Item => item;

    public string FileName => item.FileName;

    public string OriginalPath => item.OriginalPath;

    public string When => item.QuarantinedAt.ToLocalTime().ToString("g", CultureInfo.CurrentCulture);

    public string Reason => item.Summary;

    public string Source => item.Source == "Download" ? L.T("quarantine.source.download") : L.T("quarantine.source.scan");

    public Brush Brush => StatusBrushes.For(item.Detections.Count == 0 ? Severity.Suspicious : item.Detections.Max(d => d.Severity));

    [RelayCommand]
    private void Restore() => owner.Restore(this);

    [RelayCommand]
    private void Delete() => owner.Delete(this);
}

public sealed partial class QuarantineViewModel : PageViewModel
{
    private readonly AppServices _services;

    public QuarantineViewModel(AppServices services)
    {
        _services = services;
        services.Quarantine.Changed += (_, _) => Application.Current.Dispatcher.BeginInvoke(Reload);
    }

    public override NavigationTarget Target => NavigationTarget.Quarantine;

    public ObservableCollection<QuarantineRow> Items { get; } = [];

    public bool IsEmpty => Items.Count == 0;

    [ObservableProperty]
    public partial string? Message { get; set; }

    public override void OnShown() => Reload();

    public void Restore(QuarantineRow row)
    {
        MessageBoxResult answer = MessageBox.Show(
            L.F("quarantine.restore.confirm", row.FileName, row.OriginalPath, row.Reason),
            L.T("quarantine.restore.title"), MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
        if (answer != MessageBoxResult.Yes)
        {
            return;
        }

        try
        {
            // Trust first, so the download watcher doesn't put it straight back.
            _services.Trust(row.Item.Sha256);
            string restored = _services.Quarantine.Restore(row.Item.Id);
            Message = L.F("quarantine.restored", restored);
            _services.Activity.Add(new ActivityEntry(DateTimeOffset.Now, ActivityKind.Quarantine, ActivityLevel.Warning, L.F("activity.restored", row.FileName), restored));
        }
        catch (Exception ex) when (ex is QuarantineException or IOException or UnauthorizedAccessException)
        {
            Message = ex.Message;
        }
    }

    public void Delete(QuarantineRow row)
    {
        if (MessageBox.Show(L.F("quarantine.delete.confirm", row.FileName), L.T("quarantine.delete.title"),
                MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes)
        {
            return;
        }

        _services.Quarantine.Delete(row.Item.Id);
        Message = L.F("quarantine.deleted", row.FileName);
    }

    [RelayCommand]
    private void DeleteAll()
    {
        if (Items.Count == 0 || MessageBox.Show(L.F("quarantine.deleteAll.confirm", Items.Count), L.T("quarantine.deleteAll.title"),
                MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes)
        {
            return;
        }

        foreach (QuarantineRow row in Items.ToList())
        {
            _services.Quarantine.Delete(row.Item.Id);
        }

        Message = L.T("quarantine.emptied");
    }

    private void Reload()
    {
        Items.Clear();
        foreach (QuarantineItem item in _services.Quarantine.List())
        {
            Items.Add(new QuarantineRow(item, this));
        }

        OnPropertyChanged(nameof(IsEmpty));
    }
}

public sealed record EngineRow(string Name, string Description, Brush Brush);

public sealed partial class SettingsViewModel(AppServices services, MainViewModel main) : PageViewModel
{
    public override NavigationTarget Target => NavigationTarget.Settings;

    public ObservableCollection<EngineRow> Engines { get; } = [];

    public ObservableCollection<string> Exclusions { get; } = [];

    [ObservableProperty]
    public partial string NewVirusTotalKey { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string NewMalwareBazaarKey { get; set; } = string.Empty;

    public bool HasVirusTotalKey => services.Secrets.GetSecret(SecretNames.VirusTotalApiKey) is not null;

    public bool HasMalwareBazaarKey => services.Secrets.GetSecret(SecretNames.MalwareBazaarAuthKey) is not null;

    public string TrustedText => L.F("settings.trusted.count", services.Settings.AllowedHashes.Count);

    public bool IsEnglish
    {
        get => Loc.Instance.Language == AppLanguage.English;
        set
        {
            if (value)
            {
                main.SetLanguage("en");
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
                main.SetLanguage("tr");
            }
        }
    }

    public bool SimpleMode
    {
        get => services.Settings.SimpleMode;
        set
        {
            services.UpdateSettings(s => s with { SimpleMode = value });
            OnPropertyChanged();
        }
    }

    public bool AutoScanOff
    {
        get => services.Settings.AutoScan == AutoScanFrequency.Off;
        set => SetAutoScan(value, AutoScanFrequency.Off);
    }

    public bool AutoScanDaily
    {
        get => services.Settings.AutoScan == AutoScanFrequency.Daily;
        set => SetAutoScan(value, AutoScanFrequency.Daily);
    }

    public bool AutoScanWeekly
    {
        get => services.Settings.AutoScan == AutoScanFrequency.Weekly;
        set => SetAutoScan(value, AutoScanFrequency.Weekly);
    }

    public bool HashLookups
    {
        get => services.Settings.HashLookups;
        set
        {
            services.UpdateSettings(s => s with { HashLookups = value });
            OnPropertyChanged();
        }
    }

    public bool AdminRightsAlerts
    {
        get => services.Settings.AdminRightsAlerts;
        set
        {
            services.UpdateSettings(s => s with { AdminRightsAlerts = value });
            OnPropertyChanged();
        }
    }

    public bool StartAtLogin
    {
        get => AutoStart.IsEnabled;
        set
        {
            AutoStart.Set(value);
            services.UpdateSettings(s => s with { StartAtLogin = value });
            OnPropertyChanged();
        }
    }

    public override void OnShown()
    {
        Exclusions.Clear();
        foreach (string path in services.Settings.ScanExclusions)
        {
            Exclusions.Add(path);
        }

        OnPropertyChanged(nameof(HasVirusTotalKey));
        OnPropertyChanged(nameof(HasMalwareBazaarKey));
        OnPropertyChanged(nameof(TrustedText));
        _ = RefreshEnginesAsync();
    }

    /// <summary>Raised when the user asks to see the welcome guide again.</summary>
    public event EventHandler? WelcomeRequested;

    private void SetAutoScan(bool selected, AutoScanFrequency frequency)
    {
        if (!selected)
        {
            return;
        }

        services.UpdateSettings(s => s with { AutoScan = frequency });
        OnPropertyChanged(nameof(AutoScanOff));
        OnPropertyChanged(nameof(AutoScanDaily));
        OnPropertyChanged(nameof(AutoScanWeekly));
    }

    [RelayCommand]
    private void ShowWelcome() => WelcomeRequested?.Invoke(this, EventArgs.Empty);

    [RelayCommand]
    private void Open(NavigationTarget target) => main.Navigate(target);

    [RelayCommand]
    private async Task RefreshEnginesAsync()
    {
        var statuses = await services.CreateScanner(forDownloads: true).GetEngineStatusAsync(CancellationToken.None).ConfigureAwait(true);
        Engines.Clear();
        foreach ((string name, EngineStatus status) in statuses)
        {
            Engines.Add(new EngineRow(name, status.Description,
                status.Available ? StatusBrushes.For(ProtectionLevel.Protected) : StatusBrushes.For(ProtectionLevel.Warning)));
        }
    }

    [RelayCommand]
    private void SaveVirusTotalKey()
    {
        services.Secrets.SetSecret(SecretNames.VirusTotalApiKey, NewVirusTotalKey);
        NewVirusTotalKey = string.Empty;
        OnShown();
    }

    [RelayCommand]
    private void RemoveVirusTotalKey()
    {
        services.Secrets.SetSecret(SecretNames.VirusTotalApiKey, null);
        OnShown();
    }

    [RelayCommand]
    private void SaveMalwareBazaarKey()
    {
        services.Secrets.SetSecret(SecretNames.MalwareBazaarAuthKey, NewMalwareBazaarKey);
        NewMalwareBazaarKey = string.Empty;
        OnShown();
    }

    [RelayCommand]
    private void RemoveMalwareBazaarKey()
    {
        services.Secrets.SetSecret(SecretNames.MalwareBazaarAuthKey, null);
        OnShown();
    }

    [RelayCommand]
    private void AddExclusion()
    {
        var dialog = new OpenFolderDialog { Title = L.T("settings.exclusions.dialog") };
        if (dialog.ShowDialog() == true)
        {
            services.UpdateSettings(s => s with { ScanExclusions = [.. s.ScanExclusions.Append(dialog.FolderName).Distinct(StringComparer.OrdinalIgnoreCase)] });
            OnShown();
        }
    }

    [RelayCommand]
    private void RemoveExclusion(string path)
    {
        services.UpdateSettings(s => s with { ScanExclusions = [.. s.ScanExclusions.Where(p => p != path)] });
        OnShown();
    }

    [RelayCommand]
    private void ClearTrusted()
    {
        services.UpdateSettings(s => s with { AllowedHashes = [] });
        OnPropertyChanged(nameof(TrustedText));
    }

    [RelayCommand]
    private static void OpenRulesFolder()
    {
        Directory.CreateDirectory(AgamemnonPaths.UserRules);
        Shell.Open(AgamemnonPaths.UserRules);
    }

    [RelayCommand]
    private static void OpenLink(string url) => Shell.Open(url);

    [RelayCommand]
    private void ShowAbout() => main.Navigate(NavigationTarget.About);
}

public sealed record Credit(string Name, string Url);

public sealed record Component(string Name, string License, string Url);

public sealed partial class AboutViewModel : PageViewModel
{
    public override NavigationTarget Target => NavigationTarget.About;

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822", Justification = "Bound from XAML, which needs an instance property; the change is raised per instance.")]
    public string Version => L.F("about.version", AppServices.Version);

    public IReadOnlyList<Credit> Credits { get; } =
    [
        new("github.com/mirazbakis", "https://github.com/mirazbakis"),
        new("github.com/mertyesileducation", "https://github.com/mertyesileducation"),
    ];

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822", Justification = "Bound from XAML, which needs an instance property; the change is raised per instance.")]
    public IReadOnlyList<Component> Components =>
    [
        new("ClamAV", "GPL-2.0", "https://www.clamav.net/"),
        new("YARA", "BSD-3-Clause", "https://virustotal.github.io/yara/"),
        new("MalwareBazaar & URLhaus (abuse.ch)", L.T("about.serviceTerms"), "https://abuse.ch/"),
        new("VirusShare", L.T("about.serviceTerms"), "https://virusshare.com/"),
        new("VirusTotal", L.T("about.serviceTerms"), "https://www.virustotal.com/"),
        new("SharpCompress", "MIT", "https://github.com/adamhathcock/sharpcompress"),
        new("DiscUtils", "MIT", "https://github.com/DiscUtils/DiscUtils"),
        new("WiX Toolset DTF", "MS-RL", "https://wixtoolset.org/"),
        new("CommunityToolkit.Mvvm", "MIT", "https://github.com/CommunityToolkit/dotnet"),
    ];

    [RelayCommand]
    private static void OpenLink(string url) => Shell.Open(url);
}

public sealed record HelpTopic(string Question, string Answer);

/// <summary>Plain-language answers to the questions people ask most, for people who don't know computers well.</summary>
public sealed partial class HelpViewModel(MainViewModel main) : PageViewModel
{
    public override NavigationTarget Target => NavigationTarget.Help;

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822", Justification = "Bound from XAML, which needs an instance property; the change is raised per instance.")]
    public IReadOnlyList<HelpTopic> Topics =>
    [
        new(L.T("help.q.safe"), L.T("help.a.safe")),
        new(L.T("help.q.threat"), L.T("help.a.threat")),
        new(L.T("help.q.quarantine"), L.T("help.a.quarantine")),
        new(L.T("help.q.restore"), L.T("help.a.restore")),
        new(L.T("help.q.scan"), L.T("help.a.scan")),
        new(L.T("help.q.dns"), L.T("help.a.dns")),
        new(L.T("help.q.admin"), L.T("help.a.admin")),
        new(L.T("help.q.engine"), L.T("help.a.engine")),
        new(L.T("help.q.defender"), L.T("help.a.defender")),
        new(L.T("help.q.privacy"), L.T("help.a.privacy")),
        new(L.T("help.q.language"), L.T("help.a.language")),
    ];

    [RelayCommand]
    private void QuickScan()
    {
        main.Navigate(NavigationTarget.Scan);
        main.Scan.QuickScanCommand.Execute(null);
    }

    [RelayCommand]
    private void ShowWelcome() => main.Settings.ShowWelcomeCommand.Execute(null);

    [RelayCommand]
    private static void OpenLink(string url) => Shell.Open(url);
}
