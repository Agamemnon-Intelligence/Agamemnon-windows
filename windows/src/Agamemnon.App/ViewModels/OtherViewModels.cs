using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using Agamemnon.App.Services;
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

    public override string Title => "Downloads";

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

    public string CheckedText => $"{_guard.CheckedToday} download(s) checked since Agamemnon started. "
        + (_services.MalwareHosts.Count > 0 ? $"{_services.MalwareHosts.Count:N0} known malware sites on the block list." : string.Empty);

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
        var dialog = new OpenFolderDialog { Title = "Choose a folder to watch for new files" };
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

    public string Source => item.Source == "Download" ? "Blocked download" : "Found by scan";

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

    public override string Title => "Quarantine";

    public ObservableCollection<QuarantineRow> Items { get; } = [];

    public bool IsEmpty => Items.Count == 0;

    [ObservableProperty]
    public partial string? Message { get; set; }

    public override void OnShown() => Reload();

    public void Restore(QuarantineRow row)
    {
        MessageBoxResult answer = MessageBox.Show(
            $"Restore “{row.FileName}” to\n{row.OriginalPath}?\n\nIt was quarantined because: {row.Reason}.\nOnly restore it if you're sure it's safe. Agamemnon won't flag this exact file again.",
            "Restore from quarantine", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
        if (answer != MessageBoxResult.Yes)
        {
            return;
        }

        try
        {
            // Trust first, so the download watcher doesn't put it straight back.
            _services.Trust(row.Item.Sha256);
            string restored = _services.Quarantine.Restore(row.Item.Id);
            Message = $"Restored to {restored}";
            _services.Activity.Add(new ActivityEntry(DateTimeOffset.Now, ActivityKind.Quarantine, ActivityLevel.Warning, $"Restored {row.FileName}", restored));
        }
        catch (Exception ex) when (ex is QuarantineException or IOException or UnauthorizedAccessException)
        {
            Message = ex.Message;
        }
    }

    public void Delete(QuarantineRow row)
    {
        _services.Quarantine.Delete(row.Item.Id);
        Message = $"Deleted {row.FileName} permanently.";
    }

    [RelayCommand]
    private void DeleteAll()
    {
        if (Items.Count == 0 || MessageBox.Show($"Permanently delete all {Items.Count} quarantined file(s)?", "Empty quarantine",
                MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes)
        {
            return;
        }

        foreach (QuarantineRow row in Items.ToList())
        {
            _services.Quarantine.Delete(row.Item.Id);
        }

        Message = "Quarantine emptied.";
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
    public override string Title => "Settings";

    public ObservableCollection<EngineRow> Engines { get; } = [];

    public ObservableCollection<string> Exclusions { get; } = [];

    [ObservableProperty]
    public partial string NewVirusTotalKey { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string NewMalwareBazaarKey { get; set; } = string.Empty;

    public bool HasVirusTotalKey => services.Secrets.GetSecret(SecretNames.VirusTotalApiKey) is not null;

    public bool HasMalwareBazaarKey => services.Secrets.GetSecret(SecretNames.MalwareBazaarAuthKey) is not null;

    public string TrustedText => $"{services.Settings.AllowedHashes.Count} file(s) you restored or marked as trusted.";

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
        var dialog = new OpenFolderDialog { Title = "Choose a folder to leave out of scans" };
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
    public override string Title => "About";

    public string Version { get; } = $"Version {AppServices.Version} for Windows";

    public IReadOnlyList<Credit> Credits { get; } =
    [
        new("github.com/mirazbakis", "https://github.com/mirazbakis"),
        new("github.com/mertyesileducation", "https://github.com/mertyesileducation"),
    ];

    public IReadOnlyList<Component> Components { get; } =
    [
        new("ClamAV", "GPL-2.0", "https://www.clamav.net/"),
        new("YARA", "BSD-3-Clause", "https://virustotal.github.io/yara/"),
        new("MalwareBazaar and URLhaus by abuse.ch", "Service terms", "https://abuse.ch/"),
        new("VirusTotal (with your own API key)", "Service terms", "https://www.virustotal.com/"),
        new("SharpCompress", "MIT", "https://github.com/adamhathcock/sharpcompress"),
        new("DiscUtils", "MIT", "https://github.com/DiscUtils/DiscUtils"),
        new("WiX Toolset DTF", "MS-RL", "https://wixtoolset.org/"),
        new("CommunityToolkit.Mvvm", "MIT", "https://github.com/CommunityToolkit/dotnet"),
    ];

    [RelayCommand]
    private static void OpenLink(string url) => Shell.Open(url);
}
