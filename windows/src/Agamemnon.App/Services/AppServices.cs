using System.Net.Http;
using Agamemnon.Core.Archives;
using Agamemnon.Core.Intelligence;
using Agamemnon.Core.Ipc;
using Agamemnon.Core.Quarantine;
using Agamemnon.Core.Reputation;
using Agamemnon.Core.Scanning;
using Agamemnon.Core.Settings;
using Agamemnon.Core.Updates;
using Agamemnon.Platform.Windows;

namespace Agamemnon.App.Services;

/// <summary>Composition root: everything the app's pages share, created once at startup.</summary>
public sealed class AppServices : IDisposable
{
    private readonly JsonFileStore<AppSettings> _settingsStore = new(Path.Combine(AgamemnonPaths.UserSettings, "settings.json"));
    private readonly Lock _settingsGate = new();
    private AppSettings _settings;

    public AppServices()
    {
        _settings = _settingsStore.Load();
        LastSavedSettings = ReadSettingsFile();
        Directory.CreateDirectory(AgamemnonPaths.UserRules);
        Directory.CreateDirectory(AgamemnonPaths.ScanWork);

        Http = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
        Http.DefaultRequestHeaders.UserAgent.ParseAdd($"Agamemnon/{Version} (+https://github.com/Agamemnon-Intelligence/Agamemnon-Windows)");

        Secrets = new DpapiSecretStore(Path.Combine(AgamemnonPaths.UserSettings, "secrets.json"));
        Quarantine = new QuarantineStore(AgamemnonPaths.Quarantine, new DpapiKeyProtector());
        Activity = new ActivityLog(Path.Combine(AgamemnonPaths.UserLocalData, "activity.json"));
        MalwareHosts = new UrlhausHostList(Http, Path.Combine(AgamemnonPaths.UserLocalData, "urlhaus-hosts.txt"));

        ClamAv = new ClamAvEngine();
        Yara = new YaraEngine(
            Path.Combine(AgamemnonPaths.YaraBinaries, "yara64.exe"),
            Path.Combine(AgamemnonPaths.YaraBinaries, "yarac64.exe"),
            [AgamemnonPaths.BundledRules, AgamemnonPaths.UserRules],
            Path.Combine(AgamemnonPaths.UserLocalData, "YaraCache"));
        Hashes = new HashReputationEngine(
        [
            (new MalwareBazaarClient(Http, () => Settings.HashLookups ? Secrets.GetSecret(SecretNames.MalwareBazaarAuthKey) : null), 60),
            (new VirusTotalClient(Http, () => Settings.HashLookups ? Secrets.GetSecret(SecretNames.VirusTotalApiKey) : null), 4),
        ]);
        ThreatDatabase = new OfflineHashEngine(new ThreatIntelStore(AgamemnonPaths.ThreatIntelData));
        Signatures = new CodeSignatureEngine(new AuthenticodeVerifier());
        Amsi = new AmsiEngine();
        HiddenScripts = new HiddenScriptEngine();
        ScanLogs = new ScanHistory(Path.Combine(AgamemnonPaths.UserLocalData, "scan-logs.json"));
        Updates = new AgamemnonUpdateChecker(Http);
        DownloadSource = new DownloadSourceEngine(MalwareHosts);
        Expander = ArchiveExpander.CreateDefault([new MsiExtractor(), new CabExtractor()]);
        Service = new IpcClient(verifyServer: PipeServerCheck.IsService);
    }

    public static string Version =>
        typeof(AppServices).Assembly.GetName().Version is { } v ? $"{v.Major}.{v.Minor}.{v.Build}" : "4.0.0";

    public event EventHandler? SettingsChanged;

    public HttpClient Http { get; }

    public ISecretStore Secrets { get; }

    public QuarantineStore Quarantine { get; }

    public ActivityLog Activity { get; }

    public UrlhausHostList MalwareHosts { get; }

    public ClamAvEngine ClamAv { get; }

    public YaraEngine Yara { get; }

    public HashReputationEngine Hashes { get; }

    /// <summary>Offline VirusShare and MalwareBazaar hash databases, kept current by the scan engine service.</summary>
    public OfflineHashEngine ThreatDatabase { get; }

    public CodeSignatureEngine Signatures { get; }

    public DownloadSourceEngine DownloadSource { get; }

    /// <summary>4.0: Windows' own antivirus (normally Microsoft Defender) as one more engine.</summary>
    public AmsiEngine Amsi { get; }

    /// <summary>4.0: decodes scripts that hide their commands.</summary>
    public HiddenScriptEngine HiddenScripts { get; }

    public ScanHistory ScanLogs { get; }

    public AgamemnonUpdateChecker Updates { get; }

    public string SettingsPath => _settingsStore.Path;

    /// <summary>The settings file exactly as Agamemnon last wrote it, so the settings lock can tell its own changes from others'.</summary>
    public string? LastSavedSettings { get; private set; }

    public ArchiveExpander Expander { get; }

    public IpcClient Service { get; }

    public AppSettings Settings
    {
        get
        {
            lock (_settingsGate)
            {
                return _settings;
            }
        }
    }

    public void UpdateSettings(Func<AppSettings, AppSettings> change)
    {
        lock (_settingsGate)
        {
            _settings = change(_settings);
            _settingsStore.Save(_settings);
            LastSavedSettings = ReadSettingsFile();
        }

        SettingsChanged?.Invoke(this, EventArgs.Empty);
    }

    public ScanCoordinator CreateScanner(bool forDownloads)
    {
        var engines = new List<IScanEngine> { ClamAv, Yara, ThreatDatabase, Signatures, Amsi, HiddenScripts };
        if (Settings.HashLookups)
        {
            engines.Add(Hashes);
        }

        if (forDownloads && Settings.CheckDownloadSource)
        {
            engines.Add(DownloadSource);
        }

        return new ScanCoordinator(engines, Expander, MarkOfTheWeb.Read, AgamemnonPaths.ScanWork);
    }

    public ScanOptions CreateScanOptions() => new()
    {
        ExcludedPaths = [AgamemnonPaths.Quarantine, AgamemnonPaths.ScanWork, .. Settings.ScanExclusions],
        AllowedHashes = new HashSet<string>(Settings.AllowedHashes, StringComparer.OrdinalIgnoreCase),
    };

    public void Trust(string sha256)
    {
        if (string.IsNullOrEmpty(sha256))
        {
            return;
        }

        UpdateSettings(s => s.AllowedHashes.Contains(sha256, StringComparer.OrdinalIgnoreCase)
            ? s
            : s with { AllowedHashes = [.. s.AllowedHashes, sha256] });
    }

    /// <summary>
    /// Puts the settings file back the way Agamemnon last wrote it (the settings lock) and
    /// returns true when something else had changed it.
    /// </summary>
    public bool RestoreSettingsIfTampered()
    {
        lock (_settingsGate)
        {
            string? now = ReadSettingsFile();
            if (now is null || LastSavedSettings is null || now == LastSavedSettings)
            {
                return false;
            }

            _settingsStore.Save(_settings);
            LastSavedSettings = ReadSettingsFile();
            return true;
        }
    }

    private string? ReadSettingsFile()
    {
        try
        {
            return File.Exists(_settingsStore.Path) ? File.ReadAllText(_settingsStore.Path) : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return LastSavedSettings;
        }
    }

    public void Dispose()
    {
        Amsi.Dispose();
        Yara.Dispose();
        ThreatDatabase.Dispose();
        Http.Dispose();
    }
}
