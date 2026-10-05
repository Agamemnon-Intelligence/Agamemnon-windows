using System.Net.Http;
using Agamemnon.Core.Archives;
using Agamemnon.Core.Ipc;
using Agamemnon.Core.Quarantine;
using Agamemnon.Core.Reputation;
using Agamemnon.Core.Scanning;
using Agamemnon.Core.Settings;
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
        Signatures = new CodeSignatureEngine(new AuthenticodeVerifier());
        DownloadSource = new DownloadSourceEngine(MalwareHosts);
        Expander = ArchiveExpander.CreateDefault([new MsiExtractor(), new CabExtractor()]);
        Service = new IpcClient(verifyServer: PipeServerCheck.IsService);
    }

    public static string Version =>
        typeof(AppServices).Assembly.GetName().Version is { } v ? $"{v.Major}.{v.Minor}.{v.Build}" : "1.0.0";

    public event EventHandler? SettingsChanged;

    public HttpClient Http { get; }

    public ISecretStore Secrets { get; }

    public QuarantineStore Quarantine { get; }

    public ActivityLog Activity { get; }

    public UrlhausHostList MalwareHosts { get; }

    public ClamAvEngine ClamAv { get; }

    public YaraEngine Yara { get; }

    public HashReputationEngine Hashes { get; }

    public CodeSignatureEngine Signatures { get; }

    public DownloadSourceEngine DownloadSource { get; }

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
        }

        SettingsChanged?.Invoke(this, EventArgs.Empty);
    }

    public ScanCoordinator CreateScanner(bool forDownloads)
    {
        var engines = new List<IScanEngine> { ClamAv, Yara, Signatures };
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

    public void Dispose()
    {
        Yara.Dispose();
        Http.Dispose();
    }
}
