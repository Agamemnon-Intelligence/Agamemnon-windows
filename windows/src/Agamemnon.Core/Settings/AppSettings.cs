using System.Text.Json;
using System.Text.Json.Serialization;

namespace Agamemnon.Core.Settings;

public enum UnsignedDownloadPolicy
{
    /// <summary>Notify, leave the file in place.</summary>
    Warn,

    /// <summary>Quarantine unsigned programs and installers downloaded from the internet.</summary>
    Block,
}

/// <summary>How often Agamemnon runs a quick scan by itself.</summary>
public enum AutoScanFrequency
{
    Off,
    Daily,
    Weekly,
}

/// <summary>Per-user preferences, stored as JSON in %APPDATA%\Agamemnon.</summary>
public sealed record AppSettings
{
    public bool DownloadProtection { get; init; } = true;

    /// <summary>Extra folders to watch besides the user's Downloads folder.</summary>
    public IReadOnlyList<string> ExtraDownloadFolders { get; init; } = [];

    public UnsignedDownloadPolicy UnsignedDownloads { get; init; } = UnsignedDownloadPolicy.Warn;

    public bool CheckDownloadSource { get; init; } = true;

    public bool HashLookups { get; init; } = true;

    public bool AdminRightsAlerts { get; init; } = true;

    public bool StartAtLogin { get; init; } = true;

    public IReadOnlyList<string> ScanExclusions { get; init; } = [];

    /// <summary>Files the user restored or chose to trust, by SHA-256.</summary>
    public IReadOnlyList<string> AllowedHashes { get; init; } = [];

    /// <summary>"en" or "tr"; null follows the Windows display language.</summary>
    public string? Language { get; init; }

    /// <summary>Shows only the everyday pages; encrypted DNS and download details stay reachable from Settings.</summary>
    public bool SimpleMode { get; init; }

    public AutoScanFrequency AutoScan { get; init; } = AutoScanFrequency.Weekly;

    /// <summary>The 3.0 welcome guide (language and recommended setup) has been completed.</summary>
    public bool WelcomeCompleted { get; init; }

    public DateTimeOffset? LastScanAt { get; init; }

    public long LastScanFiles { get; init; }

    public int LastScanThreats { get; init; }

    public string? LastScanKind { get; init; }

    // 4.0: real-time protection that goes beyond downloads.

    /// <summary>Checks programs, scripts and installers as they are saved anywhere in your user folder.</summary>
    public bool OnAccessScanning { get; init; } = true;

    /// <summary>Watches Documents, Desktop, Pictures (and extra folders) for files being encrypted.</summary>
    public bool RansomwareShield { get; init; } = true;

    public IReadOnlyList<string> RansomwareFolders { get; init; } = [];

    /// <summary>Stops an unsigned program caught encrypting files and moves it to quarantine.</summary>
    public bool StopDangerousPrograms { get; init; } = true;

    /// <summary>Warns when a "paste this to fix it" command is copied (ClickFix).</summary>
    public bool PasteGuard { get; init; } = true;

    /// <summary>Also empties the clipboard so the command can't be pasted by accident.</summary>
    public bool PasteGuardClears { get; init; } = true;

    /// <summary>Scans USB drives and memory cards when they are connected.</summary>
    public bool UsbProtection { get; init; } = true;

    public bool EjectInfectedDrives { get; init; } = true;

    /// <summary>Tells you when an app starts using the camera or microphone.</summary>
    public bool PrivacyAlerts { get; init; } = true;

    /// <summary>Reports new programs set to start with Windows.</summary>
    public bool StartupAlerts { get; init; } = true;

    /// <summary>Puts back protection settings that something other than Agamemnon changed.</summary>
    public bool SettingsLock { get; init; } = true;

    public bool CheckForUpdates { get; init; } = true;

    public DateTimeOffset? LastUpdateCheck { get; init; }

    /// <summary>Startup items the user chose to trust (<see cref="Startup.StartupItem.Key"/>).</summary>
    public IReadOnlyList<string> TrustedStartupItems { get; init; } = [];

    /// <summary>The newest version whose welcome guide was shown (0 before 4.0).</summary>
    public int WelcomeVersion { get; init; }
}

/// <summary>Loads and atomically saves a JSON settings file; a damaged file falls back to defaults.</summary>
public sealed class JsonFileStore<T>(string path)
    where T : class, new()
{
    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    private readonly Lock _gate = new();

    public string Path => path;

    public T Load()
    {
        lock (_gate)
        {
            try
            {
                return File.Exists(path)
                    ? JsonSerializer.Deserialize<T>(File.ReadAllText(path), Options) ?? new T()
                    : new T();
            }
            catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
            {
                return new T();
            }
        }
    }

    public void Save(T value)
    {
        lock (_gate)
        {
            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!);
            string temp = path + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(value, Options));
            File.Move(temp, path, overwrite: true);
        }
    }
}

/// <summary>Stores API keys encrypted for the current user (DPAPI on Windows).</summary>
public interface ISecretStore
{
    string? GetSecret(string name);

    void SetSecret(string name, string? value);
}

public static class SecretNames
{
    public const string VirusTotalApiKey = "virustotal";
    public const string MalwareBazaarAuthKey = "abusech";
}
