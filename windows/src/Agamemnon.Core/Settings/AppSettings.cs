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

    public DateTimeOffset? LastScanAt { get; init; }

    public long LastScanFiles { get; init; }

    public int LastScanThreats { get; init; }

    public string? LastScanKind { get; init; }
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
