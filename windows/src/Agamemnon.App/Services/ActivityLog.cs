using System.Collections.ObjectModel;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Windows;

namespace Agamemnon.App.Services;

public enum ActivityKind
{
    Download,
    AdminRights,
    Scan,
    Quarantine,
    Dns,
}

public enum ActivityLevel
{
    Good,
    Info,
    Warning,
    Threat,
}

public sealed record ActivityEntry(DateTimeOffset At, ActivityKind Kind, ActivityLevel Level, string Title, string? Detail = null)
{
    [JsonIgnore]
    public string When => At.Date == DateTimeOffset.Now.Date ? At.ToString("t", System.Globalization.CultureInfo.CurrentCulture) : At.ToString("g", System.Globalization.CultureInfo.CurrentCulture);
}

/// <summary>Recent security events shown on the Dashboard and Downloads pages (last 200 kept on disk).</summary>
public sealed class ActivityLog
{
    private const int MaxEntries = 200;
    private static readonly JsonSerializerOptions Options = new() { Converters = { new JsonStringEnumConverter() } };
    private readonly string _path;

    public ActivityLog(string path)
    {
        _path = path;
        try
        {
            if (File.Exists(path))
            {
                foreach (ActivityEntry entry in JsonSerializer.Deserialize<List<ActivityEntry>>(File.ReadAllText(path), Options) ?? [])
                {
                    Entries.Add(entry);
                }
            }
        }
        catch (Exception ex) when (ex is JsonException or IOException)
        {
        }
    }

    public ObservableCollection<ActivityEntry> Entries { get; } = [];

    public void Add(ActivityEntry entry)
    {
        Application.Current.Dispatcher.Invoke(() =>
        {
            Entries.Insert(0, entry);
            while (Entries.Count > MaxEntries)
            {
                Entries.RemoveAt(Entries.Count - 1);
            }

            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
                File.WriteAllText(_path, JsonSerializer.Serialize(Entries.ToList(), Options));
            }
            catch (IOException)
            {
            }
        });
    }
}
