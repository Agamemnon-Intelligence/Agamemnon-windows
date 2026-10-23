using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Agamemnon.Core.Scanning;

public sealed record ScanLogFinding(string Path, string Verdict, IReadOnlyList<string> Detections);

/// <summary>One finished scan, kept for the scan logs on the Scan page.</summary>
public sealed record ScanLog(
    DateTimeOffset StartedAt,
    DateTimeOffset FinishedAt,
    string Kind,
    long FilesScanned,
    int Threats,
    bool Cancelled,
    IReadOnlyList<ScanLogFinding> Findings,
    IReadOnlyList<string> Warnings)
{
    public static ScanLog From(ScanReport report, string kind) => new(
        report.StartedAt,
        report.FinishedAt,
        kind,
        report.FilesScanned,
        report.ThreatCount,
        report.Cancelled,
        [.. report.Findings.Where(f => f.Detections.Count > 0).Take(500).Select(f => new ScanLogFinding(
            f.DisplayPath,
            f.Verdict?.ToString() ?? "Unscanned",
            [.. f.Detections.Select(d => d.Detail is { Length: > 0 } detail ? $"{d.Engine}: {d.Name} ({detail})" : $"{d.Engine}: {d.Name}")]))],
        [.. report.Warnings.Take(100)]);

    /// <summary>A plain-text report, for "Export…" and for attaching to a bug report.</summary>
    public string ToText()
    {
        var text = new StringBuilder();
        CultureInfo c = CultureInfo.InvariantCulture;
        text.Append(c, $"Agamemnon scan log\n");
        text.Append(c, $"Kind:     {Kind}\n");
        text.Append(c, $"Started:  {StartedAt:yyyy-MM-dd HH:mm:ss zzz}\n");
        text.Append(c, $"Finished: {FinishedAt:yyyy-MM-dd HH:mm:ss zzz}{(Cancelled ? " (stopped)" : string.Empty)}\n");
        text.Append(c, $"Files:    {FilesScanned}\n");
        text.Append(c, $"Threats:  {Threats}\n");
        if (Findings.Count > 0)
        {
            text.Append("\nFindings\n");
            foreach (ScanLogFinding finding in Findings)
            {
                text.Append(c, $"- [{finding.Verdict}] {finding.Path}\n");
                foreach (string detection in finding.Detections)
                {
                    text.Append(c, $"    {detection}\n");
                }
            }
        }

        if (Warnings.Count > 0)
        {
            text.Append("\nWarnings\n");
            foreach (string warning in Warnings)
            {
                text.Append(c, $"- {warning}\n");
            }
        }

        return text.ToString();
    }
}

/// <summary>The last <see cref="MaxLogs"/> scans, newest first, as JSON on disk.</summary>
public sealed class ScanHistory(string path)
{
    public const int MaxLogs = 50;

    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() },
    };

    private readonly Lock _gate = new();

    public IReadOnlyList<ScanLog> Load()
    {
        lock (_gate)
        {
            try
            {
                return File.Exists(path) ? JsonSerializer.Deserialize<List<ScanLog>>(File.ReadAllText(path), Options) ?? [] : [];
            }
            catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
            {
                return [];
            }
        }
    }

    public void Add(ScanLog log)
    {
        lock (_gate)
        {
            List<ScanLog> logs = [log, .. LoadUnlocked().Take(MaxLogs - 1)];
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            string temp = path + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(logs, Options));
            File.Move(temp, path, overwrite: true);
        }
    }

    public void Clear()
    {
        lock (_gate)
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    private List<ScanLog> LoadUnlocked()
    {
        try
        {
            return File.Exists(path) ? JsonSerializer.Deserialize<List<ScanLog>>(File.ReadAllText(path), Options) ?? [] : [];
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }
}
