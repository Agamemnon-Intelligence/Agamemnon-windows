namespace Agamemnon.Core.Scanning;

/// <summary>Ordered by seriousness, so <c>Max()</c> gives a file's overall verdict.</summary>
public enum Severity
{
    /// <summary>Worth knowing (e.g. unsigned program) but not a threat on its own.</summary>
    Info = 0,

    /// <summary>Looks risky; the user should decide.</summary>
    Suspicious = 1,

    /// <summary>Known bad. Quarantined automatically where policy allows.</summary>
    Malicious = 2,
}

public sealed record Detection(string Engine, string Name, Severity Severity, string? Detail = null);

/// <summary>Where a file came from, from Windows' Mark-of-the-Web (Zone.Identifier stream).</summary>
public sealed record FileOrigin(int ZoneId, string? HostUrl, string? ReferrerUrl)
{
    /// <summary>URLZONE_INTERNET (3) or URLZONE_UNTRUSTED (4).</summary>
    public bool IsFromInternet => ZoneId >= 3;

    public static FileOrigin? Parse(string? zoneIdentifier)
    {
        if (string.IsNullOrWhiteSpace(zoneIdentifier))
        {
            return null;
        }

        int? zone = null;
        string? host = null;
        string? referrer = null;
        foreach (string rawLine in zoneIdentifier.Split('\n'))
        {
            string line = rawLine.Trim();
            int eq = line.IndexOf('=', StringComparison.Ordinal);
            if (eq <= 0)
            {
                continue;
            }

            string key = line[..eq].Trim();
            string value = line[(eq + 1)..].Trim();
            if (key.Equals("ZoneId", StringComparison.OrdinalIgnoreCase)
                && int.TryParse(value, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out int z))
            {
                zone = z;
            }
            else if (key.Equals("HostUrl", StringComparison.OrdinalIgnoreCase))
            {
                host = value;
            }
            else if (key.Equals("ReferrerUrl", StringComparison.OrdinalIgnoreCase))
            {
                referrer = value;
            }
        }

        return zone is int id ? new FileOrigin(id, host, referrer) : null;
    }
}

/// <summary>One file handed to the engines. For archive members, <see cref="Path"/> is a temp extraction.</summary>
public sealed record ScanTarget(
    string Path,
    string DisplayPath,
    string Sha256,
    long Size,
    FileKind Kind,
    FileOrigin? Origin,
    int Depth);

public sealed record FileScanResult(
    string DisplayPath,
    string? OnDiskPath,
    string Sha256,
    long Size,
    IReadOnlyList<Detection> Detections,
    IReadOnlyList<string> Errors)
{
    public Severity? Verdict => Detections.Count == 0 ? null : Detections.Max(d => d.Severity);

    public bool IsThreat => Verdict >= Severity.Suspicious;

    /// <summary>True for files inside archives: those can't be quarantined on their own, the archive is.</summary>
    public bool IsArchiveMember => OnDiskPath is null;
}

public interface IScanEngine
{
    string Name { get; }

    /// <summary>Engines that are not installed or not configured are skipped and reported once.</summary>
    Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Scans a batch; returns one result per target, in the same order. Per-file problems go in
    /// <see cref="EngineResult.Error"/>; an exception means the engine itself is unusable.
    /// </summary>
    Task<IReadOnlyList<EngineResult>> ScanAsync(IReadOnlyList<ScanTarget> batch, CancellationToken cancellationToken);
}

public sealed record EngineResult(IReadOnlyList<Detection> Detections, string? Error = null)
{
    public static readonly EngineResult Clean = new([]);

    public static EngineResult Failed(string error) => new([], error);
}

public sealed record EngineStatus(bool Available, string Description);

public sealed class EngineException(string message, Exception? inner = null) : Exception(message, inner);
