using System.Globalization;

namespace Agamemnon.Core.Recovery;

/// <summary>A Windows restore point (volume shadow copy) of one drive.</summary>
/// <param name="Id">The shadow copy's ID ("{GUID}").</param>
/// <param name="CreatedAt">When it was taken.</param>
/// <param name="Volume">The drive it copies, as "C:\".</param>
/// <param name="DevicePath">Where Windows exposes it, e.g. \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3.</param>
/// <param name="ByAgamemnon">Taken by Agamemnon (only those are ever removed by Agamemnon).</param>
public sealed record RestorePoint(string Id, DateTimeOffset CreatedAt, string Volume, string DevicePath, bool ByAgamemnon);

/// <summary>One earlier copy of a file inside a restore point.</summary>
public sealed record FileVersion(string PointId, DateTimeOffset PointCreatedAt, long Size, DateTimeOffset LastWrite);

/// <summary>
/// 5.0's ransomware recovery: the decisions, kept apart from Windows so they are unit-tested.
/// The service takes a restore point of the system drive every day (and when asked), keeps
/// the last <see cref="KeepAgamemnonPoints"/> of its own, and hands people back earlier copies of
/// their files. Windows' own restore points are used too but never deleted.
/// </summary>
public static class RecoveryPlanner
{
    public const int KeepAgamemnonPoints = 7;

    public static readonly TimeSpan DailyInterval = TimeSpan.FromHours(24);

    /// <summary>"Create a restore point now" is limited so it can't fill the disk.</summary>
    public static readonly TimeSpan ManualCooldown = TimeSpan.FromMinutes(10);

    /// <summary>A copy from just before an attack might already contain damaged files.</summary>
    public static readonly TimeSpan SafetyMargin = TimeSpan.FromMinutes(2);

    public static bool IsDailyPointDue(IEnumerable<RestorePoint> points, DateTimeOffset now) =>
        !points.Any(p => now - p.CreatedAt < DailyInterval);

    /// <summary>Agamemnon's own oldest points beyond the ones it keeps; Windows' points are left alone.</summary>
    public static IReadOnlyList<RestorePoint> ToRemove(IEnumerable<RestorePoint> points) =>
        [.. points.Where(p => p.ByAgamemnon).OrderByDescending(p => p.CreatedAt).Skip(KeepAgamemnonPoints)];

    /// <summary>
    /// Checks that a path is a plain absolute path on a local drive ("C:\Users\…\file.docx") and
    /// returns it tidied, or null. Device paths, network paths and ".." are refused.
    /// </summary>
    public static string? Normalize(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Length > 32_000)
        {
            return null;
        }

        string p = path.Trim().Replace('/', '\\');
        if (p.Length < 4 || !char.IsAsciiLetter(p[0]) || p[1] != ':' || p[2] != '\\' || p.Contains('\0', StringComparison.Ordinal)
            || p.IndexOfAny(['*', '?', '"', '<', '>', '|'], 3) >= 0 || p.IndexOf(':', 2) >= 0)
        {
            return null;
        }

        string[] parts = p[3..].Split('\\', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0 || parts.Any(part => part is "." or ".." || part.EndsWith(' ') || part.EndsWith('.')))
        {
            return null;
        }

        return char.ToUpperInvariant(p[0]) + ":\\" + string.Join('\\', parts);
    }

    /// <summary>Where a file's earlier copy is inside a restore point, or null if the point is of another drive.</summary>
    public static string? PathInPoint(RestorePoint point, string path)
    {
        if (Normalize(path) is not { } normalized
            || !point.Volume.StartsWith(normalized[..2], StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return point.DevicePath.TrimEnd('\\') + normalized[2..];
    }

    /// <summary>The newest point safely before <paramref name="before"/> that has the file.</summary>
    public static FileVersion? BestBefore(IEnumerable<FileVersion> versions, DateTimeOffset before) =>
        versions.Where(v => v.PointCreatedAt <= before - SafetyMargin).MaxBy(v => v.PointCreatedAt);

    /// <summary>
    /// A name next to the original that doesn't exist yet, so restoring never overwrites anything:
    /// "Report.docx" → "Report (restored 2026-11-13).docx", then "… 2", "… 3".
    /// </summary>
    public static string RestoredPath(string original, DateTimeOffset pointDate, string restoredWord, Func<string, bool> exists)
    {
        int slash = original.LastIndexOf('\\');
        string folder = slash >= 0 ? original[..slash] : string.Empty;
        string file = slash >= 0 ? original[(slash + 1)..] : original;
        int dot = file.LastIndexOf('.');
        string stem = dot > 0 ? file[..dot] : file;
        string extension = dot > 0 ? file[dot..] : string.Empty;
        string date = pointDate.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        for (int n = 1; ; n++)
        {
            string suffix = n == 1 ? string.Empty : " " + n.ToString(CultureInfo.InvariantCulture);
            string candidate = $"{stem} ({restoredWord} {date}{suffix}){extension}";
            string full = folder.Length > 0 ? folder + "\\" + candidate : candidate;
            if (!exists(full))
            {
                return full;
            }
        }
    }
}

/// <summary>What the ransomware shield saw last time, so the files can be brought back.</summary>
public sealed record RansomwareIncident
{
    public DateTimeOffset At { get; init; }

    public IReadOnlyList<string> Files { get; init; } = [];

    /// <summary>The extension the ransomware added (".locked"), when it renamed files.</summary>
    public string? AddedExtension { get; init; }

    /// <summary>Most files an incident remembers.</summary>
    public const int MaxFiles = 2000;

    /// <summary>Where the damaged copies came from: a renamed file "x.docx.locked" was "x.docx".</summary>
    public static string OriginalName(string path, string? addedExtension) =>
        !string.IsNullOrEmpty(addedExtension) && path.EndsWith(addedExtension, StringComparison.OrdinalIgnoreCase)
            && path.Length > addedExtension.Length
            ? path[..^addedExtension.Length]
            : path;
}
