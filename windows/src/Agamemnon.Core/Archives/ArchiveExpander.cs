using Agamemnon.Core.Scanning;

namespace Agamemnon.Core.Archives;

/// <summary>One member of a container (archive, disk image, installer).</summary>
public sealed record ContainerEntry(string Name, bool IsEncrypted, long? CompressedSize, Func<Stream> Open);

/// <summary>Knows how to list one family of containers. Entries must be consumed in order.</summary>
public interface IContainerExtractor
{
    bool CanExtract(string path, FileKind kind);

    IEnumerable<ContainerEntry> Entries(string path);
}

public sealed record ExpansionLimits
{
    public int MaxDepth { get; init; } = 3;

    public int MaxEntries { get; init; } = 10_000;

    public long MaxEntryBytes { get; init; } = 1L << 30;

    /// <summary>Total bytes that may be extracted from one top-level file, across all nesting levels.</summary>
    public long MaxTotalBytes { get; init; } = 4L << 30;

    /// <summary>Uncompressed/compressed ratio above which an entry is treated as a decompression bomb.</summary>
    public int MaxCompressionRatio { get; init; } = 250;
}

public sealed record ExtractedMember(string TempPath, string DisplayPath);

public sealed record ExpansionResult(IReadOnlyList<ExtractedMember> Members, IReadOnlyList<Detection> Findings, string? Error);

/// <summary>Tracks the extraction budget for one top-level file across nested containers.</summary>
public sealed class ExpansionBudget(ExpansionLimits limits)
{
    public ExpansionLimits Limits { get; } = limits;

    public long BytesUsed { get; internal set; }
}

/// <summary>
/// Extracts containers into a private temp directory so their contents can be scanned like any
/// other file. Never trusts names or sizes from archive headers: members are written under random
/// file names (no path traversal possible) and byte counts are enforced while copying.
/// </summary>
public sealed class ArchiveExpander(IEnumerable<IContainerExtractor> extractors)
{
    private const string Engine = "Archive inspection";
    private readonly IReadOnlyList<IContainerExtractor> _extractors = [.. extractors];

    public static ArchiveExpander CreateDefault(IEnumerable<IContainerExtractor>? platformExtractors = null) =>
        new([new SharpCompressExtractor(), new IsoExtractor(), .. platformExtractors ?? []]);

    public bool CanExpand(ScanTarget target) => _extractors.Any(e => e.CanExtract(target.Path, target.Kind));

    public ExpansionResult Expand(ScanTarget target, string workDirectory, ExpansionBudget budget, CancellationToken cancellationToken)
    {
        var members = new List<ExtractedMember>();
        var findings = new List<Detection>();
        IContainerExtractor? extractor = _extractors.FirstOrDefault(e => e.CanExtract(target.Path, target.Kind));
        if (extractor is null)
        {
            return new ExpansionResult(members, findings, null);
        }

        if (target.Depth >= budget.Limits.MaxDepth)
        {
            findings.Add(new Detection(Engine, "Deeply nested archive (inner levels not unpacked)", Severity.Info));
            return new ExpansionResult(members, findings, null);
        }

        Directory.CreateDirectory(workDirectory);
        var encryptedNames = new List<string>();
        int count = 0;
        try
        {
            foreach (ContainerEntry entry in extractor.Entries(target.Path))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (++count > budget.Limits.MaxEntries)
                {
                    findings.Add(new Detection(Engine, "Archive has too many files to inspect fully", Severity.Suspicious,
                        $"Stopped after {budget.Limits.MaxEntries:N0} files."));
                    break;
                }

                string display = $"{target.DisplayPath} › {entry.Name}";
                if (FileNameHeuristics.Inspect(entry.Name) is { } nameFinding)
                {
                    findings.Add(nameFinding with { Detail = display });
                }

                if (entry.IsEncrypted)
                {
                    encryptedNames.Add(entry.Name);
                    continue;
                }

                string tempPath = Path.Combine(workDirectory, Guid.NewGuid().ToString("N") + SafeExtension(entry.Name));
                CopyResult copy = CopyBounded(entry, tempPath, budget, cancellationToken);
                if (copy == CopyResult.Bomb)
                {
                    TryDelete(tempPath);
                    findings.Add(new Detection(Engine, "Possible archive bomb", Severity.Suspicious,
                        $"{display} expands far beyond its compressed size."));
                    break;
                }

                if (copy == CopyResult.OverBudget)
                {
                    TryDelete(tempPath);
                    findings.Add(new Detection(Engine, "Archive too large to inspect fully", Severity.Info,
                        $"Stopped at {display}."));
                    break;
                }

                members.Add(new ExtractedMember(tempPath, display));
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Corrupt or unsupported container: report it but keep what was extracted so far.
            return new ExpansionResult(members, AddEncryptionFinding(findings, encryptedNames), $"Could not fully unpack: {ex.Message}");
        }

        return new ExpansionResult(members, AddEncryptionFinding(findings, encryptedNames), null);
    }

    private static List<Detection> AddEncryptionFinding(List<Detection> findings, List<string> encryptedNames)
    {
        if (encryptedNames.Count == 0)
        {
            return findings;
        }

        string[] programs = [.. encryptedNames.Where(FileClassifier.IsExecutableName)];
        findings.Add(programs.Length > 0
            ? new Detection(Engine, "Password-protected archive containing programs", Severity.Suspicious,
                "Malware is often sent this way to slip past scanners: " + string.Join(", ", programs.Take(5)))
            : new Detection(Engine, "Password-protected archive (contents not scanned)", Severity.Info));
        return findings;
    }

    private enum CopyResult
    {
        Ok,
        Bomb,
        OverBudget,
    }

    private static CopyResult CopyBounded(ContainerEntry entry, string destination, ExpansionBudget budget, CancellationToken cancellationToken)
    {
        ExpansionLimits limits = budget.Limits;
        using Stream source = entry.Open();
        using var target = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920);
        byte[] buffer = new byte[81920];
        long written = 0;
        int read;
        while ((read = source.Read(buffer, 0, buffer.Length)) > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            written += read;
            budget.BytesUsed += read;
            if (entry.CompressedSize is > 0 and long compressed && written > (1L << 20)
                && written / compressed > limits.MaxCompressionRatio)
            {
                return CopyResult.Bomb;
            }

            if (written > limits.MaxEntryBytes || budget.BytesUsed > limits.MaxTotalBytes)
            {
                return entry.CompressedSize is > 0 and long c && written / c > limits.MaxCompressionRatio / 4
                    ? CopyResult.Bomb
                    : CopyResult.OverBudget;
            }

            target.Write(buffer, 0, read);
        }

        return CopyResult.Ok;
    }

    /// <summary>Keeps a short, plain extension (so engines and the signature check see the type) and nothing else.</summary>
    private static string SafeExtension(string entryName)
    {
        string ext = Path.GetExtension(entryName.Replace('\\', '/').Split('/')[^1]);
        return ext.Length is > 1 and <= 12 && ext.Skip(1).All(char.IsAsciiLetterOrDigit) ? ext : string.Empty;
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (IOException)
        {
        }
    }
}

/// <summary>Spots names built to trick people into running programs.</summary>
public static class FileNameHeuristics
{
    private static readonly string[] DecoyExtensions =
    [
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt", ".mp4", ".mp3", ".zip", ".rtf",
    ];

    public static Detection? Inspect(string name)
    {
        string fileName = name.Replace('\\', '/').Split('/')[^1];
        if (fileName.Contains('‮', StringComparison.Ordinal))
        {
            return new Detection("File name", "Disguised file name (right-to-left override)", Severity.Suspicious);
        }

        if (FileClassifier.IsExecutableName(fileName))
        {
            string inner = Path.GetExtension(Path.GetFileNameWithoutExtension(fileName));
            if (DecoyExtensions.Contains(inner, StringComparer.OrdinalIgnoreCase))
            {
                return new Detection("File name", $"Program disguised as a {inner.TrimStart('.').ToUpperInvariant()} file", Severity.Suspicious);
            }

            if (fileName.Contains("     ", StringComparison.Ordinal))
            {
                return new Detection("File name", "Program name padded with spaces to hide its extension", Severity.Suspicious);
            }
        }

        return null;
    }
}
