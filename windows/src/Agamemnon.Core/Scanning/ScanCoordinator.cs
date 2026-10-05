using System.Security.Cryptography;
using Agamemnon.Core.Archives;

namespace Agamemnon.Core.Scanning;

public sealed record ScanOptions
{
    /// <summary>Folders and files never scanned (e.g. the quarantine store, user exclusions).</summary>
    public IReadOnlyList<string> ExcludedPaths { get; init; } = [];

    /// <summary>SHA-256 hashes the user chose to trust (e.g. restored from quarantine).</summary>
    public IReadOnlySet<string> AllowedHashes { get; init; } = new HashSet<string>();

    public long MaxFileBytes { get; init; } = 2L << 30;

    public ExpansionLimits ArchiveLimits { get; init; } = new();

    public int BatchSize { get; init; } = 32;
}

public sealed record ScanProgress(long FilesScanned, long ThreatsFound, string? CurrentPath);

public sealed record ScanReport(
    DateTimeOffset StartedAt,
    DateTimeOffset FinishedAt,
    long FilesScanned,
    IReadOnlyList<FileScanResult> Findings,
    IReadOnlyList<string> Warnings,
    bool Cancelled)
{
    public int ThreatCount => Findings.Count(f => f.IsThreat && !f.IsArchiveMember);
}

/// <summary>
/// Walks files, runs every available engine on them in batches, unpacks archives, disk images and
/// installers and scans their contents too. Engines run as the signed-in user: nothing here needs
/// administrator rights.
/// </summary>
public sealed class ScanCoordinator(
    IReadOnlyList<IScanEngine> engines,
    ArchiveExpander expander,
    Func<string, FileOrigin?> originReader,
    string workDirectory)
{
    private readonly IReadOnlyList<IScanEngine> _engines = engines;
    private readonly ArchiveExpander _expander = expander;
    private readonly Func<string, FileOrigin?> _originReader = originReader;
    private readonly string _workDirectory = workDirectory;

    public async Task<ScanReport> ScanAsync(
        IReadOnlyList<string> roots,
        ScanOptions options,
        IProgress<ScanProgress>? progress,
        CancellationToken cancellationToken)
    {
        DateTimeOffset started = DateTimeOffset.Now;
        var session = new Session(this, options, progress);
        await session.InitializeAsync(cancellationToken).ConfigureAwait(false);
        bool cancelled = false;
        try
        {
            var batch = new List<string>(options.BatchSize);
            foreach (string file in EnumerateFiles(roots, options, session.Warnings))
            {
                batch.Add(file);
                if (batch.Count == options.BatchSize)
                {
                    await session.ScanTopLevelAsync(batch, cancellationToken).ConfigureAwait(false);
                    batch.Clear();
                }
            }

            if (batch.Count > 0)
            {
                await session.ScanTopLevelAsync(batch, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            cancelled = true;
        }

        return new ScanReport(started, DateTimeOffset.Now, session.FilesScanned, session.Findings, session.Warnings, cancelled);
    }

    /// <summary>Scans one file (used for new downloads). Returns its result including archive contents.</summary>
    public async Task<(FileScanResult Result, IReadOnlyList<FileScanResult> Members, IReadOnlyList<string> Warnings)> ScanFileAsync(
        string path, ScanOptions options, CancellationToken cancellationToken)
    {
        var session = new Session(this, options, null);
        await session.InitializeAsync(cancellationToken).ConfigureAwait(false);
        await session.ScanTopLevelAsync([path], cancellationToken).ConfigureAwait(false);
        FileScanResult result = session.AllTopLevel.Count > 0
            ? session.AllTopLevel[0]
            : new FileScanResult(path, path, string.Empty, 0, [], ["File disappeared before it could be scanned."]);
        return (result, [.. session.Findings.Where(f => f.IsArchiveMember)], session.Warnings);
    }

    public async Task<IReadOnlyList<(string Engine, EngineStatus Status)>> GetEngineStatusAsync(CancellationToken cancellationToken)
    {
        var statuses = await Task.WhenAll(_engines.Select(async e => (e.Name, await e.GetStatusAsync(cancellationToken).ConfigureAwait(false)))).ConfigureAwait(false);
        return statuses;
    }

    private static IEnumerable<string> EnumerateFiles(IReadOnlyList<string> roots, ScanOptions options, List<string> warnings)
    {
        var enumeration = new EnumerationOptions
        {
            RecurseSubdirectories = false,
            IgnoreInaccessible = true,
            AttributesToSkip = FileAttributes.ReparsePoint | FileAttributes.Offline,
        };
        foreach (string root in roots)
        {
            if (File.Exists(root))
            {
                if (!IsExcluded(root, options))
                {
                    yield return Path.GetFullPath(root);
                }

                continue;
            }

            if (!Directory.Exists(root))
            {
                warnings.Add($"Not found: {root}");
                continue;
            }

            var pending = new Stack<string>();
            pending.Push(Path.GetFullPath(root));
            while (pending.Count > 0)
            {
                string directory = pending.Pop();
                if (IsExcluded(directory, options))
                {
                    continue;
                }

                IEnumerable<string> files;
                IEnumerable<string> subdirectories;
                try
                {
                    files = [.. Directory.EnumerateFiles(directory, "*", enumeration)];
                    subdirectories = [.. Directory.EnumerateDirectories(directory, "*", enumeration)];
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (string file in files)
                {
                    if (!IsExcluded(file, options))
                    {
                        yield return file;
                    }
                }

                foreach (string subdirectory in subdirectories)
                {
                    pending.Push(subdirectory);
                }
            }
        }
    }

    private static bool IsExcluded(string path, ScanOptions options)
    {
        foreach (string excluded in options.ExcludedPaths)
        {
            string e = excluded.TrimEnd('\\', '/');
            if (path.Equals(e, StringComparison.OrdinalIgnoreCase)
                || (path.StartsWith(e, StringComparison.OrdinalIgnoreCase) && path.Length > e.Length && path[e.Length] is '\\' or '/'))
            {
                return true;
            }
        }

        return false;
    }

    private sealed class Session(ScanCoordinator owner, ScanOptions options, IProgress<ScanProgress>? progress)
    {
        private readonly List<IScanEngine> _engines = [];
        private long _threats;

        public List<string> Warnings { get; } = [];

        public List<FileScanResult> Findings { get; } = [];

        public List<FileScanResult> AllTopLevel { get; } = [];

        public long FilesScanned { get; private set; }

        public async Task InitializeAsync(CancellationToken cancellationToken)
        {
            foreach (IScanEngine engine in owner._engines)
            {
                EngineStatus status = await engine.GetStatusAsync(cancellationToken).ConfigureAwait(false);
                if (status.Available)
                {
                    _engines.Add(engine);
                }
                else
                {
                    Warnings.Add($"{engine.Name} skipped: {status.Description}");
                }
            }
        }

        public async Task ScanTopLevelAsync(List<string> paths, CancellationToken cancellationToken)
        {
            var targets = new List<ScanTarget>();
            var preErrors = new List<FileScanResult>();
            foreach (string path in paths)
            {
                cancellationToken.ThrowIfCancellationRequested();
                progress?.Report(new ScanProgress(FilesScanned, _threats, path));
                try
                {
                    var info = new FileInfo(path);
                    if (info.Length > options.MaxFileBytes)
                    {
                        preErrors.Add(new FileScanResult(path, path, string.Empty, info.Length, [], ["Skipped: file is too large."]));
                        continue;
                    }

                    targets.Add(new ScanTarget(path, path, await HashAsync(path, cancellationToken).ConfigureAwait(false), info.Length,
                        FileClassifier.Classify(path), SafeOrigin(path), 0));
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    // Locked system files and vanished temp files are normal during a full scan; only report on direct requests.
                    if (paths.Count == 1)
                    {
                        preErrors.Add(new FileScanResult(path, path, string.Empty, 0, [], [ex.Message]));
                    }
                }
            }

            foreach (FileScanResult error in preErrors)
            {
                Findings.Add(error);
                AllTopLevel.Add(error);
            }

            foreach (FileScanResult result in await ScanTargetsAsync(targets, cancellationToken).ConfigureAwait(false))
            {
                AllTopLevel.Add(result);
            }
        }

        private async Task<IReadOnlyList<FileScanResult>> ScanTargetsAsync(List<ScanTarget> targets, CancellationToken cancellationToken)
        {
            if (targets.Count == 0)
            {
                return [];
            }

            var detections = targets.Select(_ => new List<Detection>()).ToArray();
            var errors = targets.Select(_ => new List<string>()).ToArray();
            var trusted = targets.Select(t => options.AllowedHashes.Contains(t.Sha256)).ToArray();
            for (int i = 0; i < targets.Count; i++)
            {
                if (!trusted[i] && FileNameHeuristics.Inspect(targets[i].DisplayPath) is { } nameFinding && targets[i].Depth == 0)
                {
                    detections[i].Add(nameFinding);
                }
            }

            List<ScanTarget> toScan = [.. targets.Where((_, i) => !trusted[i])];
            int[] indexMap = [.. Enumerable.Range(0, targets.Count).Where(i => !trusted[i])];
            IScanEngine[] engines = [.. _engines];
            var runs = engines.Select(engine => RunEngineAsync(engine, toScan, cancellationToken)).ToArray();
            IReadOnlyList<EngineResult>?[] engineResults = await Task.WhenAll(runs).ConfigureAwait(false);
            for (int e = 0; e < engines.Length; e++)
            {
                if (engineResults[e] is not { } results)
                {
                    continue;
                }

                for (int j = 0; j < results.Count; j++)
                {
                    detections[indexMap[j]].AddRange(results[j].Detections);
                    if (results[j].Error is { } error)
                    {
                        errors[indexMap[j]].Add(error);
                    }
                }
            }

            var output = new List<FileScanResult>(targets.Count);
            for (int i = 0; i < targets.Count; i++)
            {
                ScanTarget target = targets[i];
                FilesScanned++;
                if (!trusted[i] && owner._expander.CanExpand(target))
                {
                    await ExpandAndScanAsync(target, detections[i], errors[i], cancellationToken).ConfigureAwait(false);
                }

                var result = new FileScanResult(
                    target.DisplayPath,
                    target.Depth == 0 ? target.Path : null,
                    target.Sha256,
                    target.Size,
                    Dedupe(detections[i]),
                    errors[i]);
                if (result.Detections.Count > 0 || result.Errors.Count > 0)
                {
                    Findings.Add(result);
                }

                if (result.IsThreat && target.Depth == 0)
                {
                    _threats++;
                }

                output.Add(result);
            }

            progress?.Report(new ScanProgress(FilesScanned, _threats, null));
            return output;
        }

        private async Task ExpandAndScanAsync(ScanTarget container, List<Detection> detections, List<string> errors, CancellationToken cancellationToken)
        {
            string work = Path.Combine(owner._workDirectory, Guid.NewGuid().ToString("N"));
            var budget = new ExpansionBudget(options.ArchiveLimits);
            try
            {
                ExpansionResult expansion = await Task.Run(() => owner._expander.Expand(container, work, budget, cancellationToken), cancellationToken).ConfigureAwait(false);
                detections.AddRange(expansion.Findings);
                if (expansion.Error is { } error)
                {
                    errors.Add(error);
                }

                for (int start = 0; start < expansion.Members.Count; start += options.BatchSize)
                {
                    var members = new List<ScanTarget>();
                    foreach (ExtractedMember member in expansion.Members.Skip(start).Take(options.BatchSize))
                    {
                        long size = new FileInfo(member.TempPath).Length;
                        members.Add(new ScanTarget(member.TempPath, member.DisplayPath,
                            await HashAsync(member.TempPath, cancellationToken).ConfigureAwait(false), size,
                            FileClassifier.Classify(member.DisplayPath, ReadHead(member.TempPath)), container.Origin, container.Depth + 1));
                    }

                    foreach (FileScanResult inner in await ScanTargetsAsync(members, cancellationToken).ConfigureAwait(false))
                    {
                        if (inner.IsThreat)
                        {
                            Detection worst = inner.Detections.MaxBy(d => d.Severity)!;
                            detections.Add(worst with { Detail = $"Inside: {inner.DisplayPath}" });
                        }

                        foreach (Detection d in inner.Detections.Where(d => d.Engine == "Archive inspection"))
                        {
                            detections.Add(d);
                        }
                    }

                    foreach (ScanTarget member in members)
                    {
                        TryDelete(member.Path);
                    }
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
            {
                errors.Add($"Could not unpack: {ex.Message}");
            }
            finally
            {
                try
                {
                    if (Directory.Exists(work))
                    {
                        Directory.Delete(work, recursive: true);
                    }
                }
                catch (IOException)
                {
                }
            }
        }

        private async Task<IReadOnlyList<EngineResult>?> RunEngineAsync(IScanEngine engine, List<ScanTarget> batch, CancellationToken cancellationToken)
        {
            if (batch.Count == 0)
            {
                return [];
            }

            try
            {
                return await engine.ScanAsync(batch, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
            {
                // The engine stopped working (e.g. its service was restarted): drop it for the rest of this scan.
                lock (_engines)
                {
                    if (_engines.Remove(engine))
                    {
                        Warnings.Add($"{engine.Name} stopped responding: {ex.Message}");
                    }
                }

                return null;
            }
        }

        private FileOrigin? SafeOrigin(string path)
        {
            try
            {
                return owner._originReader(path);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                return null;
            }
        }

        private static IReadOnlyList<Detection> Dedupe(List<Detection> detections) =>
            [.. detections.DistinctBy(d => (d.Engine, d.Name, d.Detail)).OrderByDescending(d => d.Severity)];

        private static byte[] ReadHead(string path)
        {
            byte[] head = new byte[16];
            using var stream = File.OpenRead(path);
            int read = stream.ReadAtLeast(head, head.Length, throwOnEndOfStream: false);
            return head[..read];
        }

        private static async Task<string> HashAsync(string path, CancellationToken cancellationToken)
        {
            await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16, FileOptions.SequentialScan | FileOptions.Asynchronous);
            return Convert.ToHexStringLower(await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false));
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
}
