using System.Globalization;
using System.Security.Cryptography;
using Agamemnon.Core.Scanning;

namespace Agamemnon.Core.Intelligence;

/// <summary>
/// Checks every file against the offline malware hash databases the scan engine service keeps
/// up to date (VirusShare, MalwareBazaar: tens of millions of known samples). Nothing leaves the
/// PC, so unlike the online hash lookups this runs for every file, not just programs.
/// </summary>
public sealed class OfflineHashEngine(ThreatIntelStore store, TimeProvider? time = null) : IScanEngine, IDisposable
{
    public const string EngineName = "Offline threat database";

    private static readonly TimeSpan RecheckInterval = TimeSpan.FromSeconds(30);

    private readonly TimeProvider _time = time ?? TimeProvider.System;
    private readonly Lock _gate = new();
    private Snapshot? _snapshot;
    private DateTime _manifestWrite;
    private DateTimeOffset _checkedAt = DateTimeOffset.MinValue;

    public string Name => EngineName;

    /// <summary>The manifest last read (hash and ClamAV signature counts), or null before the first download.</summary>
    public ThreatIntelManifest? Manifest
    {
        get
        {
            lock (_gate)
            {
                return _snapshot?.Manifest;
            }
        }
    }

    public Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken)
    {
        using Snapshot? snapshot = Acquire();
        if (snapshot is null || snapshot.Databases.Count == 0)
        {
            return Task.FromResult(new EngineStatus(false, "The offline threat database hasn't been downloaded yet."));
        }

        string sources = string.Join(" + ", snapshot.Databases.Select(d => d.Entry.Source).Distinct());
        string text = string.Create(CultureInfo.CurrentCulture, $"{snapshot.Manifest.HashCount:N0} known malware hashes ({sources})");
        return Task.FromResult(new EngineStatus(true, text));
    }

    public async Task<IReadOnlyList<EngineResult>> ScanAsync(IReadOnlyList<ScanTarget> batch, CancellationToken cancellationToken)
    {
        using Snapshot? snapshot = Acquire();
        var results = new EngineResult[batch.Count];
        for (int i = 0; i < batch.Count; i++)
        {
            ScanTarget target = batch[i];
            if (snapshot is null || target.Size == 0)
            {
                // Every empty file shares one hash, and malware corpora contain it: never flag it.
                results[i] = EngineResult.Clean;
                continue;
            }

            try
            {
                results[i] = await LookupAsync(snapshot, target, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                results[i] = EngineResult.Failed(ex.Message);
            }
        }

        return results;
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _snapshot?.Dispose();
            _snapshot = null;
        }
    }

    private static async Task<EngineResult> LookupAsync(Snapshot snapshot, ScanTarget target, CancellationToken cancellationToken)
    {
        ulong? sha256 = target.Sha256.Length == 64 ? HashKey.FromHex(target.Sha256) : null;
        ulong? md5 = null;
        var detections = new List<Detection>();
        foreach ((ThreatDatabaseEntry entry, HashDatabase database) in snapshot.Databases)
        {
            ulong? key = entry.Kind == HashKind.Sha256 ? sha256 : (md5 ??= await Md5Async(target, cancellationToken).ConfigureAwait(false));
            if (key is ulong k && database.Contains(k))
            {
                string algorithm = entry.Kind == HashKind.Md5 ? "MD5" : "SHA-256";
                detections.Add(new Detection(EngineName, $"Known malware ({entry.Source})", Severity.Malicious,
                    $"The file's {algorithm} is in {entry.Source}'s list of malware samples"));
            }
        }

        return new EngineResult(detections);
    }

    private static async Task<ulong?> Md5Async(ScanTarget target, CancellationToken cancellationToken)
    {
        if (target.Md5 is { Length: 32 } known)
        {
            return HashKey.FromHex(known);
        }

        // MD5 only identifies samples in a published list here; it is not used for security decisions on its own.
#pragma warning disable CA5351
        await using var stream = new FileStream(target.Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16, FileOptions.SequentialScan | FileOptions.Asynchronous);
        return HashKey.FromHex(Convert.ToHexStringLower(await MD5.HashDataAsync(stream, cancellationToken).ConfigureAwait(false)));
#pragma warning restore CA5351
    }

    /// <summary>Returns the current databases with a reference held, reopening them when the manifest changed.</summary>
    private Snapshot? Acquire()
    {
        lock (_gate)
        {
            DateTimeOffset now = _time.GetUtcNow();
            if (now - _checkedAt >= RecheckInterval)
            {
                _checkedAt = now;
                Reload();
            }

            _snapshot?.AddRef();
            return _snapshot;
        }
    }

    private void Reload()
    {
        DateTime written;
        try
        {
            written = File.Exists(store.ManifestPath) ? File.GetLastWriteTimeUtc(store.ManifestPath) : DateTime.MinValue;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return;
        }

        if (written == _manifestWrite && _snapshot is not null)
        {
            return;
        }

        ThreatIntelManifest manifest = store.Load();
        var databases = new List<(ThreatDatabaseEntry, HashDatabase)>();
        foreach (ThreatDatabaseEntry entry in manifest.Databases)
        {
            try
            {
                HashDatabase database = HashDatabase.Open(Path.Combine(store.Directory, Path.GetFileName(entry.File)));
                if (database.Kind == entry.Kind)
                {
                    databases.Add((entry, database));
                }
                else
                {
                    database.Dispose();
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
            {
                // Missing or being replaced: picked up on the next manifest change.
            }
        }

        _snapshot?.Dispose();
        _snapshot = new Snapshot(manifest, databases);
        _manifestWrite = written;
    }

    /// <summary>Open databases shared by concurrent scans; closed when the last user releases them.</summary>
    private sealed class Snapshot(ThreatIntelManifest manifest, IReadOnlyList<(ThreatDatabaseEntry Entry, HashDatabase Database)> databases) : IDisposable
    {
        private int _references = 1;

        public ThreatIntelManifest Manifest => manifest;

        public IReadOnlyList<(ThreatDatabaseEntry Entry, HashDatabase Database)> Databases => databases;

        public void AddRef() => Interlocked.Increment(ref _references);

        public void Dispose()
        {
            if (Interlocked.Decrement(ref _references) == 0)
            {
                foreach ((_, HashDatabase database) in databases)
                {
                    database.Dispose();
                }
            }
        }
    }
}
