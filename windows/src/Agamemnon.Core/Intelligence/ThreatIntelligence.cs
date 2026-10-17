using System.Globalization;
using System.IO.Compression;
using System.Net;
using System.Text;
using Agamemnon.Core.Settings;

namespace Agamemnon.Core.Intelligence;

/// <summary>One offline hash database generation built from a feed.</summary>
public sealed record ThreatDatabaseEntry
{
    public string Id { get; init; } = string.Empty;

    /// <summary>Who publishes the hashes, shown in detections (e.g. "VirusShare").</summary>
    public string Source { get; init; } = string.Empty;

    public HashKind Kind { get; init; }

    /// <summary>File name inside the threat-intelligence folder.</summary>
    public string File { get; init; } = string.Empty;

    public long Count { get; init; }

    public DateTimeOffset UpdatedAt { get; init; }

    /// <summary>Feed-specific position, e.g. the next VirusShare list to download.</summary>
    public string? Cursor { get; init; }

    /// <summary>False while a feed is still being downloaded for the first time.</summary>
    public bool Complete { get; init; }
}

/// <summary>
/// What the scan engine service has downloaded, written to
/// <c>%ProgramData%\Agamemnon\ThreatIntel\manifest.json</c> and read by the app.
/// </summary>
public sealed record ThreatIntelManifest
{
    public IReadOnlyList<ThreatDatabaseEntry> Databases { get; init; } = [];

    /// <summary>Signatures in ClamAV's main, daily and bytecode databases.</summary>
    public long ClamAvSignatures { get; init; }

    public int ClamAvVersion { get; init; }

    public DateTimeOffset? ClamAvUpdatedAt { get; init; }

    public long HashCount => Databases.Sum(d => d.Count);

    public long TotalSignatures => HashCount + ClamAvSignatures;
}

/// <summary>Loads and saves the manifest; one writer (the scan engine service), many readers.</summary>
public sealed class ThreatIntelStore(string directory)
{
    public const string ManifestName = "manifest.json";

    private readonly JsonFileStore<ThreatIntelManifest> _file = new(Path.Combine(directory, ManifestName));
    private readonly Lock _gate = new();

    public string Directory => directory;

    public string ManifestPath => _file.Path;

    public ThreatIntelManifest Load() => _file.Load();

    public ThreatIntelManifest Update(Func<ThreatIntelManifest, ThreatIntelManifest> change)
    {
        lock (_gate)
        {
            ThreatIntelManifest updated = change(_file.Load());
            _file.Save(updated);
            return updated;
        }
    }

    /// <summary>Records ClamAV's signature count (called after each freshclam run).</summary>
    public void RecordClamAv(string databaseDirectory, DateTimeOffset now)
    {
        IReadOnlyList<ClamAvDatabaseInfo.Header> headers = ClamAvDatabaseInfo.Read(databaseDirectory);
        if (headers.Count == 0)
        {
            return;
        }

        Update(m => m with
        {
            ClamAvSignatures = headers.Sum(h => h.Signatures),
            ClamAvVersion = headers.FirstOrDefault(h => h.Name.Equals("daily", StringComparison.OrdinalIgnoreCase))?.Version ?? headers.Max(h => h.Version),
            ClamAvUpdatedAt = now,
        });
    }
}

/// <summary>Reads signature counts from ClamAV database headers (.cvd, .cld, .cud).</summary>
public static class ClamAvDatabaseInfo
{
    public sealed record Header(string Name, int Version, long Signatures);

    /// <summary>Header: <c>ClamAV-VDB:build time:version:signatures:functionality level:md5:dsig:builder:stime</c>.</summary>
    public static Header? ParseHeader(string name, ReadOnlySpan<byte> first512)
    {
        string text = Encoding.ASCII.GetString(first512).TrimEnd('\0', ' ');
        string[] fields = text.Split(':');
        if (fields.Length < 4 || fields[0] != "ClamAV-VDB")
        {
            return null;
        }

        // The build time contains no colons ("15 Oct 2026 08-23 -0400"), so the fields line up.
        return int.TryParse(fields[2], NumberStyles.Integer, CultureInfo.InvariantCulture, out int version)
               && long.TryParse(fields[3], NumberStyles.Integer, CultureInfo.InvariantCulture, out long signatures)
            ? new Header(name, version, signatures)
            : null;
    }

    public static IReadOnlyList<Header> Read(string databaseDirectory)
    {
        var headers = new List<Header>();
        if (!System.IO.Directory.Exists(databaseDirectory))
        {
            return headers;
        }

        byte[] buffer = new byte[512];
        foreach (string file in System.IO.Directory.EnumerateFiles(databaseDirectory))
        {
            string extension = Path.GetExtension(file).ToLowerInvariant();
            if (extension is not (".cvd" or ".cld" or ".cud"))
            {
                continue;
            }

            try
            {
                using var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                int read = stream.ReadAtLeast(buffer, buffer.Length, throwOnEndOfStream: false);
                if (ParseHeader(Path.GetFileNameWithoutExtension(file), buffer.AsSpan(0, read)) is { } header)
                {
                    headers.Add(header);
                }
            }
            catch (IOException)
            {
                // freshclam is replacing the file right now; the next refresh counts it.
            }
        }

        // daily.cld and daily.cvd can briefly coexist during an update: count each database once.
        return [.. headers.GroupBy(h => h.Name, StringComparer.OrdinalIgnoreCase).Select(g => g.MaxBy(h => h.Version)!)];
    }
}

/// <summary>New hashes from one feed download.</summary>
/// <param name="Keys">Hash keys, any order.</param>
/// <param name="Replace">True when the keys are the feed's full list rather than an addition.</param>
/// <param name="Cursor">Where the next download continues.</param>
/// <param name="Complete">False when more of the feed is waiting to be downloaded.</param>
public sealed record FeedBatch(ulong[] Keys, bool Replace, string? Cursor, bool Complete);

public interface IThreatFeed
{
    string Id { get; }

    string Source { get; }

    HashKind Kind { get; }

    /// <summary>How long a complete download stays fresh.</summary>
    TimeSpan RefreshInterval { get; }

    Task<FeedBatch> FetchAsync(HttpClient http, ThreatDatabaseEntry? current, CancellationToken cancellationToken);
}

public static class FeedParser
{
    public static void ReadKeys(Stream stream, HashKind kind, List<ulong> keys)
    {
        using var reader = new StreamReader(stream, Encoding.ASCII, detectEncodingFromByteOrderMarks: true, 1 << 16, leaveOpen: true);
        while (reader.ReadLine() is { } line)
        {
            if (HashKey.TryParseLine(line, kind, out ulong key))
            {
                keys.Add(key);
            }
        }
    }

    /// <summary>Reads a plain-text list, or every text file inside a zip (abuse.ch exports are zipped).</summary>
    public static async Task ReadKeysAsync(HttpContent content, HashKind kind, List<ulong> keys, CancellationToken cancellationToken)
    {
        await using Stream body = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        var buffered = new MemoryStream();
        await body.CopyToAsync(buffered, cancellationToken).ConfigureAwait(false);
        buffered.Position = 0;
        if (buffered.Length >= 4 && buffered.GetBuffer() is [(byte)'P', (byte)'K', 3, 4, ..])
        {
            using var zip = new ZipArchive(buffered, ZipArchiveMode.Read);
            foreach (ZipArchiveEntry entry in zip.Entries)
            {
                await using Stream inner = await entry.OpenAsync(cancellationToken).ConfigureAwait(false);
                ReadKeys(inner, kind, keys);
            }
        }
        else
        {
            ReadKeys(buffered, kind, keys);
        }
    }
}

/// <summary>
/// VirusShare's public MD5 lists (VirusShare_00000.md5, VirusShare_00001.md5, …): tens of millions
/// of malware samples, published in numbered lists that never change once released. Downloads a
/// few dozen lists per run until it reaches the newest one, then checks daily for new lists.
/// </summary>
public sealed class VirusShareFeed(Uri? baseUri = null, int listsPerRun = 40, TimeSpan? pause = null) : IThreatFeed
{
    private readonly Uri _base = baseUri ?? new Uri("https://virusshare.com/hashfiles/");
    private readonly TimeSpan _pause = pause ?? TimeSpan.FromSeconds(1);

    public string Id => "virusshare-md5";

    public string Source => "VirusShare";

    public HashKind Kind => HashKind.Md5;

    public TimeSpan RefreshInterval => TimeSpan.FromDays(1);

    public async Task<FeedBatch> FetchAsync(HttpClient http, ThreatDatabaseEntry? current, CancellationToken cancellationToken)
    {
        int next = int.TryParse(current?.Cursor, NumberStyles.Integer, CultureInfo.InvariantCulture, out int n) ? n : 0;
        var keys = new List<ulong>();
        for (int fetched = 0; fetched < listsPerRun; fetched++)
        {
            var uri = new Uri(_base, $"VirusShare_{next:D5}.md5");
            using HttpResponseMessage response = await http.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
            if (response.StatusCode == HttpStatusCode.NotFound)
            {
                // No list with this number yet: everything published so far is downloaded.
                return new FeedBatch([.. keys], Replace: false, next.ToString(CultureInfo.InvariantCulture), Complete: true);
            }

            response.EnsureSuccessStatusCode();
            await FeedParser.ReadKeysAsync(response.Content, Kind, keys, cancellationToken).ConfigureAwait(false);
            next++;
            if (_pause > TimeSpan.Zero)
            {
                await Task.Delay(_pause, cancellationToken).ConfigureAwait(false);
            }
        }

        return new FeedBatch([.. keys], Replace: false, next.ToString(CultureInfo.InvariantCulture), Complete: false);
    }
}

/// <summary>A full hash export that is downloaded again and replaced on every refresh.</summary>
public sealed class HashExportFeed(string id, string source, HashKind kind, Uri uri, TimeSpan refreshInterval) : IThreatFeed
{
    /// <summary>Every SHA-256 in abuse.ch MalwareBazaar, refreshed daily.</summary>
    public static HashExportFeed MalwareBazaar() => new(
        "malwarebazaar-sha256", "MalwareBazaar", HashKind.Sha256,
        new Uri("https://bazaar.abuse.ch/export/txt/sha256/full/"), TimeSpan.FromDays(1));

    public string Id => id;

    public string Source => source;

    public HashKind Kind => kind;

    public TimeSpan RefreshInterval => refreshInterval;

    public async Task<FeedBatch> FetchAsync(HttpClient http, ThreatDatabaseEntry? current, CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await http.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        var keys = new List<ulong>();
        await FeedParser.ReadKeysAsync(response.Content, kind, keys, cancellationToken).ConfigureAwait(false);
        if (keys.Count == 0)
        {
            throw new InvalidDataException($"{source} returned no hashes.");
        }

        return new FeedBatch([.. keys], Replace: true, null, Complete: true);
    }
}

public sealed record ThreatUpdateResult(IReadOnlyList<string> Updated, IReadOnlyList<string> Errors, bool MoreWaiting);

/// <summary>
/// Downloads the hash feeds and builds the offline databases. Each update writes a new file
/// generation and then switches the manifest to it, so scans in progress keep a consistent view.
/// </summary>
public sealed class ThreatFeedUpdater(ThreatIntelStore store, HttpClient http, IReadOnlyList<IThreatFeed> feeds, TimeProvider? time = null)
{
    private readonly TimeProvider _time = time ?? TimeProvider.System;

    public static IReadOnlyList<IThreatFeed> DefaultFeeds() => [new VirusShareFeed(), HashExportFeed.MalwareBazaar()];

    public async Task<ThreatUpdateResult> UpdateAsync(CancellationToken cancellationToken)
    {
        var updated = new List<string>();
        var errors = new List<string>();
        bool more = false;
        System.IO.Directory.CreateDirectory(store.Directory);
        foreach (IThreatFeed feed in feeds)
        {
            ThreatDatabaseEntry? current = store.Load().Databases.FirstOrDefault(d => d.Id == feed.Id);
            if (current is { Complete: true } && _time.GetUtcNow() - current.UpdatedAt < feed.RefreshInterval && File.Exists(PathOf(current)))
            {
                continue;
            }

            try
            {
                FeedBatch batch = await feed.FetchAsync(http, current, cancellationToken).ConfigureAwait(false);
                ThreatDatabaseEntry entry = await Task.Run(() => Build(feed, current, batch), cancellationToken).ConfigureAwait(false);
                store.Update(m => m with { Databases = [.. m.Databases.Where(d => d.Id != feed.Id), entry] });
                if (current is not null && current.File != entry.File)
                {
                    TryDelete(PathOf(current));
                }

                updated.Add($"{feed.Source}: {entry.Count:N0} hashes");
                more |= !batch.Complete;
            }
            catch (Exception ex) when (ex is HttpRequestException or IOException or InvalidDataException
                                       || (ex is TaskCanceledException && !cancellationToken.IsCancellationRequested))
            {
                errors.Add($"{feed.Source}: {ex.Message}");
            }
        }

        CleanUpUnreferenced();
        return new ThreatUpdateResult(updated, errors, more);
    }

    private ThreatDatabaseEntry Build(IThreatFeed feed, ThreatDatabaseEntry? current, FeedBatch batch)
    {
        DateTimeOffset now = _time.GetUtcNow();
        ulong[] keys = batch.Keys;
        Array.Sort(keys);
        bool keepExisting = !batch.Replace && current is not null && File.Exists(PathOf(current));
        if (keepExisting && keys.Length == 0)
        {
            return current! with { UpdatedAt = now, Cursor = batch.Cursor, Complete = batch.Complete };
        }

        string file = $"{feed.Id}-{now:yyyyMMddHHmmss}-{Guid.NewGuid().ToString("N")[..6]}.agdb";
        string path = Path.Combine(store.Directory, file);
        string temp = path + ".tmp";
        long count;
        try
        {
            if (keepExisting)
            {
                using HashDatabase existing = HashDatabase.Open(PathOf(current!));
                count = HashDatabase.Write(temp, feed.Kind, HashDatabase.Merge(existing.ReadAll(), keys), now);
            }
            else
            {
                count = HashDatabase.Write(temp, feed.Kind, keys, now);
            }

            File.Move(temp, path);
        }
        catch
        {
            TryDelete(temp);
            throw;
        }

        return new ThreatDatabaseEntry
        {
            Id = feed.Id,
            Source = feed.Source,
            Kind = feed.Kind,
            File = file,
            Count = count,
            UpdatedAt = now,
            Cursor = batch.Cursor,
            Complete = batch.Complete,
        };
    }

    private string PathOf(ThreatDatabaseEntry entry) => Path.Combine(store.Directory, entry.File);

    /// <summary>Removes old generations a scan was still reading during the previous update.</summary>
    private void CleanUpUnreferenced()
    {
        var referenced = new HashSet<string>(store.Load().Databases.Select(d => d.File), StringComparer.OrdinalIgnoreCase);
        foreach (string file in System.IO.Directory.EnumerateFiles(store.Directory, "*.agdb*"))
        {
            if (!referenced.Contains(Path.GetFileName(file)))
            {
                TryDelete(file);
            }
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }
}

/// <summary>How many threats Agamemnon can recognise, by source, for the dashboard.</summary>
public sealed record ThreatCoverage(long Total, bool Downloading, IReadOnlyList<ThreatCoverage.Source> Sources)
{
    /// <summary>Agamemnon 2.0's target: at least 50 million known threats once every feed is downloaded.</summary>
    public const long Goal = 50_000_000;

    public sealed record Source(string Name, long Count, string What);

    public bool MeetsGoal => Total >= Goal;

    public static ThreatCoverage From(ThreatIntelManifest? manifest, int yaraRules)
    {
        var sources = new List<Source>();
        if (manifest is { ClamAvSignatures: > 0 })
        {
            sources.Add(new Source("ClamAV", manifest.ClamAvSignatures, "signatures"));
        }

        foreach (ThreatDatabaseEntry entry in manifest?.Databases ?? [])
        {
            sources.Add(new Source(entry.Source, entry.Count, entry.Kind == HashKind.Md5 ? "MD5 malware hashes" : "SHA-256 malware hashes"));
        }

        if (yaraRules > 0)
        {
            sources.Add(new Source("YARA", yaraRules, "behaviour rules"));
        }

        bool downloading = manifest is null || manifest.Databases.Count == 0 || manifest.Databases.Any(d => !d.Complete);
        return new ThreatCoverage(sources.Sum(s => s.Count), downloading, sources);
    }
}
