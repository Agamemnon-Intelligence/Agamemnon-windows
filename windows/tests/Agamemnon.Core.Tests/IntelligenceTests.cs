using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Agamemnon.Core.Intelligence;
using Agamemnon.Core.Scanning;

namespace Agamemnon.Core.Tests;

public sealed class IntelligenceTests
{
    private const string EmptyMd5 = "d41d8cd98f00b204e9800998ecf8427e";

    [Fact]
    public void HashKey_parses_feed_lines_and_rejects_junk()
    {
        Assert.True(HashKey.TryParseLine("0123456789abcdef0123456789abcdef", HashKind.Md5, out ulong key));
        Assert.Equal(0x0123456789abcdefUL, key);
        Assert.True(HashKey.TryParseLine("  0123456789ABCDEF0123456789ABCDEF  # note", HashKind.Md5, out _));
        Assert.False(HashKey.TryParseLine("# VirusShare_00000.md5", HashKind.Md5, out _));
        Assert.False(HashKey.TryParseLine("0123456789abcdef", HashKind.Md5, out _));
        Assert.False(HashKey.TryParseLine("zz23456789abcdef0123456789abcdef", HashKind.Md5, out _));

        // A SHA-256 line is not an MD5 that happens to be followed by more hex.
        Assert.False(HashKey.TryParseLine(new string('a', 64), HashKind.Md5, out _));
        Assert.True(HashKey.TryParseLine(new string('a', 64), HashKind.Sha256, out _));
    }

    [Fact]
    public void Database_finds_every_key_and_nothing_else()
    {
        using var dir = new TempDir();
        string path = Path.Combine(dir.Path, "test.agdb");
        var random = new Random(7);
        ulong[] keys = [.. Enumerable.Range(0, 50_000).Select(_ => (ulong)random.NextInt64() << 1)];
        ulong[] sorted = [.. keys.Order()];
        long written = HashDatabase.Write(path, HashKind.Md5, [.. sorted, sorted[^1]], DateTimeOffset.UnixEpoch);
        Assert.Equal(keys.Distinct().Count(), written);

        using HashDatabase db = HashDatabase.Open(path);
        Assert.Equal(HashKind.Md5, db.Kind);
        Assert.Equal(written, db.Count);
        Assert.All(keys, k => Assert.True(db.Contains(k)));
        Assert.All(keys.Take(1000), k => Assert.False(db.Contains(k | 1)));
        Assert.False(db.Contains(0));
        Assert.False(db.Contains(ulong.MaxValue));
        Assert.Equal(sorted.Distinct(), db.ReadAll());
    }

    [Fact]
    public void Database_rejects_unsorted_input_and_damaged_files()
    {
        using var dir = new TempDir();
        string path = Path.Combine(dir.Path, "bad.agdb");
        Assert.Throws<ArgumentException>(() => HashDatabase.Write(path, HashKind.Md5, [5, 3], DateTimeOffset.UnixEpoch));

        HashDatabase.Write(path, HashKind.Md5, [1, 2, 3], DateTimeOffset.UnixEpoch);
        using (var stream = File.OpenWrite(path))
        {
            stream.SetLength(stream.Length - 4);
        }

        Assert.Throws<InvalidDataException>(() => HashDatabase.Open(path));
        File.WriteAllText(path, "not a database at all, just some text that is long enough to have a header");
        Assert.Throws<InvalidDataException>(() => HashDatabase.Open(path));
    }

    [Fact]
    public void Empty_database_contains_nothing()
    {
        using var dir = new TempDir();
        string path = Path.Combine(dir.Path, "empty.agdb");
        Assert.Equal(0, HashDatabase.Write(path, HashKind.Sha256, [], DateTimeOffset.UnixEpoch));
        using HashDatabase db = HashDatabase.Open(path);
        Assert.False(db.Contains(42));
    }

    [Fact]
    public void Merge_keeps_ascending_order()
    {
        Assert.Equal([1UL, 2, 3, 4, 5, 6, 9], HashDatabase.Merge([1, 4, 5, 9], [2, 3, 6]));
        Assert.Equal([1UL, 2], HashDatabase.Merge([], [1, 2]));
    }

    [Fact]
    public void ClamAv_header_gives_signature_count()
    {
        byte[] header = new byte[512];
        Encoding.ASCII.GetBytes("ClamAV-VDB:16 Oct 2026 07-20 +0000:27792:2087554:90:abcdef:sig:builder:1760599200").CopyTo(header, 0);
        ClamAvDatabaseInfo.Header? parsed = ClamAvDatabaseInfo.ParseHeader("daily", header);
        Assert.NotNull(parsed);
        Assert.Equal(27792, parsed.Version);
        Assert.Equal(2087554, parsed.Signatures);
        Assert.Null(ClamAvDatabaseInfo.ParseHeader("x", "MZ\0\0"u8));
    }

    [Fact]
    public void ClamAv_counts_each_database_once()
    {
        using var dir = new TempDir();
        dir.File("main.cvd", Header(62, 6_647_427));
        dir.File("daily.cvd", Header(27790, 2_087_000));
        dir.File("daily.cld", Header(27792, 2_087_554));
        dir.File("bytecode.cvd", Header(336, 83));
        dir.File("freshclam.dat", "ignored");
        IReadOnlyList<ClamAvDatabaseInfo.Header> headers = ClamAvDatabaseInfo.Read(dir.Path);
        Assert.Equal(3, headers.Count);
        Assert.Equal(6_647_427 + 2_087_554 + 83, headers.Sum(h => h.Signatures));

        static byte[] Header(int version, long sigs)
        {
            byte[] bytes = new byte[600];
            Encoding.ASCII.GetBytes($"ClamAV-VDB:16 Oct 2026 07-20 +0000:{version}:{sigs}:90:md5:sig:builder:1").CopyTo(bytes, 0);
            return bytes;
        }
    }

    [Fact]
    public async Task VirusShare_downloads_lists_in_batches_until_the_newest()
    {
        using var dir = new TempDir();
        var lists = new Dictionary<string, string>
        {
            ["/hashfiles/VirusShare_00000.md5"] = "# header\n" + Md5Of("a") + "\n" + Md5Of("b") + "\n",
            ["/hashfiles/VirusShare_00001.md5"] = Md5Of("c") + "\n",
            ["/hashfiles/VirusShare_00002.md5"] = Md5Of("d") + "\r\n" + Md5Of("a") + "\r\n",
        };
        using var http = new HttpClient(new MapHandler(lists));
        var store = new ThreatIntelStore(dir.Path);
        var clock = new ManualClock(DateTimeOffset.Parse("2026-10-17T00:00:00Z", System.Globalization.CultureInfo.InvariantCulture));
        var updater = new ThreatFeedUpdater(store, http, [new VirusShareFeed(new Uri("https://example.test/hashfiles/"), listsPerRun: 2, TimeSpan.Zero)], clock);

        ThreatUpdateResult first = await updater.UpdateAsync(CancellationToken.None);
        Assert.Empty(first.Errors);
        Assert.True(first.MoreWaiting);
        ThreatDatabaseEntry entry = Assert.Single(store.Load().Databases);
        Assert.Equal(3, entry.Count);
        Assert.Equal("2", entry.Cursor);
        Assert.False(entry.Complete);

        clock.Advance(TimeSpan.FromMinutes(5));
        ThreatUpdateResult second = await updater.UpdateAsync(CancellationToken.None);
        Assert.False(second.MoreWaiting);
        entry = Assert.Single(store.Load().Databases);
        Assert.Equal(4, entry.Count);
        Assert.Equal("3", entry.Cursor);
        Assert.True(entry.Complete);

        // Old generations are removed once the manifest no longer points at them.
        Assert.Single(Directory.GetFiles(dir.Path, "*.agdb"));

        // Complete and fresh: nothing is downloaded until the refresh interval passes.
        lists.Clear();
        ThreatUpdateResult third = await updater.UpdateAsync(CancellationToken.None);
        Assert.Empty(third.Updated);
        Assert.Empty(third.Errors);
    }

    [Fact]
    public async Task Export_feed_reads_zipped_lists_and_replaces_the_previous_one()
    {
        using var dir = new TempDir();
        string sha = Sha256Of("evil");
        var zipped = new MemoryStream();
        using (var zip = new ZipArchive(zipped, ZipArchiveMode.Create, leaveOpen: true))
        {
            using var writer = new StreamWriter(zip.CreateEntry("full_sha256.txt").Open());
            writer.Write("################\n# MalwareBazaar\n" + sha + "\n");
        }

        var handler = new MapHandler(new Dictionary<string, byte[]> { ["/full/"] = zipped.ToArray() });
        using var http = new HttpClient(handler);
        var store = new ThreatIntelStore(dir.Path);
        var feed = new HashExportFeed("mb", "MalwareBazaar", HashKind.Sha256, new Uri("https://example.test/full/"), TimeSpan.Zero);
        var updater = new ThreatFeedUpdater(store, http, [feed]);
        ThreatUpdateResult result = await updater.UpdateAsync(CancellationToken.None);
        Assert.Empty(result.Errors);
        Assert.Equal(1, store.Load().HashCount);

        // A failed refresh keeps the last good database.
        handler.Fail = true;
        ThreatUpdateResult failed = await updater.UpdateAsync(CancellationToken.None);
        Assert.Single(failed.Errors);
        Assert.Equal(1, store.Load().HashCount);
    }

    [Fact]
    public async Task Engine_flags_files_whose_hash_is_listed()
    {
        using var dir = new TempDir();
        string bad = dir.File("bad.bin", "known malware sample");
        string good = dir.File("good.txt", "an ordinary document");
        string empty = dir.File("empty.dat", []);
        var store = SeedStore(dir, "intel",
            md5: [Md5Of("known malware sample"), EmptyMd5],
            sha256: [Sha256Of("known malware sample")]);

        using var engine = new OfflineHashEngine(store);
        EngineStatus status = await engine.GetStatusAsync(CancellationToken.None);
        Assert.True(status.Available);
        Assert.Contains("3", status.Description, StringComparison.Ordinal);

        IReadOnlyList<EngineResult> results = await engine.ScanAsync(
        [
            Target(bad, "known malware sample"),
            Target(good, "an ordinary document") with { Md5 = null },
            Target(empty, string.Empty),
        ], CancellationToken.None);

        Assert.Equal(2, results[0].Detections.Count);
        Assert.All(results[0].Detections, d => Assert.Equal(Severity.Malicious, d.Severity));
        Assert.Contains(results[0].Detections, d => d.Name == "Known malware (VirusShare)");
        Assert.Contains(results[0].Detections, d => d.Name == "Known malware (MalwareBazaar)");
        Assert.Empty(results[1].Detections);
        Assert.Empty(results[2].Detections);
    }

    [Fact]
    public async Task Engine_is_unavailable_before_the_first_download()
    {
        using var dir = new TempDir();
        using var engine = new OfflineHashEngine(new ThreatIntelStore(Path.Combine(dir.Path, "missing")));
        Assert.False((await engine.GetStatusAsync(CancellationToken.None)).Available);
        IReadOnlyList<EngineResult> results = await engine.ScanAsync([new ScanTarget("x", "x", new string('0', 64), 1, FileKind.Other, null, 0)], CancellationToken.None);
        Assert.Empty(results[0].Detections);
    }

    [Fact]
    public async Task Coordinator_hands_engines_the_md5()
    {
        using var dir = new TempDir();
        string file = dir.File("sample.exe", "MZ known malware sample");
        var store = SeedStore(dir, "intel", md5: [Md5Of("MZ known malware sample")], sha256: []);
        using var engine = new OfflineHashEngine(store);
        var coordinator = new ScanCoordinator([engine], Archives.ArchiveExpander.CreateDefault([]), _ => null, Path.Combine(dir.Path, "work"));
        ScanReport report = await coordinator.ScanAsync([file], new ScanOptions(), null, CancellationToken.None);
        Assert.Equal(1, report.ThreatCount);
    }

    private static ThreatIntelStore SeedStore(TempDir dir, string name, string[] md5, string[] sha256)
    {
        string folder = Path.Combine(dir.Path, name);
        Directory.CreateDirectory(folder);
        var store = new ThreatIntelStore(folder);
        HashDatabase.Write(Path.Combine(folder, "vs.agdb"), HashKind.Md5, md5.Select(HashKey.FromHex).Order(), DateTimeOffset.UnixEpoch);
        HashDatabase.Write(Path.Combine(folder, "mb.agdb"), HashKind.Sha256, sha256.Select(HashKey.FromHex).Order(), DateTimeOffset.UnixEpoch);
        store.Update(m => m with
        {
            Databases =
            [
                new ThreatDatabaseEntry { Id = "vs", Source = "VirusShare", Kind = HashKind.Md5, File = "vs.agdb", Count = md5.Length, Complete = true },
                new ThreatDatabaseEntry { Id = "mb", Source = "MalwareBazaar", Kind = HashKind.Sha256, File = "mb.agdb", Count = sha256.Length, Complete = true },
            ],
        });
        return store;
    }

    private static ScanTarget Target(string path, string content) =>
        new(path, path, Sha256Of(content), new FileInfo(path).Length, FileKind.Other, null, 0) { Md5 = Md5Of(content) };

#pragma warning disable CA5351 // test data: VirusShare publishes MD5s
    private static string Md5Of(string text) => Convert.ToHexStringLower(MD5.HashData(Encoding.UTF8.GetBytes(text)));
#pragma warning restore CA5351

    private static string Sha256Of(string text) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));

    private sealed class MapHandler : HttpMessageHandler
    {
        private readonly Func<string, byte[]?> _lookup;

        public MapHandler(Dictionary<string, string> texts) => _lookup = p => texts.TryGetValue(p, out string? t) ? Encoding.ASCII.GetBytes(t) : null;

        public MapHandler(Dictionary<string, byte[]> bytes) => _lookup = p => bytes.GetValueOrDefault(p);

        public bool Fail { get; set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (Fail)
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
            }

            byte[]? body = _lookup(request.RequestUri!.AbsolutePath);
            return Task.FromResult(body is null
                ? new HttpResponseMessage(HttpStatusCode.NotFound)
                : new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) });
        }
    }

    private sealed class ManualClock(DateTimeOffset start) : TimeProvider
    {
        private DateTimeOffset _now = start;

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan by) => _now += by;
    }
}
