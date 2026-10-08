using System.Buffers.Binary;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Agamemnon.Core.Archives;
using Agamemnon.Core.Reputation;
using Agamemnon.Core.Scanning;
using Agamemnon.Core.Util;

namespace Agamemnon.Core.Tests;

public sealed class TempDir : IDisposable
{
    public TempDir()
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "agamemnon-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
    }

    public string Path { get; }

    public string File(string name, string content) => File(name, Encoding.UTF8.GetBytes(content));

    public string File(string name, byte[] content)
    {
        // GetFullPath turns '/' into the platform separator, so callers can compare paths.
        string full = System.IO.Path.GetFullPath(System.IO.Path.Combine(Path, name));
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(full)!);
        System.IO.File.WriteAllBytes(full, content);
        return full;
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(Path, recursive: true);
        }
        catch (IOException)
        {
        }
    }
}

/// <summary>Flags any file whose content contains a marker string, like a signature engine would.</summary>
internal sealed class MarkerEngine(string marker = "EVIL-MARKER", Severity severity = Severity.Malicious) : IScanEngine
{
    public string Name => "Marker";

    public List<string> Seen { get; } = [];

    public Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken) => Task.FromResult(new EngineStatus(true, "ok"));

    public Task<IReadOnlyList<EngineResult>> ScanAsync(IReadOnlyList<ScanTarget> batch, CancellationToken cancellationToken)
    {
        IReadOnlyList<EngineResult> results = [.. batch.Select(t =>
        {
            Seen.Add(t.DisplayPath);
            return File.ReadAllText(t.Path).Contains(marker, StringComparison.Ordinal)
                ? new EngineResult([new Detection(Name, "Test.Marker", severity)])
                : EngineResult.Clean;
        })];
        return Task.FromResult(results);
    }
}

public class FileClassifierTests
{
    [Fact]
    public void Classifies_by_content_before_extension()
    {
        Assert.Equal(FileKind.PortableExecutable, FileClassifier.Classify("photo.jpg", "MZ\x90\0"u8));
        Assert.Equal(FileKind.Archive, FileClassifier.Classify("report.docx", "PK\x03\x04"u8));
        Assert.Equal(FileKind.Script, FileClassifier.Classify("run.ps1", "Write-Host"u8));
        Assert.Equal(FileKind.Shortcut, FileClassifier.Classify("x.bin", [0x4C, 0, 0, 0, 1, 0x14, 2, 0]));
        Assert.Equal(FileKind.WindowsInstaller, FileClassifier.Classify("setup.msi", [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]));
        Assert.Equal(FileKind.Document, FileClassifier.Classify("old.doc", [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]));
        Assert.Equal(FileKind.Other, FileClassifier.Classify("notes.txt", "hello"u8));
    }

    [Theory]
    [InlineData("invoice.pdf.exe", true)]
    [InlineData("photo\u202Egpj.exe", true)]
    [InlineData("setup.exe", false)]
    [InlineData("report.pdf", false)]
    public void Spots_disguised_names(string name, bool suspicious)
    {
        Assert.Equal(suspicious, FileNameHeuristics.Inspect(name) is not null);
    }

    [Fact]
    public void Parses_mark_of_the_web()
    {
        FileOrigin? origin = FileOrigin.Parse("[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://example.com/\r\nHostUrl=https://dl.example.com/a.exe\r\n");
        Assert.NotNull(origin);
        Assert.True(origin.IsFromInternet);
        Assert.Equal("https://dl.example.com/a.exe", origin.HostUrl);
        Assert.False(FileOrigin.Parse("[ZoneTransfer]\nZoneId=1")!.IsFromInternet);
        Assert.Null(FileOrigin.Parse("garbage"));
    }
}

public class ClamAvEngineTests
{
    [Theory]
    [InlineData("stream: OK\0", 0, null)]
    [InlineData("stream: Win.Test.EICAR_HDB-1 FOUND\0", 1, Severity.Malicious)]
    [InlineData("stream: PUA.Win.Tool.Agent-1 FOUND", 1, Severity.Suspicious)]
    public void Parses_replies(string reply, int count, Severity? severity)
    {
        IReadOnlyList<Detection> detections = ClamAvEngine.ParseReply(reply);
        Assert.Equal(count, detections.Count);
        if (severity is not null)
        {
            Assert.Equal(severity, detections[0].Severity);
        }
    }

    [Fact]
    public void Size_limit_is_an_error_not_a_clean_result()
    {
        Assert.Throws<EngineException>(() => ClamAvEngine.ParseReply("INSTREAM size limit exceeded. ERROR"));
    }

    [Fact]
    public void Parses_version()
    {
        ClamAvVersion? v = ClamAvVersion.Parse("ClamAV 1.4.3/27788/Sun Oct  5 08:24:01 2026\n");
        Assert.NotNull(v);
        Assert.Equal("1.4.3", v.Engine);
        Assert.Equal(27788, v.DatabaseVersion);
        Assert.Equal("Sun Oct 5 08:24:01 2026", v.DatabaseDate);
    }

    [Fact]
    public async Task Streams_files_to_clamd_with_instream()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var received = new MemoryStream();
        Task server = Task.Run(async () =>
        {
            using TcpClient client = await listener.AcceptTcpClientAsync();
            NetworkStream stream = client.GetStream();
            byte[] command = new byte[10];
            await stream.ReadExactlyAsync(command);
            Assert.Equal("zINSTREAM\0", Encoding.ASCII.GetString(command));
            byte[] length = new byte[4];
            while (true)
            {
                await stream.ReadExactlyAsync(length);
                int n = (int)BinaryPrimitives.ReadUInt32BigEndian(length);
                if (n == 0)
                {
                    break;
                }

                byte[] chunk = new byte[n];
                await stream.ReadExactlyAsync(chunk);
                received.Write(chunk);
            }

            string verdict = Encoding.ASCII.GetString(received.ToArray()).Contains("EICAR", StringComparison.Ordinal)
                ? "stream: Eicar-Signature FOUND\0"
                : "stream: OK\0";
            await stream.WriteAsync(Encoding.ASCII.GetBytes(verdict));
        });

        using var dir = new TempDir();
        string file = dir.File("sample.com", "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
        var engine = new ClamAvEngine((IPEndPoint)listener.LocalEndpoint);
        var target = new ScanTarget(file, file, "00", new FileInfo(file).Length, FileKind.Other, null, 0);
        IReadOnlyList<EngineResult> results = await engine.ScanAsync([target], default);
        await server;
        Assert.Equal("Eicar-Signature", Assert.Single(results[0].Detections).Name);
        Assert.Equal(new FileInfo(file).Length, received.Length);
    }

    [Fact]
    public async Task Reports_unavailable_when_clamd_is_down()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var endpoint = (IPEndPoint)listener.LocalEndpoint;
        listener.Stop();
        EngineStatus status = await new ClamAvEngine(endpoint).GetStatusAsync(default);
        Assert.False(status.Available);
    }
}

public class YaraEngineTests
{
    private static ScanTarget Target(string path) => new(path, path, "00", 1, FileKind.Other, null, 0);

    [Fact]
    public void Parses_matches_for_paths_with_spaces()
    {
        ScanTarget[] batch = [Target(@"C:\Users\a b\Downloads\setup.exe"), Target(@"C:\x\setup.exe")];
        string stdout =
            "Suspicious_PowerShell_Cradle [suspicious] C:\\Users\\a b\\Downloads\\setup.exe\r\n" +
            "Win_Stealer_Generic [malicious,stealer] C:\\x\\setup.exe\r\n" +
            "NoTags [] C:\\x\\setup.exe\n";
        IReadOnlyList<EngineResult> results = YaraEngine.ParseOutput(batch, stdout, "error scanning C:\\x\\setup.exe: could not open file\n");
        Assert.Equal("Suspicious_PowerShell_Cradle", Assert.Single(results[0].Detections).Name);
        Assert.Equal(Severity.Suspicious, results[0].Detections[0].Severity);
        Assert.Equal(2, results[1].Detections.Count);
        Assert.Equal(Severity.Malicious, results[1].Detections[0].Severity);
        Assert.Contains("could not open file", results[1].Error, StringComparison.Ordinal);
        Assert.Null(results[0].Error);
    }

    private sealed class FakeRunner : IProcessRunner
    {
        public List<(string File, IReadOnlyList<string> Args)> Calls { get; } = [];

        public Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken)
        {
            Calls.Add((fileName, arguments));
            if (fileName.EndsWith("yarac", StringComparison.Ordinal))
            {
                File.WriteAllText(arguments[^1], "compiled");
                return Task.FromResult(new ProcessResult(0, "", ""));
            }

            string[] scanned = File.ReadAllLines(arguments[^1]);
            return Task.FromResult(new ProcessResult(0, $"Rule1 [] {scanned[0]}\n", ""));
        }
    }

    [Fact]
    public async Task Compiles_rules_once_with_namespaces_and_scans_with_a_list()
    {
        using var dir = new TempDir();
        string yara = dir.File("bin/yara", "");
        string yarac = dir.File("bin/yarac", "");
        dir.File("rules/windows.yar", "rule a { condition: false }");
        dir.File("rules/1st-pack.yara", "rule b { condition: false }");
        string sample = dir.File("sample.bin", "x");
        var runner = new FakeRunner();
        using var engine = new YaraEngine(yara, yarac, [Path.Combine(dir.Path, "rules")], Path.Combine(dir.Path, "cache"), runner);

        Assert.True((await engine.GetStatusAsync(default)).Available);
        IReadOnlyList<EngineResult> results = await engine.ScanAsync([Target(sample)], default);
        await engine.ScanAsync([Target(sample)], default);

        Assert.Equal("Rule1", Assert.Single(results[0].Detections).Name);
        var compiles = runner.Calls.Where(c => c.File == yarac).ToList();
        Assert.Single(compiles);
        Assert.Contains(compiles[0].Args, a => a.StartsWith("r_1st_pack:", StringComparison.Ordinal));
        Assert.Contains(compiles[0].Args, a => a.StartsWith("windows:", StringComparison.Ordinal));
        Assert.Contains("--scan-list", runner.Calls.Last().Args);
        Assert.Empty(Directory.EnumerateFiles(Path.Combine(dir.Path, "cache"), "scanlist-*"));
    }
}

public class ReputationTests
{
    [Fact]
    public void Interprets_malwarebazaar()
    {
        Assert.Null(MalwareBazaarClient.Interpret(new MbResponse("hash_not_found", null)));
        Detection? hit = MalwareBazaarClient.Interpret(new MbResponse("ok", [new MbSample("ab", "AgentTesla", ["exe", "stealer"])]));
        Assert.NotNull(hit);
        Assert.Equal("AgentTesla", hit.Name);
        Assert.Equal(Severity.Malicious, hit.Severity);
        Assert.Throws<HttpRequestException>(() => MalwareBazaarClient.Interpret(new MbResponse("unknown_auth_key", null)));
    }

    [Theory]
    [InlineData(0, 0, null)]
    [InlineData(2, 0, Severity.Suspicious)]
    [InlineData(0, 3, Severity.Suspicious)]
    [InlineData(40, 1, Severity.Malicious)]
    public void Interprets_virustotal(int malicious, int suspicious, Severity? expected)
    {
        var body = new VtResponse(new VtData(new VtAttributes(new VtStats(malicious, suspicious, 60, 5), new VtClassification("trojan.agent"))));
        Assert.Equal(expected, VirusTotalClient.Interpret(body)?.Severity);
    }

    [Fact]
    public async Task Parses_real_virustotal_json()
    {
        const string json = """
            {"data":{"attributes":{"last_analysis_stats":{"malicious":12,"suspicious":0,"undetected":50,"harmless":0,"timeout":0},
            "popular_threat_classification":{"suggested_threat_label":"trojan.redline/stealer"}}}}
            """;
        using var http = new HttpClient(new StubHandler(HttpStatusCode.OK, json));
        Detection? hit = await new VirusTotalClient(http, () => "key").LookupAsync(new string('a', 64), default);
        Assert.Equal("trojan.redline/stealer", hit?.Name);
        Assert.Equal("12 of 62 engines flagged this file as malicious", hit?.Detail);

        using var notFound = new HttpClient(new StubHandler(HttpStatusCode.NotFound, "{}"));
        Assert.Null(await new VirusTotalClient(notFound, () => "key").LookupAsync(new string('a', 64), default));
    }

    private sealed class StubHandler(HttpStatusCode status, string body) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Assert.Equal("key", request.Headers.GetValues("x-apikey").Single());
            return Task.FromResult(new HttpResponseMessage(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") });
        }
    }

    private sealed class CountingLookup(Detection? answer) : IHashLookup
    {
        public int Calls { get; private set; }

        public string Name => "Counting";

        public bool IsConfigured => true;

        public Task<Detection?> LookupAsync(string sha256, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(answer);
        }
    }

    [Fact]
    public async Task Engine_caches_rate_limits_and_skips_harmless_types()
    {
        var lookup = new CountingLookup(new Detection("Counting", "Bad", Severity.Malicious));
        var engine = new HashReputationEngine([(lookup, 2)]);
        ScanTarget Exe(string hash) => new("p", "p.exe", hash, 10, FileKind.PortableExecutable, null, 0);
        ScanTarget text = new("t", "t.txt", "tt", 10, FileKind.Other, null, 0);

        IReadOnlyList<EngineResult> results = await engine.ScanAsync([Exe("h1"), Exe("h1"), text, Exe("h2"), Exe("h3")], default);

        Assert.Equal("Bad", results[0].Detections[0].Name);
        Assert.Equal("Bad", results[1].Detections[0].Name); // served from cache
        Assert.Empty(results[2].Detections); // text files aren't looked up
        Assert.Single(results[3].Detections);
        Assert.Contains("rate limit", results[4].Error, StringComparison.Ordinal);
        Assert.Equal(2, lookup.Calls);
    }

    [Fact]
    public async Task Parses_urlhaus_hostfile_and_flags_downloads()
    {
        var hosts = UrlhausHostList.Parse("# URLhaus\n127.0.0.1\tbad.example.com\n127.0.0.1\t198.51.100.4\n\n127.0.0.1 localhost\n");
        Assert.Equal(2, hosts.Count);

        var list = new StaticBlocklist(hosts);
        var engine = new DownloadSourceEngine(list);
        var origin = new FileOrigin(3, "https://www.bad.example.com/payload.exe", null);
        var target = new ScanTarget("x", "x.exe", "00", 1, FileKind.PortableExecutable, origin, 0);
        IReadOnlyList<EngineResult> results = await engine.ScanAsync([target], default);
        Assert.Equal(Severity.Malicious, Assert.Single(results[0].Detections).Severity);
    }

    private sealed class StaticBlocklist(HashSet<string> hosts) : IHostBlocklist
    {
        public int Count => hosts.Count;

        public bool IsBlocked(string host) => hosts.Contains(host) || (host.StartsWith("www.", StringComparison.Ordinal) && hosts.Contains(host[4..]));
    }
}

public class CodeSignatureTests
{
    private static ScanTarget Exe(bool fromInternet) =>
        new("p", "setup.exe", "00", 1, FileKind.PortableExecutable, fromInternet ? new FileOrigin(3, null, null) : null, 0);

    [Fact]
    public void Unsigned_programs_are_suspicious_only_when_downloaded()
    {
        Assert.Equal(Severity.Suspicious, CodeSignatureEngine.Interpret(new SignatureInfo(SignatureState.Unsigned), Exe(true))!.Severity);
        Assert.Equal(Severity.Info, CodeSignatureEngine.Interpret(new SignatureInfo(SignatureState.Unsigned), Exe(false))!.Severity);
        Assert.Null(CodeSignatureEngine.Interpret(new SignatureInfo(SignatureState.Trusted, "Contoso"), Exe(true)));
    }

    [Fact]
    public void Broken_and_self_signed_signatures_are_flagged()
    {
        Assert.Equal(Severity.Suspicious, CodeSignatureEngine.Interpret(new SignatureInfo(SignatureState.UntrustedRoot, "Me"), Exe(false))!.Severity);
        Assert.Equal(Severity.Suspicious, CodeSignatureEngine.Interpret(new SignatureInfo(SignatureState.Invalid, "Contoso"), Exe(false))!.Severity);
        Assert.Equal(Severity.Malicious, CodeSignatureEngine.Interpret(new SignatureInfo(SignatureState.Distrusted), Exe(false))!.Severity);
    }
}

public class ArchiveTests
{
    private static string Zip(TempDir dir, string name, params (string Entry, byte[] Content)[] entries)
    {
        string path = Path.Combine(dir.Path, name);
        using var zip = ZipFile.Open(path, ZipArchiveMode.Create);
        foreach ((string entry, byte[] content) in entries)
        {
            using Stream s = zip.CreateEntry(entry, CompressionLevel.Optimal).Open();
            s.Write(content);
        }

        return path;
    }

    private static ScanTarget TargetFor(string path) =>
        new(path, path, "00", new FileInfo(path).Length, FileClassifier.Classify(path), null, 0);

    [Fact]
    public void Extracts_under_random_names_so_traversal_is_impossible()
    {
        using var dir = new TempDir();
        string zip = Zip(dir, "a.zip", ("../../evil.exe", "MZ"u8.ToArray()), ("docs/readme.txt", "hi"u8.ToArray()));
        string work = Path.Combine(dir.Path, "work");
        ExpansionResult result = ArchiveExpander.CreateDefault().Expand(TargetFor(zip), work, new ExpansionBudget(new ExpansionLimits()), default);

        Assert.Equal(2, result.Members.Count);
        Assert.All(result.Members, m => Assert.Equal(Path.GetFullPath(work), Path.GetDirectoryName(Path.GetFullPath(m.TempPath))));
        Assert.EndsWith(".exe", result.Members[0].TempPath, StringComparison.Ordinal);
        Assert.Contains("a.zip › ../../evil.exe", result.Members[0].DisplayPath, StringComparison.Ordinal);
        Assert.False(File.Exists(Path.Combine(dir.Path, "..", "evil.exe")));
    }

    [Fact]
    public void Detects_decompression_bombs()
    {
        using var dir = new TempDir();
        string zip = Zip(dir, "bomb.zip", ("zeros.bin", new byte[64 << 20]));
        Assert.True(new FileInfo(zip).Length < 1 << 20);
        ExpansionResult result = ArchiveExpander.CreateDefault().Expand(TargetFor(zip), Path.Combine(dir.Path, "w"), new ExpansionBudget(new ExpansionLimits()), default);
        Assert.Contains(result.Findings, f => f.Name == "Possible archive bomb");
        Assert.Empty(result.Members);
    }

    [Fact]
    public void Flags_disguised_names_inside_archives()
    {
        using var dir = new TempDir();
        string zip = Zip(dir, "mail.zip", ("Invoice_2026.pdf.exe", "MZ"u8.ToArray()));
        ExpansionResult result = ArchiveExpander.CreateDefault().Expand(TargetFor(zip), Path.Combine(dir.Path, "w"), new ExpansionBudget(new ExpansionLimits()), default);
        Assert.Contains(result.Findings, f => f.Name.StartsWith("Program disguised", StringComparison.Ordinal));
    }

    [Fact]
    public void Respects_nesting_depth()
    {
        using var dir = new TempDir();
        string zip = Zip(dir, "deep.zip", ("x.txt", "x"u8.ToArray()));
        ScanTarget deep = TargetFor(zip) with { Depth = 3 };
        ExpansionResult result = ArchiveExpander.CreateDefault().Expand(deep, Path.Combine(dir.Path, "w"), new ExpansionBudget(new ExpansionLimits()), default);
        Assert.Empty(result.Members);
        Assert.Contains(result.Findings, f => f.Name.StartsWith("Deeply nested", StringComparison.Ordinal));
    }
}

public class ScanCoordinatorTests
{
    private static ScanCoordinator Create(TempDir dir, params IScanEngine[] engines) =>
        new(engines, ArchiveExpander.CreateDefault(), _ => null, Path.Combine(dir.Path, ".work"));

    [Fact]
    public async Task Finds_threats_in_folders_and_inside_archives()
    {
        using var dir = new TempDir();
        string root = Path.Combine(dir.Path, "scan");
        dir.File("scan/clean.txt", "hello");
        string bad = dir.File("scan/sub/bad.txt", "xx EVIL-MARKER xx");
        string zip = Path.Combine(root, "pack.zip");
        using (var archive = ZipFile.Open(zip, ZipArchiveMode.Create))
        {
            using var s = archive.CreateEntry("inner/payload.txt").Open();
            s.Write("EVIL-MARKER"u8);
        }

        var engine = new MarkerEngine();
        ScanReport report = await Create(dir, engine).ScanAsync([root], new ScanOptions(), null, default);

        Assert.Equal(4, report.FilesScanned); // three files on disk plus the archive member
        Assert.Equal(2, report.ThreatCount);
        Assert.Contains(report.Findings, f => f.OnDiskPath == bad && f.IsThreat);
        FileScanResult packed = Assert.Single(report.Findings, f => f.OnDiskPath == zip);
        Assert.Contains("inner/payload.txt", packed.Detections[0].Detail, StringComparison.Ordinal);
        Assert.Contains(report.Findings, f => f.IsArchiveMember && f.DisplayPath.EndsWith("inner/payload.txt", StringComparison.Ordinal));
        Assert.Empty(Directory.EnumerateFileSystemEntries(Path.Combine(dir.Path, ".work")));
    }

    [Fact]
    public async Task Honors_exclusions_and_trusted_hashes()
    {
        using var dir = new TempDir();
        string excluded = Path.Combine(dir.Path, "skip");
        dir.File("skip/bad.txt", "EVIL-MARKER");
        string trusted = dir.File("trusted.txt", "EVIL-MARKER trusted");
        string hash = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(trusted)));
        var engine = new MarkerEngine();
        var options = new ScanOptions { ExcludedPaths = [excluded], AllowedHashes = new HashSet<string> { hash } };

        ScanReport report = await Create(dir, engine).ScanAsync([dir.Path], options, null, default);

        Assert.Equal(0, report.ThreatCount);
        Assert.DoesNotContain(engine.Seen, p => p.StartsWith(excluded, StringComparison.Ordinal));
        Assert.DoesNotContain(trusted, engine.Seen);
    }

    private sealed class BrokenEngine : IScanEngine
    {
        public string Name => "Broken";

        public Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken) => Task.FromResult(new EngineStatus(true, "ok"));

        public Task<IReadOnlyList<EngineResult>> ScanAsync(IReadOnlyList<ScanTarget> batch, CancellationToken cancellationToken) =>
            throw new IOException("connection reset");
    }

    private sealed class MissingEngine : IScanEngine
    {
        public string Name => "Missing";

        public Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken) => Task.FromResult(new EngineStatus(false, "not installed"));

        public Task<IReadOnlyList<EngineResult>> ScanAsync(IReadOnlyList<ScanTarget> batch, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("must not be called");
    }

    [Fact]
    public async Task Keeps_scanning_when_an_engine_fails()
    {
        using var dir = new TempDir();
        dir.File("bad.txt", "EVIL-MARKER");
        ScanReport report = await Create(dir, new BrokenEngine(), new MissingEngine(), new MarkerEngine())
            .ScanAsync([dir.Path], new ScanOptions(), null, default);
        Assert.Equal(1, report.ThreatCount);
        Assert.Contains(report.Warnings, w => w.Contains("Broken stopped responding", StringComparison.Ordinal));
        Assert.Contains(report.Warnings, w => w.Contains("Missing skipped", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Cancellation_returns_a_partial_report()
    {
        using var dir = new TempDir();
        dir.File("a.txt", "a");
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        ScanReport report = await Create(dir, new MarkerEngine()).ScanAsync([dir.Path], new ScanOptions(), null, cts.Token);
        Assert.True(report.Cancelled);
    }

    [Fact]
    public async Task Single_file_scan_reports_members()
    {
        using var dir = new TempDir();
        string zip = Path.Combine(dir.Path, "dl.zip");
        using (var archive = ZipFile.Open(zip, ZipArchiveMode.Create))
        {
            using var s = archive.CreateEntry("x.txt").Open();
            s.Write("EVIL-MARKER"u8);
        }

        var (result, members, _) = await Create(dir, new MarkerEngine()).ScanFileAsync(zip, new ScanOptions(), default);
        Assert.True(result.IsThreat);
        Assert.Single(members);
    }
}
