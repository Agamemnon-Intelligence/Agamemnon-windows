using System.Security.Cryptography;
using Agamemnon.Core.Dns;
using Agamemnon.Core.Downloads;
using Agamemnon.Core.Ipc;
using Agamemnon.Core.Quarantine;
using Agamemnon.Core.Scanning;
using Agamemnon.Core.Settings;

namespace Agamemnon.Core.Tests;

internal sealed class XorProtector : IKeyProtector
{
    public byte[] Protect(byte[] secret) => [.. secret.Select(b => (byte)(b ^ 0x5A))];

    public byte[] Unprotect(byte[] protectedSecret) => Protect(protectedSecret);
}

public class QuarantineStoreTests
{
    private static readonly Detection[] Found = [new("ClamAV", "Win.Test", Severity.Malicious)];

    [Fact]
    public void Quarantines_and_restores_byte_for_byte()
    {
        using var dir = new TempDir();
        byte[] content = RandomNumberGenerator.GetBytes((5 << 20) / 2); // spans several 1 MiB chunks
        string original = dir.File("Downloads/setup.exe", content);
        var store = new QuarantineStore(Path.Combine(dir.Path, "q"), new XorProtector());

        QuarantineItem item = store.Add(original, Found, "Download");

        Assert.False(File.Exists(original));
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(content)), item.Sha256);
        byte[] stored = File.ReadAllBytes(Path.Combine(dir.Path, "q", item.Id + ".agq"));
        Assert.Equal(-1, stored.AsSpan().IndexOf(content.AsSpan(0, 64))); // not stored in the clear
        Assert.Equal("Win.Test", Assert.Single(store.List()).Summary);

        // A fresh store instance (new process) can still decrypt with the protected key.
        var reopened = new QuarantineStore(Path.Combine(dir.Path, "q"), new XorProtector());
        string restored = reopened.Restore(item.Id);

        Assert.Equal(original, restored);
        Assert.Equal(content, File.ReadAllBytes(restored));
        Assert.Empty(reopened.List());
    }

    [Fact]
    public void Restores_next_to_a_file_that_took_its_place()
    {
        using var dir = new TempDir();
        string original = dir.File("a.txt", "one");
        var store = new QuarantineStore(Path.Combine(dir.Path, "q"), new XorProtector());
        QuarantineItem item = store.Add(original, Found);
        File.WriteAllText(original, "new file");

        string restored = store.Restore(item.Id);

        Assert.Equal(Path.Combine(dir.Path, "a (restored).txt"), restored);
        Assert.Equal("new file", File.ReadAllText(original));
    }

    [Fact]
    public void Refuses_to_restore_tampered_data()
    {
        using var dir = new TempDir();
        string original = dir.File("b.bin", RandomNumberGenerator.GetBytes(3000));
        var store = new QuarantineStore(Path.Combine(dir.Path, "q"), new XorProtector());
        QuarantineItem item = store.Add(original, Found);
        string data = Path.Combine(dir.Path, "q", item.Id + ".agq");
        byte[] bytes = File.ReadAllBytes(data);
        bytes[100] ^= 1;
        File.WriteAllBytes(data, bytes);

        Assert.Throws<QuarantineException>(() => store.Restore(item.Id));
        Assert.False(File.Exists(original));
        Assert.Single(store.List()); // still in quarantine
    }

    [Fact]
    public void Empty_files_round_trip_and_ids_are_validated()
    {
        using var dir = new TempDir();
        string original = dir.File("empty.txt", []);
        var store = new QuarantineStore(Path.Combine(dir.Path, "q"), new XorProtector());
        QuarantineItem item = store.Add(original, []);
        Assert.Equal(0, item.Size);
        Assert.Equal(original, store.Restore(item.Id));
        Assert.Throws<QuarantineException>(() => store.Delete("../../etc/passwd"));
    }

    [Fact]
    public void Missing_source_leaves_nothing_behind()
    {
        using var dir = new TempDir();
        var store = new QuarantineStore(Path.Combine(dir.Path, "q"), new XorProtector());
        Assert.Throws<QuarantineException>(() => store.Add(Path.Combine(dir.Path, "nope.exe"), Found));
        Assert.Empty(Directory.EnumerateFiles(Path.Combine(dir.Path, "q"), "*.agq"));
    }
}

public class DownloadWatcherTests
{
    [Theory]
    [InlineData("setup.exe.crdownload", true)]
    [InlineData("movie.mp4.part", true)]
    [InlineData("Unconfirmed 123456.crdownload", true)]
    [InlineData("setup.exe", false)]
    [InlineData("archive.zip", false)]
    public void Recognizes_partial_downloads(string name, bool partial)
    {
        Assert.Equal(partial, DownloadWatcher.IsPartialDownload(name));
    }

    [Fact]
    public async Task Reports_a_finished_download_once()
    {
        using var dir = new TempDir();
        using var watcher = new DownloadWatcher([dir.Path], TimeSpan.FromMilliseconds(300));
        var ready = new List<string>();
        var first = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        watcher.FileReady += (_, path) =>
        {
            lock (ready)
            {
                ready.Add(path);
            }

            first.TrySetResult(path);
        };
        watcher.Start();

        // Browser-style: write a partial file, then rename it to its final name.
        string partial = dir.File("tool.exe.crdownload", "MZ partial");
        await File.AppendAllTextAsync(partial, " more");
        string final = Path.Combine(dir.Path, "tool.exe");
        File.Move(partial, final);
        File.SetLastWriteTimeUtc(final, DateTime.UtcNow); // browsers touch the file again (e.g. writing Mark-of-the-Web)

        Assert.Equal(final, await first.Task.WaitAsync(TimeSpan.FromSeconds(10)));
        await Task.Delay(1500);
        lock (ready)
        {
            Assert.Single(ready, final);
            Assert.DoesNotContain(ready, p => p.EndsWith(".crdownload", StringComparison.Ordinal));
        }
    }
}

public class IpcProtocolTests
{
    [Fact]
    public async Task Messages_round_trip()
    {
        var status = new DnsStatus
        {
            Settings = new DnsSettings { Enabled = true, PresetId = "quad9", Protocol = DnsProtocol.Tls, ExcludedDomains = ["corp.example"] },
            Mode = DnsMode.Forwarder,
            ServerName = "Quad9",
            Queries = 12,
        };
        using var stream = new MemoryStream();
        await IpcProtocol.WriteAsync(stream, status, default);
        await IpcProtocol.WriteAsync(stream, new ServiceEvent { Kind = ServiceEventKind.ElevationGranted, ProgramName = "setup.exe", SessionId = 1 }, default);
        stream.Position = 0;

        DnsStatus? read = await IpcProtocol.ReadAsync<DnsStatus>(stream, default);
        ServiceEvent? evt = await IpcProtocol.ReadAsync<ServiceEvent>(stream, default);

        Assert.NotNull(read);
        Assert.Equal(DnsProtocol.Tls, read.Settings.Protocol);
        Assert.Equal(["corp.example"], read.Settings.ExcludedDomains);
        Assert.Equal(DnsMode.Forwarder, read.Mode);
        Assert.Equal(ServiceEventKind.ElevationGranted, evt!.Kind);
        Assert.Null(await IpcProtocol.ReadAsync<ServiceEvent>(stream, default));
    }

    [Fact]
    public async Task Rejects_oversized_frames()
    {
        using var stream = new MemoryStream([0xFF, 0xFF, 0xFF, 0x7F]);
        await Assert.ThrowsAsync<InvalidDataException>(() => IpcProtocol.ReadAsync<ServiceEvent>(stream, default));
    }
}

public class SettingsStoreTests
{
    [Fact]
    public void Saves_atomically_and_survives_corruption()
    {
        using var dir = new TempDir();
        var store = new JsonFileStore<AppSettings>(Path.Combine(dir.Path, "settings.json"));
        Assert.True(store.Load().DownloadProtection);

        store.Save(new AppSettings { UnsignedDownloads = UnsignedDownloadPolicy.Block, AllowedHashes = ["ab"] });
        AppSettings loaded = store.Load();
        Assert.Equal(UnsignedDownloadPolicy.Block, loaded.UnsignedDownloads);
        Assert.Equal(["ab"], loaded.AllowedHashes);

        File.WriteAllText(store.Path, "{ not json");
        Assert.Equal(UnsignedDownloadPolicy.Warn, store.Load().UnsignedDownloads);
    }
}
