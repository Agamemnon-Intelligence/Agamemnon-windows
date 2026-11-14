using System.Buffers.Binary;
using System.Text;
using Agamemnon.Core.Heuristics;
using Agamemnon.Core.Localization;
using Agamemnon.Core.Protection;
using Agamemnon.Core.Recovery;
using Agamemnon.Core.Scanning;
using Agamemnon.Core.Web;

namespace Agamemnon.Core.Tests;

/// <summary>Builds small, valid 64-bit PE files with chosen sections and imports.</summary>
internal static class PeBuilder
{
    public sealed record Section(string Name, uint Characteristics, byte[] Data, uint VirtualSize = 0);

    public const uint Code = 0x60000020;      // code, execute, read
    public const uint Data = 0xC0000040;      // initialised data, read, write
    public const uint ReadOnly = 0x40000040;  // initialised data, read
    public const uint Rwx = 0xE0000020;       // code, execute, read, write

    public static byte[] Build(Section[] sections, int imports, bool versionInfo, int entrySection = 0, bool dotNet = false, int overlay = 0)
    {
        const int fileAlign = 0x200;
        const int sectionAlign = 0x1000;
        const int headers = 0x400;
        var list = sections.ToList();

        // Import table and resources live in an extra read-only section.
        int extraIndex = list.Count;
        list.Add(new Section(".idata", ReadOnly, new byte[0x400]));
        uint[] rvas = new uint[list.Count];
        uint[] raws = new uint[list.Count];
        uint nextRva = sectionAlign;
        uint nextRaw = headers;
        for (int i = 0; i < list.Count; i++)
        {
            rvas[i] = nextRva;
            raws[i] = (uint)list[i].Data.Length == 0 ? 0 : nextRaw;
            uint vsize = Math.Max(list[i].VirtualSize, (uint)list[i].Data.Length);
            nextRva += (uint)((vsize + sectionAlign - 1) / sectionAlign * sectionAlign);
            nextRaw += (uint)((list[i].Data.Length + fileAlign - 1) / fileAlign * fileAlign);
        }

        byte[] file = new byte[nextRaw + overlay];
        file[0] = (byte)'M';
        file[1] = (byte)'Z';
        BinaryPrimitives.WriteInt32LittleEndian(file.AsSpan(0x3C), 0x80);
        int pe = 0x80;
        "PE\0\0"u8.CopyTo(file.AsSpan(pe));
        int coff = pe + 4;
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(coff), 0x8664);
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(coff + 2), (ushort)list.Count);
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(coff + 16), 240);
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(coff + 18), 0x0022);
        int opt = coff + 20;
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(opt), 0x20B);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(opt + 16), rvas[entrySection] + 0x10);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(opt + 108), 16);
        int dirs = opt + 112;

        // Import directory: one DLL with `imports` functions, all inside the extra section.
        int x = (int)raws[extraIndex];
        uint xr = rvas[extraIndex];
        if (imports > 0)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(dirs + 8), xr);
            BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(dirs + 12), 40);
            BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(x), xr + 0x40);       // lookup table
            BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(x + 12), xr + 0x200); // DLL name
            BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(x + 16), xr + 0x40);
            for (int i = 0; i < imports; i++)
            {
                BinaryPrimitives.WriteUInt64LittleEndian(file.AsSpan(x + 0x40 + (i * 8)), xr + 0x300);
            }

            "kernel32.dll\0"u8.CopyTo(file.AsSpan(x + 0x200));
        }

        if (versionInfo)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(dirs + 16), xr + 0x380);
            BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(dirs + 20), 0x20);
            BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(x + 0x380 + 14), 1);
            BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(x + 0x380 + 16), 16);
        }

        if (dotNet)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(dirs + (14 * 8)), xr + 0x100);
            BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(dirs + (14 * 8) + 4), 0x48);
        }

        int table = opt + 240;
        for (int i = 0; i < list.Count; i++)
        {
            int s = table + (i * 40);
            Encoding.ASCII.GetBytes(list[i].Name.PadRight(8, '\0')[..8]).CopyTo(file.AsSpan(s));
            BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(s + 8), Math.Max(list[i].VirtualSize, (uint)list[i].Data.Length));
            BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(s + 12), rvas[i]);
            BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(s + 16), (uint)((list[i].Data.Length + fileAlign - 1) / fileAlign * fileAlign));
            BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(s + 20), raws[i]);
            BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(s + 36), list[i].Characteristics);
            if (i != extraIndex)
            {
                list[i].Data.CopyTo(file.AsSpan((int)raws[i]));
            }
        }

        return file;
    }

    /// <summary>Ordinary-looking machine code: a small repeated alphabet, low entropy.</summary>
    public static byte[] PlainCode(int length) => [.. Enumerable.Range(0, length).Select(i => (byte)"\x48\x89\x5C\x24\x08\x57\x48\x83\xEC\x20\xC3\xCC"[i % 12])];

    public static byte[] RandomBytes(int length)
    {
        byte[] bytes = new byte[length];
        new Random(42).NextBytes(bytes);
        return bytes;
    }
}

public class SmartAnalysisTests
{
    private static byte[] Normal() => PeBuilder.Build(
        [new(".text", PeBuilder.Code, PeBuilder.PlainCode(16384)), new(".data", PeBuilder.Data, new byte[2048])],
        imports: 40, versionInfo: true);

    private static byte[] Packed() => PeBuilder.Build(
        [new("UPX0", PeBuilder.Rwx, [], VirtualSize: 0x40000), new("UPX1", PeBuilder.Rwx, PeBuilder.RandomBytes(32768))],
        imports: 2, versionInfo: false, entrySection: 1);

    [Fact]
    public void Reads_the_layout_of_a_program()
    {
        PeFile pe = PeFile.Parse(Normal())!;
        Assert.True(pe.Is64Bit);
        Assert.False(pe.IsDotNet);
        Assert.Equal([".text", ".data", ".idata"], pe.Sections.Select(s => s.Name));
        Assert.Equal(1, pe.ImportedLibraries);
        Assert.Equal(40, pe.ImportedFunctions);
        Assert.True(pe.HasVersionInfo);
        Assert.Equal(".text", pe.EntrySection?.Name);
        Assert.InRange(pe.Sections[0].Entropy, 0, 4);
    }

    [Fact]
    public void Ordinary_programs_score_low()
    {
        HeuristicAssessment assessment = PeHeuristics.Assess(PeFile.Parse(Normal())!);
        Assert.False(assessment.IsSuspicious);
        Assert.True(assessment.Score < 20, $"score {assessment.Score}");
    }

    [Fact]
    public void Packed_programs_are_suspicious_and_explained()
    {
        HeuristicAssessment assessment = PeHeuristics.Assess(PeFile.Parse(Packed())!);
        Assert.True(assessment.IsSuspicious);
        string[] ids = [.. assessment.Reasons.Select(r => r.Id)];
        Assert.Contains("packer", ids);
        Assert.Contains("selfModifying", ids);
        Assert.Contains("encryptedCode", ids);
        Assert.Contains("fewImports", ids);
        Assert.Contains("noVersionInfo", ids);
        Assert.InRange(assessment.Score, HeuristicAssessment.Threshold, 100);
    }

    [Fact]
    public void Dotnet_programs_are_not_scored()
    {
        byte[] file = PeBuilder.Build([new("UPX1", PeBuilder.Rwx, PeBuilder.RandomBytes(8192))], imports: 1, versionInfo: false, dotNet: true);
        Assert.Equal(0, PeHeuristics.Assess(PeFile.Parse(file)!).Score);
    }

    [Theory]
    [InlineData(new byte[0])]
    [InlineData(new byte[] { (byte)'M', (byte)'Z', 0, 0 })]
    public void Damaged_or_tiny_files_are_not_programs(byte[] data) => Assert.Null(PeFile.Parse(data));

    [Fact]
    public void Random_damage_never_crashes_the_parser()
    {
        byte[] good = Packed();
        var random = new Random(7);
        for (int round = 0; round < 500; round++)
        {
            byte[] copy = [.. good];
            for (int i = 0; i < 20; i++)
            {
                copy[random.Next(0, 0x400)] = (byte)random.Next(256);
            }

            _ = PeFile.Parse(copy.AsSpan(0, random.Next(0, copy.Length)));
        }
    }

    [Fact]
    public void Entropy_goes_from_zero_to_eight()
    {
        Assert.Equal(0, PeFile.Entropy(new byte[100]));
        Assert.Equal(8, PeFile.Entropy([.. Enumerable.Range(0, 256 * 4).Select(i => (byte)i)]), 6);
    }

    private sealed class FixedVerifier(SignatureState state) : ISignatureVerifier
    {
        public SignatureInfo Verify(string path, bool onlineRevocationCheck) => new(state, state == SignatureState.Trusted ? "Contoso" : null);
    }

    [Theory]
    [InlineData(SignatureState.Unsigned, true)]
    [InlineData(SignatureState.Trusted, false)]
    public async Task Engine_reports_unsigned_packed_programs_only(SignatureState state, bool reported)
    {
        string path = Path.Combine(Path.GetTempPath(), $"agm-smart-{Guid.NewGuid():N}.exe");
        await File.WriteAllBytesAsync(path, Packed());
        try
        {
            var engine = new HeuristicEngine(new FixedVerifier(state), () => true);
            var target = new ScanTarget(path, path, "x", 1, FileKind.PortableExecutable, null, 0);
            IReadOnlyList<EngineResult> results = await engine.ScanAsync([target], CancellationToken.None);
            Assert.Equal(reported, results[0].Detections.Count == 1);
            if (reported)
            {
                Assert.Equal(Severity.Suspicious, results[0].Detections[0].Severity);
            }
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task Engine_can_be_switched_off() =>
        Assert.False((await new HeuristicEngine(new FixedVerifier(SignatureState.Unsigned), () => false).GetStatusAsync(CancellationToken.None)).Available);
}

public class LinkInspectorTests
{
    private sealed class Hosts(params string[] hosts) : IHostBlocklist
    {
        public int Count => hosts.Length;

        public bool IsBlocked(string host) => hosts.Contains(host, StringComparer.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("https://www.paypal.com/signin")]
    [InlineData("https://accounts.google.com/")]
    [InlineData("https://www.garantibbva.com.tr/")]
    [InlineData("https://www.turkiye.gov.tr/")]
    [InlineData("https://github.com/Agamemnon-Intelligence")]
    [InlineData("https://www.wikipedia.org/")]
    [InlineData("https://www.applebees.com/")]
    [InlineData("https://www.turkiye-haber.com/")]
    [InlineData("https://stream.example.com/")]
    [InlineData("example.org")]
    public void Real_sites_are_safe(string link) => Assert.Equal(LinkRisk.Safe, LinkInspector.Inspect(link).Risk);

    [Theory]
    [InlineData("https://paypa1.com/login", "lookalike", "PayPal")]
    [InlineData("https://micros0ft.com/", "lookalike", "Microsoft")]
    [InlineData("https://rnicrosoft.com/", "lookalike", "Microsoft")]
    [InlineData("https://amazom.com/", "lookalike", "Amazon")]
    [InlineData("https://garanti-giris.com/", "brandInName", "Garanti BBVA")]
    [InlineData("https://paypal-secure.net/", "brandInName", "PayPal")]
    [InlineData("https://dhl-kargo.info/", "brandInName", "DHL")]
    [InlineData("https://ptt-kargo-takip.com/", "brandInName", "PTT")]
    [InlineData("https://www.edevlet-basvuru.com/", "brandInName", "e-Devlet")]
    [InlineData("https://paypal.com.account-check.top/", "brandInSubdomain", "PayPal")]
    public void Fake_copies_of_well_known_sites_are_dangerous(string link, string reason, string brand)
    {
        LinkVerdict verdict = LinkInspector.Inspect(link);
        Assert.Equal(LinkRisk.Dangerous, verdict.Risk);
        LinkReason found = Assert.Single(verdict.Reasons, r => r.Id == reason);
        Assert.Equal(brand, found.Value);
    }

    [Fact]
    public void Cyrillic_letters_in_a_brand_are_caught()
    {
        LinkVerdict verdict = LinkInspector.Inspect("https://аpple.com/"); // first letter is Cyrillic
        Assert.Equal(LinkRisk.Dangerous, verdict.Risk);
        Assert.Contains(verdict.Reasons, r => r.Id is "mixedScripts" or "lookalike");
    }

    [Fact]
    public void A_disguised_beginning_is_dangerous() =>
        Assert.Contains(LinkInspector.Inspect("https://www.paypal.com@evil.example/").Reasons, r => r.Id == "userInfo" && r.Value == "evil.example");

    [Fact]
    public void Known_malware_hosts_are_dangerous() =>
        Assert.Equal("knownMalware", LinkInspector.Inspect("http://bad.example/x.exe", new Hosts("bad.example")).Reasons[0].Id);

    [Theory]
    [InlineData("https://bit.ly/3abc", "shortener")]
    [InlineData("http://192.168.1.20/login", "ipAddress")]
    [InlineData("https://cheap-offers.top/", "riskyEnding")]
    [InlineData("http://shop.example.com/account/login", "insecureLogin")]
    [InlineData("https://github.mycompany.com/", "brandInSubdomain")]
    public void Unusual_links_ask_for_care(string link, string reason)
    {
        LinkVerdict verdict = LinkInspector.Inspect(link);
        Assert.Equal(LinkRisk.Caution, verdict.Risk);
        Assert.Contains(verdict.Reasons, r => r.Id == reason);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not a link")]
    [InlineData("ftp://example.com/")]
    public void Things_that_are_not_links_say_so(string text) => Assert.Equal("invalid", LinkInspector.Inspect(text).Reasons.Single().Id);

    [Fact]
    public void Registrable_domains_handle_two_part_endings()
    {
        Assert.Equal(("garantibbva.com.tr", "garantibbva", "tr"), LinkInspector.Split("www.garantibbva.com.tr".Split('.')));
        Assert.Equal(("example.com", "example", "com"), LinkInspector.Split("a.b.example.com".Split('.')));
    }

    [Fact]
    public void Finds_links_in_copied_text() =>
        Assert.Equal(["https://a.example/x", "www.b.example"], LinkInspector.FindLinks("Kargonuz bekliyor: https://a.example/x. Ya da www.b.example, teşekkürler"));

    [Fact]
    public void Skeleton_sees_through_lookalike_letters()
    {
        Assert.Equal("paypal", LinkInspector.Skeleton("paypa1"));
        Assert.Equal("microsoft", LinkInspector.Skeleton("rnicr0soft"));
        Assert.Equal("garanti", LinkInspector.Skeleton("garantı"));
        Assert.Equal(1, LinkInspector.Distance("amazon", "amazom"));
        Assert.Equal(1, LinkInspector.Distance("google", "goolge"));
    }

    [Fact]
    public async Task Downloads_from_fake_sites_are_suspicious()
    {
        var engine = new DownloadSourceEngine(new Hosts(), () => true);
        var target = new ScanTarget("x", "x", "x", 1, FileKind.PortableExecutable, new FileOrigin(3, "https://paypa1-secure.com/app.exe", null), 0);
        Detection detection = Assert.Single((await engine.ScanAsync([target], CancellationToken.None))[0].Detections);
        Assert.Equal(Severity.Suspicious, detection.Severity);
    }

    [Fact]
    public void Every_reason_has_its_texts()
    {
        foreach (string id in LinkInspector.ReasonIds)
        {
            Assert.True(Translations.All.ContainsKey($"web.reason.{id}"), $"web.reason.{id} is missing");
        }

        foreach (LinkRisk risk in Enum.GetValues<LinkRisk>())
        {
            Assert.True(Translations.All.ContainsKey($"web.result.{risk.ToString().ToLowerInvariant()}"));
        }
    }
}

public class RecoveryPlannerTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 14, 12, 0, 0, TimeSpan.Zero);

    private static RestorePoint Point(int daysAgo, bool ours = true, string volume = "C:\\") =>
        new($"{{{daysAgo}}}", Now.AddDays(-daysAgo), volume, $@"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy{daysAgo}", ours);

    [Theory]
    [InlineData(@"C:\Users\ayse\Documents\rapor.docx", @"C:\Users\ayse\Documents\rapor.docx")]
    [InlineData(@"c:/Users/ayse//a.txt", @"C:\Users\ayse\a.txt")]
    [InlineData(@"C:\Users\..\Windows\System32\config\SAM", null)]
    [InlineData(@"\\server\share\a.txt", null)]
    [InlineData(@"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\a.txt", null)]
    [InlineData(@"C:\a.txt:secret", null)]
    [InlineData(@"C:\folder\*.docx", null)]
    [InlineData(@"relative\a.txt", null)]
    [InlineData("", null)]
    public void Only_plain_local_paths_are_accepted(string path, string? expected) => Assert.Equal(expected, RecoveryPlanner.Normalize(path));

    [Fact]
    public void Maps_a_file_into_a_restore_point()
    {
        Assert.Equal(@"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Users\ayse\a.txt", RecoveryPlanner.PathInPoint(Point(1), @"C:\Users\ayse\a.txt"));
        Assert.Null(RecoveryPlanner.PathInPoint(Point(1, volume: "D:\\"), @"C:\Users\ayse\a.txt"));
    }

    [Fact]
    public void A_daily_point_is_due_after_a_day()
    {
        Assert.True(RecoveryPlanner.IsDailyPointDue([], Now));
        Assert.False(RecoveryPlanner.IsDailyPointDue([Point(0)], Now));
        Assert.True(RecoveryPlanner.IsDailyPointDue([Point(2)], Now));
    }

    [Fact]
    public void Only_Agamemnons_oldest_points_are_removed()
    {
        RestorePoint[] points = [.. Enumerable.Range(0, 10).Select(d => Point(d)), Point(30, ours: false)];
        IReadOnlyList<RestorePoint> remove = RecoveryPlanner.ToRemove(points);
        Assert.Equal([7, 8, 9], remove.Select(p => (int)(Now - p.CreatedAt).TotalDays));
        Assert.DoesNotContain(remove, p => !p.ByAgamemnon);
    }

    [Fact]
    public void Picks_the_newest_copy_from_before_the_attack()
    {
        FileVersion[] versions =
        [
            new("a", Now.AddDays(-3), 1, Now), new("b", Now.AddHours(-20), 1, Now), new("c", Now.AddMinutes(-1), 1, Now),
        ];
        Assert.Equal("b", RecoveryPlanner.BestBefore(versions, Now)?.PointId);
        Assert.Null(RecoveryPlanner.BestBefore(versions, Now.AddDays(-5)));
    }

    [Fact]
    public void Restored_files_never_overwrite_anything()
    {
        var existing = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { @"C:\D\Rapor (restored 2026-11-13).docx" };
        string path = RecoveryPlanner.RestoredPath(@"C:\D\Rapor.docx", Now.AddDays(-1), "restored", existing.Contains);
        Assert.Equal(@"C:\D\Rapor (restored 2026-11-13 2).docx", path);
        Assert.Equal(@"C:\D\notes (restored 2026-11-14)", RecoveryPlanner.RestoredPath(@"C:\D\notes", Now, "restored", _ => false));
    }

    [Fact]
    public void Renamed_files_point_back_to_their_original_name()
    {
        Assert.Equal(@"C:\D\photo.jpg", RansomwareIncident.OriginalName(@"C:\D\photo.jpg.locked", ".locked"));
        Assert.Equal(@"C:\D\photo.jpg", RansomwareIncident.OriginalName(@"C:\D\photo.jpg", null));
    }
}

public class ProtectionScoreTests
{
    private static readonly ProtectionInputs Everything = new()
    {
        ScanEngine = true, ThreatDatabaseComplete = true, DownloadProtection = true, OnAccessScanning = true, RansomwareShield = true,
        PasteGuard = true, SmartAnalysis = true, WebProtection = true, EncryptedDns = true, RecentRestorePoint = true, ScannedRecently = true,
    };

    [Fact]
    public void Everything_on_is_a_hundred()
    {
        ProtectionScoreResult result = ProtectionScore.Compute(Everything);
        Assert.Equal(100, result.Score);
        Assert.Equal("strong", result.Grade);
        Assert.Null(result.NextStep);
    }

    [Fact]
    public void Suggests_the_most_valuable_layer_first()
    {
        ProtectionScoreResult result = ProtectionScore.Compute(Everything with { ScanEngine = false, PasteGuard = false });
        Assert.Equal(79, result.Score);
        Assert.Equal("engine", result.NextStep?.Id);
    }

    [Fact]
    public void Weak_windows_settings_and_threats_lower_the_score()
    {
        Assert.Equal(85, ProtectionScore.Compute(Everything with { CheckupProblems = 3 }).Score);
        Assert.Equal(80, ProtectionScore.Compute(Everything with { CheckupProblems = 9 }).Score);
        Assert.Equal(40, ProtectionScore.Compute(Everything with { UnresolvedThreats = 1 }).Score);
        Assert.Equal(0, ProtectionScore.Compute(new ProtectionInputs()).Score);
    }

    [Fact]
    public void Every_layer_has_a_name_in_both_languages()
    {
        foreach (ProtectionLayer layer in ProtectionScore.Compute(Everything).Layers)
        {
            Assert.True(Translations.All.ContainsKey($"score.layer.{layer.Id}"), $"score.layer.{layer.Id} is missing");
        }

        Assert.Equal(100, ProtectionScore.Compute(Everything).Layers.Sum(l => l.Weight));
        foreach (string grade in new[] { "strong", "fair", "weak" })
        {
            Assert.True(Translations.All.ContainsKey($"score.grade.{grade}"));
        }
    }
}
