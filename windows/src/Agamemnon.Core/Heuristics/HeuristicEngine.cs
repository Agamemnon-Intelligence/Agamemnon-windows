using Agamemnon.Core.Scanning;

namespace Agamemnon.Core.Heuristics;

/// <summary>One reason the smart analysis gave a program points, for the explanation shown to people.</summary>
public sealed record HeuristicReason(string Id, int Points, string Text);

public sealed record HeuristicAssessment(int Score, IReadOnlyList<HeuristicReason> Reasons)
{
    /// <summary>Points from which a program is reported as suspicious.</summary>
    public const int Threshold = 60;

    public bool IsSuspicious => Score >= Threshold;
}

/// <summary>
/// 5.0's smart analysis: looks at how an unsigned Windows program is built and reports the
/// ones built like malware usually is (packed or encrypted code, code that rewrites itself,
/// almost no imports, no version information). This catches new programs no signature or hash
/// list knows yet. It is a hand-tuned, explainable score, not a trained model, and on its own it
/// only ever says "suspicious": known-malware verdicts stay with the other engines. Programs
/// signed by a trusted publisher and .NET programs (whose layout is different) aren't scored.
/// </summary>
public static class PeHeuristics
{
    private static readonly string[] PackerSections =
    [
        "UPX0", "UPX1", "UPX2", ".aspack", ".adata", ".MPRESS1", ".MPRESS2", ".petite", ".nsp0", ".nsp1",
        ".themida", ".vmp0", ".vmp1", ".enigma1", ".enigma2", ".packed", ".perplex", "pebundle", ".yP", "kkrunchy",
    ];

    public static HeuristicAssessment Assess(PeFile pe)
    {
        var reasons = new List<HeuristicReason>();
        if (pe.IsDotNet)
        {
            return new HeuristicAssessment(0, reasons);
        }

        string? packer = pe.Sections.Select(s => s.Name).FirstOrDefault(n => PackerSections.Contains(n, StringComparer.OrdinalIgnoreCase));
        if (packer is not null)
        {
            reasons.Add(new("packer", 35, $"Packed with a tool that hides the code (section {packer})"));
        }

        if (pe.Sections.Any(s => s.IsExecutable && s.IsWritable))
        {
            reasons.Add(new("selfModifying", 20, "Code that can rewrite itself while running"));
        }

        if (pe.Sections.Any(s => s.IsExecutable && s.RawSize >= 4096 && s.Entropy >= 7.2))
        {
            reasons.Add(new("encryptedCode", 25, "Its code looks compressed or encrypted"));
        }

        if (pe.Sections.Any(s => s.IsExecutable && s.RawSize == 0 && s.VirtualSize >= 64 * 1024))
        {
            reasons.Add(new("emptyCode", 15, "Its code only appears once it runs"));
        }

        PeSection? entry = pe.EntrySection;
        if (entry is null || !entry.IsExecutable)
        {
            reasons.Add(new("entryOutsideCode", 20, "It starts outside its own code"));
        }
        else if (pe.Sections.Count > 1 && ReferenceEquals(entry, pe.Sections[^1]) && entry.IsWritable)
        {
            reasons.Add(new("entryLastSection", 15, "It starts in an unusual place"));
        }

        if (pe.ImportedFunctions == 0)
        {
            reasons.Add(new("noImports", 25, "It hides which Windows functions it uses"));
        }
        else if (pe.ImportedFunctions <= 4)
        {
            reasons.Add(new("fewImports", 20, "It only names a handful of Windows functions"));
        }

        if (pe.Sections.Any(s => s.Name.Length == 0 || s.Name.Any(c => c < 0x20 || c > 0x7E)))
        {
            reasons.Add(new("oddSectionNames", 15, "Garbled section names"));
        }

        if (!pe.IsDll && !pe.HasVersionInfo)
        {
            reasons.Add(new("noVersionInfo", 10, "No product name or version"));
        }

        if (!pe.HasCertificate && pe.OverlaySize > 1 << 20 && pe.OverlaySize > pe.FileSize / 2)
        {
            reasons.Add(new("overlay", 5, "Most of the file is extra data after the program"));
        }

        return new HeuristicAssessment(Math.Min(100, reasons.Sum(r => r.Points)), reasons);
    }
}

/// <summary>The smart analysis as a scan engine.</summary>
public sealed class HeuristicEngine(ISignatureVerifier verifier, Func<bool> enabled) : IScanEngine
{
    /// <summary>Larger programs are read only up to here; layout and code sections come first.</summary>
    public const int MaxBytes = 64 << 20;

    public const string EngineName = "Smart analysis";

    public string Name => EngineName;

    public Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken) =>
        Task.FromResult(enabled()
            ? new EngineStatus(true, "Checks how unknown programs are built")
            : new EngineStatus(false, "Turned off in Settings."));

    public Task<IReadOnlyList<EngineResult>> ScanAsync(IReadOnlyList<ScanTarget> batch, CancellationToken cancellationToken)
    {
        var results = new List<EngineResult>(batch.Count);
        foreach (ScanTarget target in batch)
        {
            cancellationToken.ThrowIfCancellationRequested();
            results.Add(target.Kind == FileKind.PortableExecutable ? Scan(target) : EngineResult.Clean);
        }

        return Task.FromResult<IReadOnlyList<EngineResult>>(results);
    }

    private EngineResult Scan(ScanTarget target)
    {
        try
        {
            byte[] data = ReadHead(target.Path);
            if (PeFile.Parse(data) is not { } pe)
            {
                return EngineResult.Clean;
            }

            HeuristicAssessment assessment = PeHeuristics.Assess(pe);
            if (!assessment.IsSuspicious || verifier.Verify(target.Path, onlineRevocationCheck: false).State == SignatureState.Trusted)
            {
                return EngineResult.Clean;
            }

            string detail = $"Score {assessment.Score}/100: " + string.Join("; ", assessment.Reasons.OrderByDescending(r => r.Points).Select(r => r.Text));
            return new EngineResult([new Detection(EngineName, "Built like malware (unknown program)", Severity.Suspicious, detail)]);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return EngineResult.Failed(ex.Message);
        }
    }

    private static byte[] ReadHead(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        int length = (int)Math.Min(stream.Length, MaxBytes);
        byte[] data = new byte[length];
        stream.ReadExactly(data);
        return data;
    }
}
