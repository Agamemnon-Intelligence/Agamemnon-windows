namespace Agamemnon.Core.Protection;

/// <summary>One layer of protection and how much it counts towards the score.</summary>
public sealed record ProtectionLayer(string Id, bool On, int Weight);

/// <summary>Everything the protection score looks at, read from settings and live state.</summary>
public sealed record ProtectionInputs
{
    public bool ScanEngine { get; init; }

    public bool ThreatDatabaseComplete { get; init; }

    public bool DownloadProtection { get; init; }

    public bool OnAccessScanning { get; init; }

    public bool RansomwareShield { get; init; }

    public bool PasteGuard { get; init; }

    public bool SmartAnalysis { get; init; }

    public bool WebProtection { get; init; }

    public bool EncryptedDns { get; init; }

    public bool RecentRestorePoint { get; init; }

    public bool ScannedRecently { get; init; }

    public int CheckupProblems { get; init; }

    public int UnresolvedThreats { get; init; }
}

public sealed record ProtectionScoreResult(int Score, IReadOnlyList<ProtectionLayer> Layers)
{
    /// <summary>Plain-words grade: 85+ strong, 60+ fair, below that weak.</summary>
    public string Grade => Score >= 85 ? "strong" : Score >= 60 ? "fair" : "weak";

    /// <summary>The most valuable layer that is off, to suggest first.</summary>
    public ProtectionLayer? NextStep => Layers.Where(l => !l.On).MaxBy(l => l.Weight);
}

/// <summary>
/// 5.0's protection score: one number from 0 to 100 for how well this PC is protected, built
/// from the layers that are on. Weak Windows settings take points off, and a threat that is
/// still on the PC caps the score at 40 whatever else is on.
/// </summary>
public static class ProtectionScore
{
    public static ProtectionScoreResult Compute(ProtectionInputs i)
    {
        ProtectionLayer[] layers =
        [
            new("engine", i.ScanEngine, 15),
            new("database", i.ThreatDatabaseComplete, 5),
            new("downloads", i.DownloadProtection, 10),
            new("onAccess", i.OnAccessScanning, 12),
            new("ransomware", i.RansomwareShield, 12),
            new("paste", i.PasteGuard, 6),
            new("smart", i.SmartAnalysis, 10),
            new("web", i.WebProtection, 8),
            new("dns", i.EncryptedDns, 6),
            new("recovery", i.RecentRestorePoint, 10),
            new("scan", i.ScannedRecently, 6),
        ];
        int score = layers.Where(l => l.On).Sum(l => l.Weight);
        score -= Math.Min(20, 5 * Math.Max(0, i.CheckupProblems));
        if (i.UnresolvedThreats > 0)
        {
            score = Math.Min(score, 40);
        }

        return new ProtectionScoreResult(Math.Clamp(score, 0, 100), layers);
    }
}
