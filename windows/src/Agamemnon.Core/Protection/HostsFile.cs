namespace Agamemnon.Core.Protection;

public sealed record HostsEntry(string Address, string Host);

/// <summary>
/// Checks the Windows hosts file (System32\drivers\etc\hosts). Malware edits it to block
/// antivirus and Windows updates (pointing their sites at 127.0.0.1 or 0.0.0.0) or to send
/// people to fake banking and login pages. Ad-blocking lists that only block ad hosts are fine.
/// </summary>
public static class HostsFile
{
    /// <summary>Security, update and sign-in sites that should never be redirected.</summary>
    private static readonly string[] Protected =
    [
        "microsoft.com", "windowsupdate.com", "update.microsoft.com", "windows.com", "live.com", "office.com", "microsoftonline.com",
        "google.com", "gstatic.com", "apple.com", "github.com", "githubusercontent.com", "abuse.ch", "virustotal.com",
        "virusshare.com", "clamav.net", "malwarebytes.com", "kaspersky.com", "eset.com", "avast.com", "avg.com",
        "bitdefender.com", "norton.com", "mcafee.com", "sophos.com", "trendmicro.com", "paypal.com", "facebook.com",
        "cloudflare-dns.com", "quad9.net",
    ];

    public static IReadOnlyList<HostsEntry> Parse(string text)
    {
        var entries = new List<HostsEntry>();
        foreach (string rawLine in text.Split('\n'))
        {
            string line = rawLine;
            int hash = line.IndexOf('#', StringComparison.Ordinal);
            if (hash >= 0)
            {
                line = line[..hash];
            }

            string[] parts = line.Split([' ', '\t', '\r'], StringSplitOptions.RemoveEmptyEntries);
            for (int i = 1; i < parts.Length; i++)
            {
                entries.Add(new HostsEntry(parts[0], parts[i].TrimEnd('.').ToLowerInvariant()));
            }
        }

        return entries;
    }

    /// <summary>Entries that redirect or block a protected site.</summary>
    public static IReadOnlyList<HostsEntry> Suspicious(IReadOnlyList<HostsEntry> entries) =>
        [.. entries.Where(e => e.Host != "localhost" && Protected.Any(p => e.Host == p || e.Host.EndsWith("." + p, StringComparison.Ordinal)))];
}
