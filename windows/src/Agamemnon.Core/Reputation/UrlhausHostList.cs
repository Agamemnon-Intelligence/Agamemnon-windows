using Agamemnon.Core.Scanning;

namespace Agamemnon.Core.Reputation;

/// <summary>
/// abuse.ch URLhaus host list (hosts currently serving malware), refreshed at most every 12 hours
/// and cached on disk so it works offline.
/// </summary>
public sealed class UrlhausHostList(HttpClient http, string cacheFile, TimeProvider? time = null) : IHostBlocklist
{
    private static readonly Uri Source = new("https://urlhaus.abuse.ch/downloads/hostfile/");
    private readonly TimeProvider _time = time ?? TimeProvider.System;
    private volatile HashSet<string> _hosts = new(StringComparer.OrdinalIgnoreCase);

    public int Count => _hosts.Count;

    public bool IsBlocked(string host)
    {
        HashSet<string> hosts = _hosts;
        string h = host.TrimEnd('.');
        return hosts.Contains(h) || (h.StartsWith("www.", StringComparison.OrdinalIgnoreCase) && hosts.Contains(h[4..]));
    }

    public async Task RefreshAsync(CancellationToken cancellationToken)
    {
        if (_hosts.Count == 0 && File.Exists(cacheFile))
        {
            _hosts = Parse(await File.ReadAllTextAsync(cacheFile, cancellationToken).ConfigureAwait(false));
        }

        if (File.Exists(cacheFile) && _time.GetUtcNow() - File.GetLastWriteTimeUtc(cacheFile) < TimeSpan.FromHours(12))
        {
            return;
        }

        string text = await http.GetStringAsync(Source, cancellationToken).ConfigureAwait(false);
        HashSet<string> parsed = Parse(text);
        if (parsed.Count == 0)
        {
            return; // never replace a good list with an empty one
        }

        _hosts = parsed;
        Directory.CreateDirectory(Path.GetDirectoryName(cacheFile)!);
        string temp = cacheFile + ".tmp";
        await File.WriteAllTextAsync(temp, text, cancellationToken).ConfigureAwait(false);
        File.Move(temp, cacheFile, overwrite: true);
    }

    /// <summary>Hosts-file format: "127.0.0.1\tbad.example.com", with # comments.</summary>
    internal static HashSet<string> Parse(string text)
    {
        var hosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string rawLine in text.Split('\n'))
        {
            string line = rawLine.Trim();
            if (line.Length == 0 || line[0] == '#')
            {
                continue;
            }

            string[] parts = line.Split((char[])['\t', ' '], StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 2 && parts[1] is not ("localhost" or "0.0.0.0" or "127.0.0.1"))
            {
                hosts.Add(parts[1].TrimEnd('.'));
            }
        }

        return hosts;
    }
}
