using System.Globalization;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Agamemnon.Core.Updates;

/// <summary>A newer Agamemnon for Windows release, with the setup program to download.</summary>
public sealed record AvailableUpdate(Version Version, string Tag, Uri Page, Uri Setup, long Size, string? Sha256);

/// <summary>
/// Agamemnon's own updates. Once a day the app asks GitHub for the newest release of
/// Agamemnon-Intelligence/Agamemnon-windows (drafts, pre-releases and nightly builds are
/// ignored). The setup .exe is only downloaded from that repository's release downloads, its
/// SHA-256 must match the one GitHub publishes for the asset, and the app then checks its code
/// signature before starting it.
/// </summary>
public sealed class AgamemnonUpdateChecker(HttpClient http)
{
    public const string Repository = "Agamemnon-Intelligence/Agamemnon-windows";
    private static readonly Uri Latest = new($"https://api.github.com/repos/{Repository}/releases/latest");
    private static readonly string DownloadPrefix = $"https://github.com/{Repository}/releases/download/";

    public async Task<AvailableUpdate?> CheckAsync(Version current, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, Latest);
        request.Headers.Accept.ParseAdd("application/vnd.github+json");
        using HttpResponseMessage response = await http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            return null;
        }

        GitHubRelease? release = await response.Content.ReadFromJsonAsync<GitHubRelease>(cancellationToken).ConfigureAwait(false);
        return release is null ? null : Pick(release, current);
    }

    /// <summary>The update in a release, or null when it isn't newer or has no usable setup program.</summary>
    internal static AvailableUpdate? Pick(GitHubRelease release, Version current)
    {
        if (release.Draft || release.Prerelease || ParseVersion(release.TagName) is not { } version || version <= Normalize(current))
        {
            return null;
        }

        GitHubAsset? setup = release.Assets.FirstOrDefault(a => a.Name.EndsWith("-Setup.exe", StringComparison.OrdinalIgnoreCase)
                                                                 && a.BrowserDownloadUrl.StartsWith(DownloadPrefix, StringComparison.OrdinalIgnoreCase));
        if (setup is null || !Uri.TryCreate(setup.BrowserDownloadUrl, UriKind.Absolute, out Uri? download)
            || !Uri.TryCreate(release.HtmlUrl, UriKind.Absolute, out Uri? page))
        {
            return null;
        }

        string? sha256 = setup.Digest is { } digest && digest.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase)
            ? digest["sha256:".Length..].ToLowerInvariant()
            : null;
        return new AvailableUpdate(version, release.TagName, page, download, setup.Size, sha256);
    }

    /// <summary>"v4.0.1" or "4.0" → 4.0.1 / 4.0.0; "nightly" → null.</summary>
    public static Version? ParseVersion(string? tag)
    {
        if (string.IsNullOrWhiteSpace(tag))
        {
            return null;
        }

        string text = tag.Trim().TrimStart('v', 'V');
        int dash = text.IndexOfAny(['-', '+']);
        if (dash >= 0)
        {
            return null; // "4.1.0-beta" is a pre-release
        }

        return Version.TryParse(text.Contains('.', StringComparison.Ordinal) ? text : text + ".0", out Version? version) ? Normalize(version) : null;
    }

    private static Version Normalize(Version v) => new(v.Major, v.Minor, Math.Max(0, v.Build));

    /// <summary>Downloads the setup program to <paramref name="destination"/> and checks its size and SHA-256.</summary>
    public async Task DownloadAsync(AvailableUpdate update, string destination, CancellationToken cancellationToken)
    {
        if (!update.Setup.AbsoluteUri.StartsWith(DownloadPrefix, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("The update isn't hosted on Agamemnon's release page.");
        }

        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        string temp = destination + ".part";
        using (HttpResponseMessage response = await http.GetAsync(update.Setup, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false))
        {
            response.EnsureSuccessStatusCode();
            await using Stream body = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            await using var file = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None);
            await body.CopyToAsync(file, cancellationToken).ConfigureAwait(false);
        }

        string actual;
        await using (FileStream check = File.OpenRead(temp))
        {
            if (update.Size > 0 && check.Length != update.Size)
            {
                throw new InvalidDataException("The downloaded update is incomplete.");
            }

            actual = Convert.ToHexStringLower(await SHA256.HashDataAsync(check, cancellationToken).ConfigureAwait(false));
        }

        if (update.Sha256 is { } expected && !string.Equals(expected, actual, StringComparison.OrdinalIgnoreCase))
        {
            File.Delete(temp);
            throw new InvalidDataException("The downloaded update doesn't match the published fingerprint.");
        }

        File.Move(temp, destination, overwrite: true);
    }
}

internal sealed record GitHubRelease(
    [property: JsonPropertyName("tag_name")] string TagName,
    [property: JsonPropertyName("html_url")] string HtmlUrl,
    [property: JsonPropertyName("draft")] bool Draft,
    [property: JsonPropertyName("prerelease")] bool Prerelease,
    [property: JsonPropertyName("assets")] IReadOnlyList<GitHubAsset> Assets)
{
    public static GitHubRelease? Parse(string json) => JsonSerializer.Deserialize<GitHubRelease>(json);
}

internal sealed record GitHubAsset(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("browser_download_url")] string BrowserDownloadUrl,
    [property: JsonPropertyName("size")] long Size,
    [property: JsonPropertyName("digest")] string? Digest);

/// <summary>An installed program with a newer version available, from <c>winget upgrade</c>.</summary>
public sealed record SoftwareUpdate(string Name, string Id, string Installed, string Available);

/// <summary>
/// Reads the table <c>winget upgrade</c> prints. Column titles are translated by winget, so
/// columns are found by position: the title line sits right above the line of dashes, and
/// every column starts where a title word starts.
/// </summary>
public static class WingetOutput
{
    public static IReadOnlyList<SoftwareUpdate> ParseUpgrades(string output)
    {
        string[] lines = [.. output.Replace("\r", string.Empty, StringComparison.Ordinal).Split('\n').Select(StripProgress)];
        int dashes = Array.FindIndex(lines, l => l.Length > 10 && l.Trim().Length > 10 && l.Trim().All(c => c == '-'));
        if (dashes < 1)
        {
            return [];
        }

        string header = lines[dashes - 1];
        var starts = new List<int>();
        for (int i = 0; i < header.Length; i++)
        {
            if (header[i] != ' ' && (i == 0 || header[i - 1] == ' '))
            {
                starts.Add(i);
            }
        }

        if (starts.Count < 4)
        {
            return [];
        }

        var updates = new List<SoftwareUpdate>();
        for (int row = dashes + 1; row < lines.Length; row++)
        {
            string line = lines[row];
            if (line.Trim().Length == 0)
            {
                break; // the summary ("3 upgrades available.") follows a blank line
            }

            string Column(int index)
            {
                int start = starts[index];
                if (start >= line.Length)
                {
                    return string.Empty;
                }

                int end = index + 1 < starts.Count ? Math.Min(starts[index + 1], line.Length) : line.Length;
                return line[start..end].Trim();
            }

            string name = Column(0);
            string id = Column(1);
            string installed = Column(2);
            string available = Column(3);
            if (name.Length > 0 && id.Length > 0 && available.Length > 0 && !id.Contains(' ', StringComparison.Ordinal))
            {
                updates.Add(new SoftwareUpdate(name.TrimEnd('…'), id.TrimEnd('…'), installed, available));
            }
        }

        return updates;
    }

    /// <summary>winget draws spinners and progress bars with carriage returns; keep what's after the last one.</summary>
    private static string StripProgress(string line)
    {
        int bs = line.LastIndexOf('\b');
        return bs >= 0 ? line[(bs + 1)..] : line;
    }

    public static string Format(SoftwareUpdate update) =>
        string.Format(CultureInfo.InvariantCulture, "{0} {1} → {2}", update.Name, update.Installed, update.Available);
}
