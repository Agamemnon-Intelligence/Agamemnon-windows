using System.Globalization;
using System.Text.RegularExpressions;

namespace Agamemnon.Core.Dns;

/// <summary>The user's encrypted-DNS choices. Persisted by the service and sent over IPC.</summary>
public sealed record DnsSettings
{
    public bool Enabled { get; init; }

    public string PresetId { get; init; } = DnsPresets.Default.Id;

    public DnsProtocol Protocol { get; init; } = DnsProtocol.Https;

    /// <summary>Configuration ID for presets that need one (NextDNS).</summary>
    public string? ProfileId { get; init; }

    /// <summary>Used when <see cref="PresetId"/> is <see cref="DnsPresets.CustomId"/>.</summary>
    public CustomDnsServer? Custom { get; init; }

    /// <summary>Wi-Fi network names (SSIDs) on which encrypted DNS is switched off.</summary>
    public IReadOnlyList<string> DisabledOnNetworks { get; init; } = [];

    /// <summary>Domains (and their subdomains) resolved by the network's own DNS servers.</summary>
    public IReadOnlyList<string> ExcludedDomains { get; init; } = [];

    public bool IsCustom => string.Equals(PresetId, DnsPresets.CustomId, StringComparison.OrdinalIgnoreCase);

    public DnsServerConfig ResolveServer()
    {
        DnsServerConfig server;
        if (IsCustom)
        {
            if (Custom is null)
            {
                throw new DnsConfigurationException("Enter the custom server's details.");
            }

            server = new DnsServerConfig(
                string.IsNullOrWhiteSpace(Custom.Name) ? "Custom server" : Custom.Name.Trim(),
                Protocol,
                Custom.Addresses,
                Custom.DohTemplate ?? string.Empty,
                Custom.DotHost ?? string.Empty,
                []);
        }
        else
        {
            DnsPreset preset = DnsPresets.Find(PresetId)
                ?? throw new DnsConfigurationException($"Unknown DNS preset '{PresetId}'.");
            server = preset.Resolve(Protocol, ProfileId);
        }

        server.Validate();
        return server;
    }

    /// <summary>Returns a copy with normalized, de-duplicated rule lists; throws on invalid input.</summary>
    public DnsSettings Normalize()
    {
        var domains = new SortedSet<string>(StringComparer.Ordinal);
        foreach (string raw in ExcludedDomains)
        {
            domains.Add(DnsValidation.NormalizeDomain(raw)
                ?? throw new DnsConfigurationException($"'{raw}' is not a valid domain name."));
        }

        var networks = new SortedSet<string>(StringComparer.Ordinal);
        foreach (string raw in DisabledOnNetworks)
        {
            string ssid = raw.Trim();
            if (ssid.Length is 0 or > 32)
            {
                throw new DnsConfigurationException("Wi-Fi network names must be 1–32 characters.");
            }

            networks.Add(ssid);
        }

        return this with { ExcludedDomains = [.. domains], DisabledOnNetworks = [.. networks] };
    }
}

public sealed record CustomDnsServer
{
    public string? Name { get; init; }

    public IReadOnlyList<string> Addresses { get; init; } = [];

    public string? DohTemplate { get; init; }

    public string? DotHost { get; init; }
}

public static partial class DnsValidation
{
    private static readonly IdnMapping Idn = new() { UseStd3AsciiRules = true };

    public static bool IsValidProfileId(string? id) =>
        !string.IsNullOrEmpty(id) && id.Length <= 32 && ProfileIdRegex().IsMatch(id);

    public static bool IsValidDohTemplate(string? template) =>
        Uri.TryCreate(template, UriKind.Absolute, out Uri? uri)
        && uri.Scheme == Uri.UriSchemeHttps
        && string.IsNullOrEmpty(uri.UserInfo)
        && uri.Query.Length == 0
        && IsValidHostName(uri.Host);

    public static bool IsValidHostName(string? host) => NormalizeDomain(host) is { } d && d.Contains('.', StringComparison.Ordinal);

    /// <summary>
    /// Lower-cases, strips a leading "*." or "." and a trailing ".", converts IDN to punycode.
    /// Returns null when the result is not a syntactically valid DNS name.
    /// </summary>
    public static string? NormalizeDomain(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        string name = raw.Trim();
        if (name.StartsWith("*.", StringComparison.Ordinal))
        {
            name = name[2..];
        }

        name = name.TrimStart('.').TrimEnd('.');
        if (name.Length == 0)
        {
            return null;
        }

        try
        {
            name = Idn.GetAscii(name).ToLowerInvariant();
        }
        catch (ArgumentException)
        {
            return null;
        }

        if (name.Length > 253)
        {
            return null;
        }

        foreach (string label in name.Split('.'))
        {
            if (!LabelRegex().IsMatch(label))
            {
                return null;
            }
        }

        return name;
    }

    /// <summary>True when <paramref name="name"/> equals or is a subdomain of any excluded domain.</summary>
    public static bool IsExcluded(string name, IReadOnlyCollection<string> excludedDomains)
    {
        string n = name.TrimEnd('.').ToLowerInvariant();
        foreach (string domain in excludedDomains)
        {
            if (n.Length == domain.Length)
            {
                if (n == domain)
                {
                    return true;
                }
            }
            else if (n.Length > domain.Length
                     && n.EndsWith(domain, StringComparison.Ordinal)
                     && n[n.Length - domain.Length - 1] == '.')
            {
                return true;
            }
        }

        return false;
    }

    [GeneratedRegex("^[A-Za-z0-9]+$")]
    private static partial Regex ProfileIdRegex();

    [GeneratedRegex("^(?!-)[a-z0-9-]{1,63}(?<!-)$")]
    private static partial Regex LabelRegex();
}

/// <summary>Decides what the DNS layer should be doing right now.</summary>
public static class DnsRules
{
    public static DnsActivation Evaluate(DnsSettings settings, string? currentWifiNetwork)
    {
        if (!settings.Enabled)
        {
            return new DnsActivation(false, "Encrypted DNS is off.");
        }

        if (currentWifiNetwork is not null
            && settings.DisabledOnNetworks.Contains(currentWifiNetwork, StringComparer.Ordinal))
        {
            return new DnsActivation(false, $"Paused on Wi-Fi network “{currentWifiNetwork}”.");
        }

        return new DnsActivation(true, "Encrypted DNS is on.");
    }
}

public sealed record DnsActivation(bool Active, string Reason);
