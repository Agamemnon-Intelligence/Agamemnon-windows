namespace Agamemnon.Core.Dns;

public enum DnsProtocol
{
    /// <summary>DNS-over-HTTPS (RFC 8484).</summary>
    Https,

    /// <summary>DNS-over-TLS (RFC 7858).</summary>
    Tls,
}

public enum DnsCategory
{
    General,
    SecurityFiltering,
    Custom,
}

/// <summary>
/// A known encrypted DNS provider. <see cref="Addresses"/> are the provider's anycast IPs; they are
/// used as bootstrap addresses (so the DoH/DoT hostname never has to be resolved through the
/// system resolver we are replacing) and, in native Windows mode, as the interface DNS servers
/// that Windows auto-upgrades to DoH.
/// </summary>
public sealed record DnsPreset(
    string Id,
    string Name,
    DnsCategory Category,
    string Description,
    IReadOnlyList<string> Addresses,
    string DohTemplate,
    string DotHost,
    IReadOnlyList<int> KnownAsns,
    bool RequiresProfileId = false)
{
    public const string ProfilePlaceholder = "{profile}";

    public DnsServerConfig Resolve(DnsProtocol protocol, string? profileId = null)
    {
        string template = DohTemplate;
        string host = DotHost;
        if (RequiresProfileId)
        {
            if (!DnsValidation.IsValidProfileId(profileId))
            {
                throw new DnsConfigurationException($"{Name} needs a configuration ID (letters and digits only).");
            }

            template = template.Replace(ProfilePlaceholder, profileId, StringComparison.Ordinal);
            host = host.Replace(ProfilePlaceholder, profileId, StringComparison.Ordinal);
        }

        return new DnsServerConfig(Name, protocol, Addresses, template, host, KnownAsns);
    }
}

/// <summary>A fully resolved upstream: everything needed to send encrypted queries.</summary>
public sealed record DnsServerConfig(
    string Name,
    DnsProtocol Protocol,
    IReadOnlyList<string> Addresses,
    string DohTemplate,
    string DotHost,
    IReadOnlyList<int> KnownAsns)
{
    public void Validate()
    {
        if (Addresses.Count == 0)
        {
            throw new DnsConfigurationException("At least one server IP address is required.");
        }

        foreach (string address in Addresses)
        {
            if (!System.Net.IPAddress.TryParse(address, out _))
            {
                throw new DnsConfigurationException($"'{address}' is not an IP address.");
            }
        }

        if (Protocol == DnsProtocol.Https && !DnsValidation.IsValidDohTemplate(DohTemplate))
        {
            throw new DnsConfigurationException("The DNS-over-HTTPS URL must be an absolute https:// URL.");
        }

        if (Protocol == DnsProtocol.Tls && !DnsValidation.IsValidHostName(DotHost))
        {
            throw new DnsConfigurationException("The DNS-over-TLS server name is not a valid host name.");
        }
    }
}

public sealed class DnsConfigurationException(string message) : Exception(message);

public static class DnsPresets
{
    // ASNs are only listed where the provider's recursive resolvers egress from its own network,
    // so the leak test can assert "every resolver we saw belongs to the chosen provider".
    public static readonly IReadOnlyList<DnsPreset> All =
    [
        new("cloudflare", "Cloudflare", DnsCategory.General,
            "Fast, privacy-focused resolver. No filtering.",
            ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"],
            "https://cloudflare-dns.com/dns-query", "one.one.one.one", [13335]),

        new("quad9-unfiltered", "Quad9", DnsCategory.General,
            "Non-profit resolver, unfiltered service.",
            ["9.9.9.10", "149.112.112.10", "2620:fe::10", "2620:fe::fe:10"],
            "https://dns10.quad9.net/dns-query", "dns10.quad9.net", [19281]),

        new("mullvad", "Mullvad", DnsCategory.General,
            "No-logging resolver run by Mullvad VPN. No filtering.",
            ["194.242.2.2", "2a07:e340::2"],
            "https://dns.mullvad.net/dns-query", "dns.mullvad.net", []),

        new("google", "Google", DnsCategory.General,
            "Google Public DNS. No filtering.",
            ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"],
            "https://dns.google/dns-query", "dns.google", [15169]),

        new("controld", "Control D", DnsCategory.General,
            "Control D free unfiltered resolver.",
            ["76.76.2.0", "76.76.10.0", "2606:1a40::", "2606:1a40:1::"],
            "https://freedns.controld.com/p0", "p0.freedns.controld.com", []),

        new("nextdns", "NextDNS", DnsCategory.General,
            "Your own NextDNS configuration. Enter the configuration ID from my.nextdns.io.",
            ["45.90.28.0", "45.90.30.0", "2a07:a8c0::", "2a07:a8c1::"],
            "https://dns.nextdns.io/" + DnsPreset.ProfilePlaceholder,
            DnsPreset.ProfilePlaceholder + ".dns.nextdns.io", [], RequiresProfileId: true),

        new("cloudflare-security", "Cloudflare 1.1.1.2", DnsCategory.SecurityFiltering,
            "Cloudflare for Families: blocks malware and phishing domains.",
            ["1.1.1.2", "1.0.0.2", "2606:4700:4700::1112", "2606:4700:4700::1002"],
            "https://security.cloudflare-dns.com/dns-query", "security.cloudflare-dns.com", [13335]),

        new("quad9", "Quad9", DnsCategory.SecurityFiltering,
            "Quad9 threat-blocking service: blocks malware and phishing domains.",
            ["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"],
            "https://dns.quad9.net/dns-query", "dns.quad9.net", [19281]),

        new("adguard", "AdGuard", DnsCategory.SecurityFiltering,
            "AdGuard DNS: blocks malware, phishing, ads and trackers.",
            ["94.140.14.14", "94.140.15.15", "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"],
            "https://dns.adguard-dns.com/dns-query", "dns.adguard-dns.com", []),
    ];

    public const string CustomId = "custom";

    public static DnsPreset? Find(string id) =>
        All.FirstOrDefault(p => string.Equals(p.Id, id, StringComparison.OrdinalIgnoreCase));

    public static DnsPreset Default => All[0];
}
