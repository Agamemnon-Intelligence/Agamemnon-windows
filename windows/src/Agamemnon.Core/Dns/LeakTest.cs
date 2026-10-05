using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Agamemnon.Core.Dns;

/// <summary>Resolves TXT records through the operating system's resolver (the path apps actually use).</summary>
public interface ISystemTxtResolver
{
    Task<IReadOnlyList<IReadOnlyList<string>>> QueryTxtAsync(string name, CancellationToken cancellationToken);
}

public enum LeakVerdict
{
    /// <summary>Every resolver that answered belongs to the chosen provider.</summary>
    Pass,

    /// <summary>At least one answering resolver belongs to someone else (usually the ISP).</summary>
    Leak,

    /// <summary>Resolvers were identified but the provider's networks aren't known, so no verdict.</summary>
    Inconclusive,

    /// <summary>The test itself could not run (offline, resolver failing).</summary>
    Failed,
}

public sealed record ResolverObservation(string Address, int? Asn, string? Owner);

public sealed record LeakTestResult(LeakVerdict Verdict, string Summary, IReadOnlyList<ResolverObservation> Resolvers);

/// <summary>
/// DNS leak test. Asks the authoritative servers of Akamai and Google "which resolver is asking
/// me?" through the system resolver, then maps each resolver's address to its network (ASN) via
/// Team Cymru's IP-to-ASN DNS service and compares against the provider's known networks.
/// </summary>
public sealed class LeakTest(ISystemTxtResolver resolver)
{
    private static readonly string[] WhoAmINames = ["whoami.ds.akahelp.net", "o-o.myaddr.l.google.com"];

    public async Task<LeakTestResult> RunAsync(DnsServerConfig? expected, CancellationToken cancellationToken)
    {
        var addresses = new HashSet<IPAddress>();
        var errors = new List<string>();
        for (int round = 0; round < 3; round++)
        {
            foreach (string name in WhoAmINames)
            {
                try
                {
                    var records = await resolver.QueryTxtAsync(name, cancellationToken).ConfigureAwait(false);
                    foreach (IPAddress address in ExtractResolverAddresses(name, records))
                    {
                        addresses.Add(address);
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    errors.Add(ex.Message);
                }
            }
        }

        if (addresses.Count == 0)
        {
            string reason = errors.FirstOrDefault() ?? "no resolver answered";
            return new LeakTestResult(LeakVerdict.Failed, $"The leak test could not run: {reason}.", []);
        }

        var observations = new List<ResolverObservation>();
        foreach (IPAddress address in addresses.OrderBy(a => a.ToString(), StringComparer.Ordinal))
        {
            (int? asn, string? owner) = await LookupAsnAsync(address, cancellationToken).ConfigureAwait(false);
            observations.Add(new ResolverObservation(address.ToString(), asn, owner));
        }

        return Judge(expected, observations);
    }

    internal static LeakTestResult Judge(DnsServerConfig? expected, IReadOnlyList<ResolverObservation> observations)
    {
        if (expected is null)
        {
            return new LeakTestResult(LeakVerdict.Leak,
                "Encrypted DNS is off: lookups go to your network's resolver in plain text.", observations);
        }

        if (expected.KnownAsns.Count == 0)
        {
            return new LeakTestResult(LeakVerdict.Inconclusive,
                $"Answered by {observations.Count} resolver(s). Agamemnon doesn't know {expected.Name}'s networks, so compare the owners below yourself.",
                observations);
        }

        var foreign = observations.Where(o => o.Asn is not int asn || !expected.KnownAsns.Contains(asn)).ToList();
        if (foreign.Count == 0)
        {
            return new LeakTestResult(LeakVerdict.Pass,
                $"No leak: every lookup was answered by {expected.Name}.", observations);
        }

        string who = string.Join(", ", foreign.Select(o => o.Owner ?? o.Address));
        return new LeakTestResult(LeakVerdict.Leak,
            $"Leak: some lookups were answered by {who}, not {expected.Name}.", observations);
    }

    internal static IEnumerable<IPAddress> ExtractResolverAddresses(string name, IReadOnlyList<IReadOnlyList<string>> records)
    {
        foreach (IReadOnlyList<string> record in records)
        {
            if (name.StartsWith("whoami.", StringComparison.Ordinal))
            {
                // Akamai: "ns" "<resolver ip>" (other records carry "ecs"/"ip" which we ignore)
                if (record.Count >= 2 && record[0] == "ns" && IPAddress.TryParse(record[1], out IPAddress? ns))
                {
                    yield return ns;
                }
            }
            else if (record.Count >= 1 && IPAddress.TryParse(record[0], out IPAddress? address))
            {
                // Google: "<resolver ip>" (a second record "edns0-client-subnet ..." is ignored)
                yield return address;
            }
        }
    }

    private async Task<(int? Asn, string? Owner)> LookupAsnAsync(IPAddress address, CancellationToken cancellationToken)
    {
        try
        {
            var origin = await resolver.QueryTxtAsync(CymruOriginName(address), cancellationToken).ConfigureAwait(false);
            int? asn = ParseFirstAsn(origin);
            if (asn is null)
            {
                return (null, null);
            }

            var info = await resolver.QueryTxtAsync($"AS{asn}.asn.cymru.com", cancellationToken).ConfigureAwait(false);
            return (asn, ParseAsnName(info) ?? $"AS{asn}");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return (null, null);
        }
    }

    internal static string CymruOriginName(IPAddress address)
    {
        byte[] bytes = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            return $"{bytes[3]}.{bytes[2]}.{bytes[1]}.{bytes[0]}.origin.asn.cymru.com";
        }

        var nibbles = new StringBuilder();
        for (int i = bytes.Length - 1; i >= 0; i--)
        {
            nibbles.Append(System.Globalization.CultureInfo.InvariantCulture, $"{bytes[i] & 0xF:x}.{bytes[i] >> 4:x}.");
        }

        return nibbles + "origin6.asn.cymru.com";
    }

    // "13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11" (multi-origin prefixes list several ASNs: "13335 1234 | ...")
    internal static int? ParseFirstAsn(IReadOnlyList<IReadOnlyList<string>> records)
    {
        foreach (var record in records)
        {
            string text = string.Concat(record);
            string first = text.Split('|')[0].Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? string.Empty;
            if (int.TryParse(first, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int asn))
            {
                return asn;
            }
        }

        return null;
    }

    // "13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"
    internal static string? ParseAsnName(IReadOnlyList<IReadOnlyList<string>> records)
    {
        foreach (var record in records)
        {
            string[] parts = string.Concat(record).Split('|');
            if (parts.Length >= 5 && parts[4].Trim() is { Length: > 0 } name)
            {
                return name;
            }
        }

        return null;
    }
}
