using System.Net;
using System.Net.Sockets;
using Agamemnon.Core.Dns;

namespace Agamemnon.Core.Tests;

public class DnsPresetTests
{
    [Fact]
    public void Preset_ids_are_unique()
    {
        Assert.Equal(DnsPresets.All.Count, DnsPresets.All.Select(p => p.Id).Distinct().Count());
    }

    [Theory]
    [InlineData(DnsProtocol.Https)]
    [InlineData(DnsProtocol.Tls)]
    public void Every_preset_resolves_to_a_valid_server(DnsProtocol protocol)
    {
        foreach (DnsPreset preset in DnsPresets.All)
        {
            DnsServerConfig server = preset.Resolve(protocol, preset.RequiresProfileId ? "abc123" : null);
            server.Validate();
            Assert.DoesNotContain(DnsPreset.ProfilePlaceholder, server.DohTemplate, StringComparison.Ordinal);
            Assert.DoesNotContain(DnsPreset.ProfilePlaceholder, server.DotHost, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Security_filtering_presets_match_the_spec()
    {
        string[] filtering = [.. DnsPresets.All.Where(p => p.Category == DnsCategory.SecurityFiltering).Select(p => p.Name)];
        Assert.Equal(["Cloudflare 1.1.1.2", "Quad9", "AdGuard"], filtering);
        Assert.Contains("1.1.1.2", DnsPresets.Find("cloudflare-security")!.Addresses);
    }

    [Fact]
    public void NextDns_profile_is_substituted_and_required()
    {
        DnsPreset nextDns = DnsPresets.Find("nextdns")!;
        DnsServerConfig server = nextDns.Resolve(DnsProtocol.Tls, "a1b2c3");
        Assert.Equal("https://dns.nextdns.io/a1b2c3", server.DohTemplate);
        Assert.Equal("a1b2c3.dns.nextdns.io", server.DotHost);
        Assert.Throws<DnsConfigurationException>(() => nextDns.Resolve(DnsProtocol.Https, null));
        Assert.Throws<DnsConfigurationException>(() => nextDns.Resolve(DnsProtocol.Https, "../evil"));
    }

    [Fact]
    public void Custom_server_is_validated()
    {
        var good = new DnsSettings
        {
            PresetId = DnsPresets.CustomId,
            Custom = new CustomDnsServer { Addresses = ["192.0.2.53"], DohTemplate = "https://dns.example.net/dns-query" },
        };
        Assert.Equal("https://dns.example.net/dns-query", good.ResolveServer().DohTemplate);

        var plainHttp = good with { Custom = good.Custom! with { DohTemplate = "http://dns.example.net/dns-query" } };
        Assert.Throws<DnsConfigurationException>(() => plainHttp.ResolveServer());

        var badIp = good with { Custom = good.Custom! with { Addresses = ["dns.example.net"] } };
        Assert.Throws<DnsConfigurationException>(() => badIp.ResolveServer());

        var tlsWithoutHost = good with { Protocol = DnsProtocol.Tls };
        Assert.Throws<DnsConfigurationException>(() => tlsWithoutHost.ResolveServer());
    }
}

public class DnsValidationTests
{
    [Theory]
    [InlineData("Example.COM", "example.com")]
    [InlineData("*.corp.example.com", "corp.example.com")]
    [InlineData(".intranet.local.", "intranet.local")]
    [InlineData("bücher.example", "xn--bcher-kva.example")]
    [InlineData("router", "router")]
    public void Normalizes_domains(string input, string expected)
    {
        Assert.Equal(expected, DnsValidation.NormalizeDomain(input));
    }

    [Theory]
    [InlineData("")]
    [InlineData("exa mple.com")]
    [InlineData("-bad.example.com")]
    [InlineData("a..b")]
    [InlineData("http://example.com")]
    public void Rejects_invalid_domains(string input)
    {
        Assert.Null(DnsValidation.NormalizeDomain(input));
    }

    [Fact]
    public void Exclusion_matches_domain_and_subdomains_only()
    {
        string[] excluded = ["corp.example.com"];
        Assert.True(DnsValidation.IsExcluded("corp.example.com", excluded));
        Assert.True(DnsValidation.IsExcluded("Mail.Corp.Example.com.", excluded));
        Assert.False(DnsValidation.IsExcluded("evilcorp.example.com", excluded));
        Assert.False(DnsValidation.IsExcluded("example.com", excluded));
    }

    [Fact]
    public void Normalize_dedupes_and_rejects_bad_rules()
    {
        var settings = new DnsSettings
        {
            ExcludedDomains = ["Example.com", "example.com.", "*.lan.example"],
            DisabledOnNetworks = ["Cafe Wi-Fi", "Cafe Wi-Fi", " Home "],
        };
        DnsSettings normalized = settings.Normalize();
        Assert.Equal(["example.com", "lan.example"], normalized.ExcludedDomains);
        Assert.Equal(["Cafe Wi-Fi", "Home"], normalized.DisabledOnNetworks);

        Assert.Throws<DnsConfigurationException>(() => (settings with { ExcludedDomains = ["not a domain"] }).Normalize());
        Assert.Throws<DnsConfigurationException>(() => (settings with { DisabledOnNetworks = [new string('x', 33)] }).Normalize());
    }

    [Fact]
    public void Wifi_rule_pauses_dns()
    {
        var settings = new DnsSettings { Enabled = true, DisabledOnNetworks = ["Hotel"] };
        Assert.True(DnsRules.Evaluate(settings, "Home").Active);
        Assert.True(DnsRules.Evaluate(settings, null).Active);
        Assert.False(DnsRules.Evaluate(settings, "Hotel").Active);
        Assert.False(DnsRules.Evaluate(settings with { Enabled = false }, "Home").Active);
    }
}

public class DnsMessageTests
{
    [Fact]
    public void Query_round_trips()
    {
        byte[] query = DnsMessage.BuildQuery("www.example.com", DnsMessage.TypeAaaa, 0xBEEF);
        Assert.Equal(0xBEEF, DnsMessage.ReadId(query));
        Assert.True(DnsMessage.TryReadQuestion(query, out string name, out ushort type, out int end));
        Assert.Equal("www.example.com", name);
        Assert.Equal(DnsMessage.TypeAaaa, type);
        Assert.Equal(query.Length, end);
    }

    [Fact]
    public void ServerFailure_answers_the_question()
    {
        byte[] query = DnsMessage.BuildQuery("example.com", DnsMessage.TypeA, 7);
        byte[] response = DnsMessage.ServerFailure(query);
        Assert.Equal(7, DnsMessage.ReadId(response));
        Assert.Equal(0x80, response[2] & 0x80); // QR
        Assert.Equal(0x01, response[2] & 0x01); // RD preserved
        Assert.Equal(2, DnsMessage.ResponseCode(response));
        Assert.True(DnsMessage.TryReadQuestion(response, out string name, out _, out _));
        Assert.Equal("example.com", name);
    }

    [Fact]
    public void Rejects_malformed_messages()
    {
        Assert.False(DnsMessage.TryReadQuestion(new byte[5], out _, out _, out _));
        byte[] query = DnsMessage.BuildQuery("example.com", DnsMessage.TypeA, 1);
        Assert.False(DnsMessage.TryReadQuestion(query.AsSpan(0, 15), out _, out _, out _));
    }

    [Fact]
    public void Reads_txt_answers_with_name_compression()
    {
        byte[] response = TxtResponse("whoami.ds.akahelp.net", ["ns", "203.0.113.9"], ["ecs", "x"]);
        var records = DnsMessage.ReadTxtAnswers(response);
        Assert.Equal(2, records.Count);
        Assert.Equal(["ns", "203.0.113.9"], records[0]);
    }

    internal static byte[] TxtResponse(string name, params string[][] records)
    {
        byte[] query = DnsMessage.BuildQuery(name, DnsMessage.TypeTxt, 42);
        using var stream = new MemoryStream();
        stream.Write(query);
        foreach (string[] strings in records)
        {
            stream.Write([0xC0, 0x0C]); // pointer to the question name
            stream.Write([0x00, 0x10, 0x00, 0x01, 0, 0, 0, 60]);
            byte[] rdata = [.. strings.SelectMany(s => new[] { (byte)s.Length }.Concat(System.Text.Encoding.ASCII.GetBytes(s)))];
            stream.Write([(byte)(rdata.Length >> 8), (byte)rdata.Length]);
            stream.Write(rdata);
        }

        byte[] response = stream.ToArray();
        response[2] |= 0x80;
        response[7] = (byte)records.Length;
        return response;
    }
}

public class DnsForwarderTests
{
    private sealed class FakeUpstream(string label, Func<byte[], byte[]>? answer = null) : IDnsUpstream
    {
        public List<string> Names { get; } = [];

        public string Description => label;

        public Task<byte[]> QueryAsync(ReadOnlyMemory<byte> query, CancellationToken cancellationToken)
        {
            DnsMessage.TryReadQuestion(query.Span, out string name, out _, out _);
            lock (Names)
            {
                Names.Add(name);
            }

            if (answer is null)
            {
                throw new IOException($"{label} is down");
            }

            return Task.FromResult(answer(query.ToArray()));
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private static byte[] Echo(byte[] query)
    {
        byte[] response = (byte[])query.Clone();
        response[2] |= 0x80;
        return response;
    }

    private static DnsForwarder Create(IDnsUpstream encrypted, IDnsUpstream? excludedUpstream, params string[] excluded)
    {
        var forwarder = new DnsForwarder(encrypted, excluded, excludedUpstream, [new IPEndPoint(IPAddress.Loopback, 0)]);
        forwarder.Start();
        return forwarder;
    }

    [Fact]
    public async Task Forwards_udp_queries_over_the_encrypted_upstream()
    {
        var encrypted = new FakeUpstream("encrypted", Echo);
        await using DnsForwarder forwarder = Create(encrypted, null);
        using var client = new UdpClient();
        byte[] query = DnsMessage.BuildQuery("example.org", DnsMessage.TypeA, 99);
        await client.SendAsync(query, forwarder.BoundUdpEndpoints[0]);
        UdpReceiveResult result = await client.ReceiveAsync().WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(99, DnsMessage.ReadId(result.Buffer));
        Assert.Equal(["example.org"], encrypted.Names);
        Assert.Equal(1, forwarder.Stats.Queries);
    }

    [Fact]
    public async Task Excluded_domains_use_the_network_resolver()
    {
        var encrypted = new FakeUpstream("encrypted", Echo);
        var network = new FakeUpstream("network", Echo);
        await using DnsForwarder forwarder = Create(encrypted, network, "corp.example");
        await forwarder.ResolveAsync(DnsMessage.BuildQuery("intranet.corp.example", DnsMessage.TypeA, 1), default);
        await forwarder.ResolveAsync(DnsMessage.BuildQuery("example.com", DnsMessage.TypeA, 2), default);
        Assert.Equal(["intranet.corp.example"], network.Names);
        Assert.Equal(["example.com"], encrypted.Names);
    }

    [Fact]
    public async Task Fails_closed_when_the_encrypted_upstream_is_down()
    {
        var down = new FakeUpstream("encrypted");
        var network = new FakeUpstream("network", Echo);
        await using DnsForwarder forwarder = Create(down, network, "corp.example");
        byte[] answer = await forwarder.ResolveAsync(DnsMessage.BuildQuery("example.com", DnsMessage.TypeA, 5), default);
        Assert.Equal(2, DnsMessage.ResponseCode(answer)); // SERVFAIL, not a plaintext fallback
        Assert.Empty(network.Names);
        Assert.Equal(1, forwarder.Stats.Failures);
        Assert.Contains("encrypted is down", forwarder.Stats.LastError, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Serves_tcp_clients()
    {
        var encrypted = new FakeUpstream("encrypted", Echo);
        await using DnsForwarder forwarder = Create(encrypted, null);
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(forwarder.BoundTcpEndpoints[0]);
        NetworkStream stream = tcp.GetStream();
        byte[] query = DnsMessage.BuildQuery("example.net", DnsMessage.TypeA, 3);
        await stream.WriteAsync(new byte[] { 0, (byte)query.Length }.Concat(query).ToArray());
        byte[] length = new byte[2];
        await stream.ReadExactlyAsync(length);
        byte[] answer = new byte[(length[0] << 8) | length[1]];
        await stream.ReadExactlyAsync(answer);
        Assert.Equal(3, DnsMessage.ReadId(answer));
    }

    [Fact]
    public void Large_udp_answers_are_truncated_unless_edns_allows_them()
    {
        byte[] query = DnsMessage.BuildQuery("big.example", DnsMessage.TypeTxt, 11);
        byte[] big = new byte[900];
        query.CopyTo(big, 0);
        byte[] truncated = DnsForwarder.TruncateForUdp(query, big);
        Assert.True(DnsMessage.IsTruncated(truncated));
        Assert.Equal(0, DnsMessage.ResponseCode(truncated));

        // Same query with an EDNS OPT record advertising 1232 bytes.
        byte[] edns = [.. query, 0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0];
        edns[11] = 1; // ARCOUNT
        Assert.Same(big, DnsForwarder.TruncateForUdp(edns, big));
    }
}

public class LeakTestTests
{
    private sealed class FakeResolver(Dictionary<string, string[][]> zone) : ISystemTxtResolver
    {
        public Task<IReadOnlyList<IReadOnlyList<string>>> QueryTxtAsync(string name, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<IReadOnlyList<string>>>(
                zone.TryGetValue(name, out string[][]? records) ? [.. records.Select(r => (IReadOnlyList<string>)r)] : []);
    }

    private static DnsServerConfig Cloudflare => DnsPresets.Find("cloudflare")!.Resolve(DnsProtocol.Https);

    [Fact]
    public async Task Passes_when_all_resolvers_belong_to_the_provider()
    {
        var resolver = new FakeResolver(new()
        {
            ["whoami.ds.akahelp.net"] = [["ns", "172.70.1.1"], ["ip", "198.51.100.7"]],
            ["o-o.myaddr.l.google.com"] = [["172.70.1.2"]],
            ["1.1.70.172.origin.asn.cymru.com"] = [["13335 | 172.70.0.0/15 | US | arin | 2014-03-28"]],
            ["2.1.70.172.origin.asn.cymru.com"] = [["13335 | 172.70.0.0/15 | US | arin | 2014-03-28"]],
            ["AS13335.asn.cymru.com"] = [["13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"]],
        });
        LeakTestResult result = await new LeakTest(resolver).RunAsync(Cloudflare, default);
        Assert.Equal(LeakVerdict.Pass, result.Verdict);
        Assert.Equal(2, result.Resolvers.Count);
        Assert.All(result.Resolvers, r => Assert.Equal("CLOUDFLARENET, US", r.Owner));
    }

    [Fact]
    public async Task Reports_a_leak_to_the_isp()
    {
        var resolver = new FakeResolver(new()
        {
            ["whoami.ds.akahelp.net"] = [["ns", "203.0.113.53"]],
            ["53.113.0.203.origin.asn.cymru.com"] = [["64500 | 203.0.113.0/24 | TR | ripencc | 2001-01-01"]],
            ["AS64500.asn.cymru.com"] = [["64500 | TR | ripencc | 2001-01-01 | EXAMPLE-ISP, TR"]],
        });
        LeakTestResult result = await new LeakTest(resolver).RunAsync(Cloudflare, default);
        Assert.Equal(LeakVerdict.Leak, result.Verdict);
        Assert.Contains("EXAMPLE-ISP", result.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Fails_when_nothing_answers()
    {
        LeakTestResult result = await new LeakTest(new FakeResolver([])).RunAsync(Cloudflare, default);
        Assert.Equal(LeakVerdict.Failed, result.Verdict);
    }

    [Fact]
    public void Inconclusive_for_providers_without_known_networks()
    {
        DnsServerConfig mullvad = DnsPresets.Find("mullvad")!.Resolve(DnsProtocol.Https);
        LeakTestResult result = LeakTest.Judge(mullvad, [new ResolverObservation("194.242.2.2", 39351, "X")]);
        Assert.Equal(LeakVerdict.Inconclusive, result.Verdict);
    }

    [Fact]
    public void Builds_cymru_names()
    {
        Assert.Equal("4.3.2.1.origin.asn.cymru.com", LeakTest.CymruOriginName(IPAddress.Parse("1.2.3.4")));
        string v6 = LeakTest.CymruOriginName(IPAddress.Parse("2606:4700::1"));
        Assert.StartsWith("1.0.0.0.", v6, StringComparison.Ordinal);
        Assert.EndsWith(".0.0.7.4.6.0.6.2.origin6.asn.cymru.com", v6, StringComparison.Ordinal);
    }
}
