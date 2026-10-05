using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Agamemnon.Core.Dns;
using Agamemnon.Core.Util;
using Microsoft.Win32;

namespace Agamemnon.Platform.Windows;

/// <summary>
/// Points Windows at encrypted DNS without configuration profiles or Group Policy. Runs inside the
/// Agamemnon service (LocalSystem). Two strategies:
/// <list type="bullet">
/// <item><b>Native</b> (Windows 11, DNS-over-HTTPS): registers the provider's DoH template with the
/// Windows DNS client (auto-upgrade on, plaintext fallback off) and sets the provider's IPs on
/// each connected adapter. Excluded domains become NRPT rules pointing at the network's resolver.</item>
/// <item><b>Loopback</b> (DNS-over-TLS, or Windows 10): sets 127.0.0.1/::1 on each adapter so all
/// queries reach Agamemnon's forwarder.</item>
/// </list>
/// Everything it changes is recorded first, so <see cref="RestoreAsync"/> puts back exactly what
/// the user had (DHCP or their own static servers, and any pre-existing DoH entries).
/// </summary>
public sealed class WindowsDnsConfigurator(string stateDirectory, IProcessRunner? runner = null) : IDisposable
{
    private const string NrptComment = "Agamemnon";
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
    private readonly IProcessRunner _runner = runner ?? ProcessRunner.Instance;
    private readonly string _statePath = Path.Combine(stateDirectory, "dns-original-state.json");
    private readonly SemaphoreSlim _gate = new(1, 1);

    /// <summary>Windows 11 (build 22000+) has a built-in DNS-over-HTTPS client.</summary>
    public static bool SupportsNativeDoh => Environment.OSVersion.Version.Build >= 22000;

    public async Task ApplyNativeDohAsync(DnsServerConfig server, IReadOnlyList<string> excludedDomains, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            OriginalState state = LoadState();
            IReadOnlyList<Adapter> adapters = ConnectedAdapters();
            RememberAdapters(state, adapters);
            await RememberDohEntriesAsync(state, server.Addresses, cancellationToken).ConfigureAwait(false);
            IReadOnlyList<IPEndPoint> networkDns = NetworkDnsServersFor(state);
            SaveState(state);

            var script = new StringBuilder("$ErrorActionPreference = 'Stop'\n");
            foreach (string address in server.Addresses.Select(a => IPAddress.Parse(a).ToString()))
            {
                string args = $"-ServerAddress {Quote(address)} -DohTemplate {Quote(server.DohTemplate)} -AllowFallbackToUdp $false -AutoUpgrade $true";
                script.Append(System.Globalization.CultureInfo.InvariantCulture,
                    $"if (Get-DnsClientDohServerAddress -ServerAddress {Quote(address)} -ErrorAction SilentlyContinue) {{ Set-DnsClientDohServerAddress {args} }} else {{ Add-DnsClientDohServerAddress {args} }}\n");
            }

            foreach (Adapter adapter in adapters)
            {
                AppendSetServers(script, adapter.Index, server.Addresses);
            }

            AppendNrptRules(script, excludedDomains, networkDns);
            script.Append("Clear-DnsClientCache\n");
            await RunAsync(script.ToString(), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Sends all DNS on connected adapters to the local forwarder.</summary>
    public async Task ApplyLoopbackAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            OriginalState state = LoadState();
            IReadOnlyList<Adapter> adapters = ConnectedAdapters();
            RememberAdapters(state, adapters);
            SaveState(state);

            var script = new StringBuilder("$ErrorActionPreference = 'Stop'\n");
            foreach (Adapter adapter in adapters)
            {
                AppendSetServers(script, adapter.Index, ["127.0.0.1", "::1"]);
            }

            // Any NRPT rules from an earlier native session would bypass the forwarder's own exclusions.
            AppendNrptRules(script, [], []);
            script.Append("Clear-DnsClientCache\n");
            await RunAsync(script.ToString(), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Puts every adapter and DoH entry back the way it was before Agamemnon touched it.</summary>
    public async Task RestoreAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!File.Exists(_statePath))
            {
                return; // nothing was ever changed (or it has already been restored)
            }

            OriginalState state = LoadState();
            var script = new StringBuilder("$ErrorActionPreference = 'Continue'\n");
            Dictionary<string, int> indexes = AllAdapterIndexes();
            foreach ((string id, AdapterState original) in state.Adapters)
            {
                if (!indexes.TryGetValue(id, out int index))
                {
                    continue;
                }

                string[] servers = [.. original.StaticV4.Concat(original.StaticV6)];
                if (servers.Length == 0)
                {
                    script.Append(FormattableString.Invariant($"Set-DnsClientServerAddress -InterfaceIndex {index} -ResetServerAddresses\n"));
                }
                else
                {
                    AppendSetServers(script, index, servers);
                }
            }

            foreach ((string address, DohEntry? previous) in state.DohEntries)
            {
                script.Append(previous is null
                    ? $"Remove-DnsClientDohServerAddress -ServerAddress {Quote(address)} -ErrorAction SilentlyContinue\n"
                    : $"Set-DnsClientDohServerAddress -ServerAddress {Quote(address)} -DohTemplate {Quote(previous.Template)} " +
                      $"-AllowFallbackToUdp ${previous.AllowFallbackToUdp.ToString().ToLowerInvariant()} -AutoUpgrade ${previous.AutoUpgrade.ToString().ToLowerInvariant()}\n");
            }

            AppendNrptRules(script, [], []);
            script.Append("Clear-DnsClientCache\n");
            await RunAsync(script.ToString(), cancellationToken).ConfigureAwait(false);
            File.Delete(_statePath);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>The network's own resolvers (DHCP-assigned, or the user's static ones): used for excluded domains.</summary>
    public IReadOnlyList<IPEndPoint> NetworkDnsServers() => NetworkDnsServersFor(LoadState());

    private static IReadOnlyList<IPEndPoint> NetworkDnsServersFor(OriginalState state)
    {
        var servers = new List<IPEndPoint>();
        foreach (Adapter adapter in ConnectedAdapters())
        {
            IEnumerable<string> candidates = state.Adapters.TryGetValue(adapter.Id, out AdapterState? saved)
                && saved.StaticV4.Count + saved.StaticV6.Count > 0
                ? saved.StaticV4.Concat(saved.StaticV6)
                : ReadServers(adapter.Id, "Tcpip", "DhcpNameServer").Concat(ReadServers(adapter.Id, "Tcpip6", "Dhcpv6DNSServers"));
            foreach (string candidate in candidates)
            {
                if (IPAddress.TryParse(candidate, out IPAddress? ip) && !IPAddress.IsLoopback(ip))
                {
                    var endpoint = new IPEndPoint(ip, 53);
                    if (!servers.Contains(endpoint))
                    {
                        servers.Add(endpoint);
                    }
                }
            }
        }

        return servers;
    }

    /// <summary>
    /// Sets an adapter's DNS servers. Adapters with IPv6 unbound reject IPv6 servers, so on
    /// failure the IPv4 ones are set on their own.
    /// </summary>
    private static void AppendSetServers(StringBuilder script, int index, IEnumerable<string> addresses)
    {
        IPAddress[] parsed = [.. addresses.Select(IPAddress.Parse)];
        string all = Array(parsed.Select(a => a.ToString()));
        string v4 = Array(parsed.Where(a => a.AddressFamily == AddressFamily.InterNetwork).Select(a => a.ToString()));
        script.Append(System.Globalization.CultureInfo.InvariantCulture,
            $"try {{ Set-DnsClientServerAddress -InterfaceIndex {index} -ServerAddresses {all} -ErrorAction Stop }} " +
            $"catch {{ Set-DnsClientServerAddress -InterfaceIndex {index} -ServerAddresses {v4} -ErrorAction Stop }}\n");
    }

    private static void AppendNrptRules(StringBuilder script, IReadOnlyList<string> excludedDomains, IReadOnlyList<IPEndPoint> networkDns)
    {
        script.Append(System.Globalization.CultureInfo.InvariantCulture,
            $"Get-DnsClientNrptRule | Where-Object {{ $_.Comment -eq {Quote(NrptComment)} }} | ForEach-Object {{ Remove-DnsClientNrptRule -Name $_.Name -Force }}\n");
        if (networkDns.Count == 0)
        {
            return;
        }

        string servers = Array(networkDns.Select(e => e.Address.ToString()));
        foreach (string raw in excludedDomains)
        {
            // Domains were normalized by DnsSettings.Normalize; re-check so nothing odd reaches PowerShell.
            string domain = DnsValidation.NormalizeDomain(raw) ?? throw new DnsConfigurationException($"Invalid domain '{raw}'.");
            script.Append(System.Globalization.CultureInfo.InvariantCulture,
                $"Add-DnsClientNrptRule -Namespace {Quote("." + domain)} -NameServers {servers} -Comment {Quote(NrptComment)}\n");
            script.Append(System.Globalization.CultureInfo.InvariantCulture,
                $"Add-DnsClientNrptRule -Namespace {Quote(domain)} -NameServers {servers} -Comment {Quote(NrptComment)}\n");
        }
    }

    private async Task RememberDohEntriesAsync(OriginalState state, IReadOnlyList<string> addresses, CancellationToken cancellationToken)
    {
        string[] missing = [.. addresses.Select(a => IPAddress.Parse(a).ToString()).Where(a => !state.DohEntries.ContainsKey(a))];
        if (missing.Length == 0)
        {
            return;
        }

        string script = $"@(Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue | Where-Object {{ {Array(missing)} -contains $_.ServerAddress }} | " +
                        "Select-Object ServerAddress, DohTemplate, AllowFallbackToUdp, AutoUpgrade) | ConvertTo-Json -Compress";
        ProcessResult result = await RunAsync(script, cancellationToken).ConfigureAwait(false);
        var existing = new Dictionary<string, DohEntry>(StringComparer.OrdinalIgnoreCase);
        string json = result.StandardOutput.Trim();
        if (json.Length > 0)
        {
            using JsonDocument document = JsonDocument.Parse(json);
            IEnumerable<JsonElement> rows = document.RootElement.ValueKind == JsonValueKind.Array
                ? document.RootElement.EnumerateArray()
                : [document.RootElement];
            foreach (JsonElement row in rows)
            {
                string? address = row.GetProperty("ServerAddress").GetString();
                if (address is not null)
                {
                    existing[address] = new DohEntry(
                        row.GetProperty("DohTemplate").GetString() ?? string.Empty,
                        row.GetProperty("AllowFallbackToUdp").GetBoolean(),
                        row.GetProperty("AutoUpgrade").GetBoolean());
                }
            }
        }

        foreach (string address in missing)
        {
            state.DohEntries[address] = existing.GetValueOrDefault(address);
        }
    }

    private static void RememberAdapters(OriginalState state, IReadOnlyList<Adapter> adapters)
    {
        foreach (Adapter adapter in adapters)
        {
            if (state.Adapters.ContainsKey(adapter.Id))
            {
                continue; // already recorded before our first change: never overwrite with our own settings
            }

            state.Adapters[adapter.Id] = new AdapterState(
                [.. ReadServers(adapter.Id, "Tcpip", "NameServer").Where(s => s != "127.0.0.1")],
                [.. ReadServers(adapter.Id, "Tcpip6", "NameServer").Where(s => s != "::1")]);
        }
    }

    private static IEnumerable<string> ReadServers(string adapterId, string stack, string value)
    {
        using RegistryKey? key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{stack}\Parameters\Interfaces\{adapterId}");
        return key?.GetValue(value) is string text
            ? text.Split([',', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Where(s => IPAddress.TryParse(s, out _))
            : [];
    }

    /// <summary>Adapters that are up and route to the internet (have a default gateway).</summary>
    private static List<Adapter> ConnectedAdapters()
    {
        var adapters = new List<Adapter>();
        foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up
                || nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
            {
                continue;
            }

            IPInterfaceProperties properties = nic.GetIPProperties();
            if (properties.GatewayAddresses.Count == 0 || properties.GetIPv4Properties() is not { } v4)
            {
                continue;
            }

            adapters.Add(new Adapter(nic.Id, v4.Index));
        }

        return adapters;
    }

    private static Dictionary<string, int> AllAdapterIndexes()
    {
        var indexes = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            try
            {
                if (nic.GetIPProperties().GetIPv4Properties() is { } v4)
                {
                    indexes[nic.Id] = v4.Index;
                }
            }
            catch (NetworkInformationException)
            {
            }
        }

        return indexes;
    }

    private async Task<ProcessResult> RunAsync(string script, CancellationToken cancellationToken)
    {
        // Full path, so a powershell.exe earlier on PATH can't be substituted.
        string powershell = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
        string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        ProcessResult result = await _runner.RunAsync(
            powershell,
            ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
            TimeSpan.FromMinutes(1),
            cancellationToken).ConfigureAwait(false);
        if (result.ExitCode != 0)
        {
            string error = result.StandardError.Trim();
            throw new DnsConfigurationException($"Windows refused the DNS change: {(error.Length > 400 ? error[..400] : error)}");
        }

        return result;
    }

    private static string Quote(string value) => "'" + value.Replace("'", "''", StringComparison.Ordinal) + "'";

    private static string Array(IEnumerable<string> values) => "@(" + string.Join(",", values.Select(Quote)) + ")";

    private OriginalState LoadState()
    {
        try
        {
            return File.Exists(_statePath)
                ? JsonSerializer.Deserialize<OriginalState>(File.ReadAllText(_statePath), JsonOptions) ?? new OriginalState()
                : new OriginalState();
        }
        catch (JsonException)
        {
            return new OriginalState();
        }
    }

    private void SaveState(OriginalState state)
    {
        Directory.CreateDirectory(stateDirectory);
        string temp = _statePath + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(state, JsonOptions));
        File.Move(temp, _statePath, overwrite: true);
    }

    public void Dispose() => _gate.Dispose();

    private sealed record Adapter(string Id, int Index);

    private sealed class OriginalState
    {
        public Dictionary<string, AdapterState> Adapters { get; init; } = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>DoH entries we changed, with what was there before (null: we added it).</summary>
        public Dictionary<string, DohEntry?> DohEntries { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    }

    private sealed record AdapterState(IReadOnlyList<string> StaticV4, IReadOnlyList<string> StaticV6);

    private sealed record DohEntry(string Template, bool AllowFallbackToUdp, bool AutoUpgrade);
}
