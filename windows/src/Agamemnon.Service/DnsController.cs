using System.Net.NetworkInformation;
using Agamemnon.Core.Dns;
using Agamemnon.Core.Ipc;
using Agamemnon.Core.Settings;
using Agamemnon.Platform.Windows;

namespace Agamemnon.Service;

/// <summary>
/// Owns the machine's encrypted-DNS state: persists the user's choice, reacts to network and
/// Wi-Fi changes, and switches between Windows' native DoH client and the local forwarder.
/// </summary>
public sealed class DnsController(ILogger<DnsController> logger, EventHub events) : BackgroundService
{
    private readonly JsonFileStore<DnsSettings> _store = new(Path.Combine(AgamemnonPaths.MachineData, "dns-settings.json"));
    private readonly WindowsDnsConfigurator _configurator = new(AgamemnonPaths.MachineData);
    private readonly SemaphoreSlim _reconcile = new(1, 1);
    private readonly SemaphoreSlim _wake = new(0);
    private DnsForwarder? _forwarder;
    private string? _forwarderKey;
    private string? _appliedKey;
    private DnsStatus _status = new() { Settings = new DnsSettings(), Message = "Starting…" };

    public DnsStatus Status
    {
        get
        {
            DnsStatus status = Volatile.Read(ref _status);
            if (_forwarder is { } forwarder && status.Mode == DnsMode.Forwarder)
            {
                DnsForwarderStats stats = forwarder.Stats;
                status = status with { Queries = stats.Queries, Failures = stats.Failures, LastError = stats.LastError };
            }

            return status;
        }
    }

    public static string? CurrentWifi()
    {
        try
        {
            return WifiNetwork.CurrentSsid();
        }
        catch (DllNotFoundException)
        {
            return null; // Windows Server without the WLAN feature
        }
    }

    public async Task<DnsStatus> ApplyAsync(DnsSettings requested, CancellationToken cancellationToken)
    {
        DnsSettings settings = requested.Normalize();
        if (settings.Enabled)
        {
            settings.ResolveServer(); // validate before saving
        }

        _store.Save(settings);
        _appliedKey = null;
        await ReconcileAsync(cancellationToken).ConfigureAwait(false);
        DnsStatus status = Status;
        if (status.Mode == DnsMode.Error)
        {
            throw new IpcException(status.Message);
        }

        return status;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        NetworkChange.NetworkAddressChanged += OnNetworkChanged;
        NetworkChange.NetworkAvailabilityChanged += OnNetworkChanged;
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                await ReconcileAsync(stoppingToken).ConfigureAwait(false);

                // Wake on network changes (debounced) or every minute to catch Wi-Fi roaming.
                await _wake.WaitAsync(TimeSpan.FromMinutes(1), stoppingToken).ConfigureAwait(false);
                await Task.Delay(TimeSpan.FromSeconds(2), stoppingToken).ConfigureAwait(false);
                while (_wake.CurrentCount > 0)
                {
                    await _wake.WaitAsync(stoppingToken).ConfigureAwait(false);
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
        finally
        {
            NetworkChange.NetworkAddressChanged -= OnNetworkChanged;
            NetworkChange.NetworkAvailabilityChanged -= OnNetworkChanged;
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await base.StopAsync(cancellationToken).ConfigureAwait(false);

        // Never leave adapters pointing at a forwarder that is no longer running. The settings
        // stay saved, so encrypted DNS comes back when the service starts again.
        if (_appliedKey is not null)
        {
            using var budget = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            try
            {
                await _configurator.RestoreAsync(budget.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is DnsConfigurationException or OperationCanceledException or IOException)
            {
                logger.LogError(ex, "Could not restore DNS settings while stopping");
            }
        }

        await StopForwarderAsync().ConfigureAwait(false);
    }

    public override void Dispose()
    {
        _configurator.Dispose();
        _reconcile.Dispose();
        _wake.Dispose();
        base.Dispose();
    }

    private void OnNetworkChanged(object? sender, EventArgs e) => _wake.Release();

    private async Task ReconcileAsync(CancellationToken cancellationToken)
    {
        await _reconcile.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            DnsSettings settings = _store.Load();
            string? wifi = CurrentWifi();
            DnsActivation activation = DnsRules.Evaluate(settings, wifi);
            string adapters = string.Join(",", NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up).Select(n => n.Id).Order(StringComparer.Ordinal));
            string key = $"{System.Text.Json.JsonSerializer.Serialize(settings)}|{activation.Active}|{wifi}|{adapters}";
            if (key == _appliedKey)
            {
                return;
            }

            DnsStatus status;
            try
            {
                status = activation.Active
                    ? await ActivateAsync(settings, wifi, cancellationToken).ConfigureAwait(false)
                    : await DeactivateAsync(settings, wifi, activation, cancellationToken).ConfigureAwait(false);
                _appliedKey = key;
            }
            catch (Exception ex) when (ex is DnsConfigurationException or IOException or System.Net.Sockets.SocketException)
            {
                logger.LogError(ex, "Applying DNS settings failed");
                status = new DnsStatus { Settings = settings, Mode = DnsMode.Error, Message = ex.Message, CurrentNetwork = wifi };
                _appliedKey = null;
            }

            Volatile.Write(ref _status, status);
            events.Publish(new ServiceEvent { Kind = ServiceEventKind.DnsStatusChanged, Dns = status });
        }
        finally
        {
            _reconcile.Release();
        }
    }

    private async Task<DnsStatus> ActivateAsync(DnsSettings settings, string? wifi, CancellationToken cancellationToken)
    {
        DnsServerConfig server = settings.ResolveServer();
        string protocol = server.Protocol == DnsProtocol.Https ? "DNS-over-HTTPS" : "DNS-over-TLS";
        if (server.Protocol == DnsProtocol.Https && WindowsDnsConfigurator.SupportsNativeDoh)
        {
            await StopForwarderAsync().ConfigureAwait(false);
            await _configurator.ApplyNativeDohAsync(server, settings.ExcludedDomains, cancellationToken).ConfigureAwait(false);
            logger.LogInformation("Encrypted DNS on: {Server} via Windows DoH client", server.Name);
            return new DnsStatus
            {
                Settings = settings,
                Mode = DnsMode.Native,
                ServerName = server.Name,
                CurrentNetwork = wifi,
                Message = $"{server.Name} over {protocol}, handled by Windows.",
            };
        }

        // Excluded domains go to the current network's resolver, which changes when the PC moves networks.
        var networkDns = _configurator.NetworkDnsServers();
        string forwarderKey = System.Text.Json.JsonSerializer.Serialize(new { server, settings.ExcludedDomains, Network = networkDns.Select(e => e.ToString()) });
        if (_forwarder is null || _forwarderKey != forwarderKey)
        {
            await StopForwarderAsync().ConfigureAwait(false);
            var forwarder = new DnsForwarder(
                DnsUpstreams.Create(server),
                settings.ExcludedDomains,
                settings.ExcludedDomains.Count > 0 ? new PlainUpstream(networkDns) : null);
            forwarder.Start();
            _forwarder = forwarder;
            _forwarderKey = forwarderKey;
        }

        await _configurator.ApplyLoopbackAsync(cancellationToken).ConfigureAwait(false);
        logger.LogInformation("Encrypted DNS on: {Server} via local forwarder", server.Name);
        return new DnsStatus
        {
            Settings = settings,
            Mode = DnsMode.Forwarder,
            ServerName = server.Name,
            CurrentNetwork = wifi,
            Message = $"{server.Name} over {protocol}, handled by Agamemnon.",
        };
    }

    private async Task<DnsStatus> DeactivateAsync(DnsSettings settings, string? wifi, DnsActivation activation, CancellationToken cancellationToken)
    {
        await _configurator.RestoreAsync(cancellationToken).ConfigureAwait(false);
        await StopForwarderAsync().ConfigureAwait(false);
        return new DnsStatus
        {
            Settings = settings,
            Mode = settings.Enabled ? DnsMode.Paused : DnsMode.Off,
            CurrentNetwork = wifi,
            Message = activation.Reason,
        };
    }

    private async Task StopForwarderAsync()
    {
        if (_forwarder is { } forwarder)
        {
            _forwarder = null;
            _forwarderKey = null;
            await forwarder.DisposeAsync().ConfigureAwait(false);
        }
    }
}
