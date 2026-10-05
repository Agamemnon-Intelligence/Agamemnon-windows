using System.Collections.ObjectModel;
using System.Security.Principal;
using System.Windows.Media;
using Agamemnon.App.Services;
using Agamemnon.Core.Dns;
using Agamemnon.Core.Ipc;
using Agamemnon.Platform.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Agamemnon.App.ViewModels;

public sealed partial class PresetOption(DnsPreset? preset, DnsViewModel owner) : ObservableObject
{
    public string Id => preset?.Id ?? DnsPresets.CustomId;

    public string Name => preset?.Name ?? "Custom server";

    public string Description => preset?.Description ?? "Any DNS-over-HTTPS or DNS-over-TLS server you trust.";

    public bool IsSelected
    {
        get => string.Equals(owner.SelectedPresetId, Id, StringComparison.OrdinalIgnoreCase);
        set
        {
            if (value)
            {
                owner.SelectPreset(Id);
            }
        }
    }

    public void Refresh() => OnPropertyChanged(nameof(IsSelected));
}

public sealed partial class ResolverRow(ResolverObservation observation)
{
    public string Address => observation.Address;

    public string Owner => observation.Owner ?? (observation.Asn is int asn ? $"AS{asn}" : "Unknown network");
}

/// <summary>
/// Encrypted DNS page. Settings live in the service (it applies them system-wide); this page
/// edits a copy and sends it. Selections and rules apply immediately; typed server details apply
/// with their Save button.
/// </summary>
public sealed partial class DnsViewModel : PageViewModel
{
    private readonly AppServices _services;
    private readonly MainViewModel _main;
    private DnsStatus? _status;
    private string? _loadedSettings;
    private bool _loading;

    public DnsViewModel(AppServices services, MainViewModel main)
    {
        _services = services;
        _main = main;
        GeneralPresets = [.. DnsPresets.All.Where(p => p.Category == DnsCategory.General).Select(p => new PresetOption(p, this))];
        FilteringPresets = [.. DnsPresets.All.Where(p => p.Category == DnsCategory.SecurityFiltering).Select(p => new PresetOption(p, this))];
        CustomPreset = new PresetOption(null, this);
    }

    public override string Title => "DNS";

    public IReadOnlyList<PresetOption> GeneralPresets { get; }

    public IReadOnlyList<PresetOption> FilteringPresets { get; }

    public PresetOption CustomPreset { get; }

    public ObservableCollection<string> ExcludedDomains { get; } = [];

    public ObservableCollection<string> DisabledNetworks { get; } = [];

    public ObservableCollection<ResolverRow> LeakResolvers { get; } = [];

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsNextDns), nameof(IsCustom))]
    public partial string SelectedPresetId { get; set; } = DnsPresets.Default.Id;

    [ObservableProperty]
    public partial bool IsEnabled { get; set; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsTls))]
    public partial bool IsHttps { get; set; } = true;

    [ObservableProperty]
    public partial string NextDnsId { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string CustomName { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string CustomDohUrl { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string CustomTlsHost { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string CustomAddresses { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string NewDomain { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string NewNetwork { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string? CurrentNetwork { get; set; }

    [ObservableProperty]
    public partial bool IsBusy { get; set; }

    [ObservableProperty]
    public partial string? Error { get; set; }

    [ObservableProperty]
    public partial string StatusText { get; set; } = "Connecting to the Agamemnon service…";

    [ObservableProperty]
    public partial string? StatsText { get; set; }

    [ObservableProperty]
    public partial string? LeakSummary { get; set; }

    [ObservableProperty]
    public partial Brush LeakBrush { get; set; } = StatusBrushes.Neutral;

    [ObservableProperty]
    public partial bool ServiceReady { get; set; }

    public bool IsTls
    {
        get => !IsHttps;
        set => IsHttps = !value;
    }

    public bool IsNextDns => string.Equals(SelectedPresetId, "nextdns", StringComparison.OrdinalIgnoreCase);

    public bool IsCustom => string.Equals(SelectedPresetId, DnsPresets.CustomId, StringComparison.OrdinalIgnoreCase);

    public bool IsProtecting => _status?.IsProtecting == true;

    public bool HasError => _status?.Mode == DnsMode.Error;

    public Brush StatusBrush => IsProtecting ? StatusBrushes.For(ProtectionLevel.Protected)
        : HasError ? StatusBrushes.For(ProtectionLevel.Warning) : StatusBrushes.Neutral;

    public string Summary => _status switch
    {
        null => "Service not running",
        { Mode: DnsMode.Native or DnsMode.Forwarder } s =>
            $"{s.ServerName} ({(s.Settings.Protocol == DnsProtocol.Https ? "DoH" : "DoT")})",
        { Mode: DnsMode.Paused } s => $"Paused on {s.CurrentNetwork}",
        { Mode: DnsMode.Error } => "Problem",
        _ => "Off",
    };

    public override void OnShown() => _ = RefreshAsync();

    public void SelectPreset(string id)
    {
        if (string.Equals(SelectedPresetId, id, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        SelectedPresetId = id;
        foreach (PresetOption option in GeneralPresets.Concat(FilteringPresets).Append(CustomPreset))
        {
            option.Refresh();
        }

        // Presets that need details (NextDNS ID, custom server) apply when those are saved.
        if (!_loading && !IsNextDns && !IsCustom)
        {
            _ = ApplyAsync();
        }
    }

    partial void OnIsEnabledChanged(bool value)
    {
        if (!_loading)
        {
            _ = ApplyAsync();
        }
    }

    partial void OnIsHttpsChanged(bool value)
    {
        if (!_loading && (!IsNextDns || NextDnsId.Length > 0) && (!IsCustom || CustomAddresses.Length > 0))
        {
            _ = ApplyAsync();
        }
    }

    /// <summary>A new status from the service (pushed, or after a change).</summary>
    public void ApplyStatus(DnsStatus status)
    {
        _status = status;
        ServiceReady = true;

        // Reload the form only when the saved settings actually changed, so a routine status
        // update doesn't wipe out a NextDNS ID or custom server the user is still typing.
        string saved = System.Text.Json.JsonSerializer.Serialize(status.Settings, IpcProtocol.Json);
        if (!IsBusy && saved != _loadedSettings)
        {
            Load(status.Settings);
            _loadedSettings = saved;
        }

        CurrentNetwork = status.CurrentNetwork;
        StatusText = status.Message;
        Error = status.Mode == DnsMode.Error ? status.Message : null;
        StatsText = status.Mode switch
        {
            DnsMode.Forwarder => $"Encrypted by Agamemnon's local resolver · {status.Queries:N0} lookups, {status.Failures:N0} failed"
                                 + (status.LastError is { } e ? $" · last problem: {e}" : string.Empty),
            DnsMode.Native => "Encrypted by Windows' built-in DNS-over-HTTPS client; plain-text fallback is off.",
            _ => null,
        };
        OnPropertyChanged(nameof(IsProtecting));
        OnPropertyChanged(nameof(HasError));
        OnPropertyChanged(nameof(StatusBrush));
        OnPropertyChanged(nameof(Summary));
    }

    public void ServiceUnavailable()
    {
        _status = null;
        ServiceReady = false;
        StatusText = "The Agamemnon service isn't running, so DNS settings can't be changed.";
        OnPropertyChanged(nameof(IsProtecting));
        OnPropertyChanged(nameof(HasError));
        OnPropertyChanged(nameof(StatusBrush));
        OnPropertyChanged(nameof(Summary));
    }

    private void Load(DnsSettings settings)
    {
        _loading = true;
        try
        {
            IsEnabled = settings.Enabled;
            IsHttps = settings.Protocol == DnsProtocol.Https;
            SelectPreset(settings.PresetId);
            NextDnsId = settings.ProfileId ?? string.Empty;
            CustomName = settings.Custom?.Name ?? string.Empty;
            CustomDohUrl = settings.Custom?.DohTemplate ?? string.Empty;
            CustomTlsHost = settings.Custom?.DotHost ?? string.Empty;
            CustomAddresses = string.Join(", ", settings.Custom?.Addresses ?? []);
            Replace(ExcludedDomains, settings.ExcludedDomains);
            Replace(DisabledNetworks, settings.DisabledOnNetworks);
        }
        finally
        {
            _loading = false;
        }
    }

    private static void Replace(ObservableCollection<string> target, IEnumerable<string> values)
    {
        target.Clear();
        foreach (string value in values)
        {
            target.Add(value);
        }
    }

    private DnsSettings BuildSettings() => new()
    {
        Enabled = IsEnabled,
        PresetId = SelectedPresetId,
        Protocol = IsHttps ? DnsProtocol.Https : DnsProtocol.Tls,
        ProfileId = string.IsNullOrWhiteSpace(NextDnsId) ? null : NextDnsId.Trim(),
        Custom = IsCustom || !string.IsNullOrWhiteSpace(CustomAddresses)
            ? new CustomDnsServer
            {
                Name = CustomName.Trim(),
                DohTemplate = CustomDohUrl.Trim(),
                DotHost = CustomTlsHost.Trim(),
                Addresses = [.. CustomAddresses.Split([',', ' ', ';'], StringSplitOptions.RemoveEmptyEntries)],
            }
            : null,
        ExcludedDomains = [.. ExcludedDomains],
        DisabledOnNetworks = [.. DisabledNetworks],
    };

    [RelayCommand]
    private async Task RefreshAsync()
    {
        try
        {
            ApplyStatus(await _services.Service.CallAsync<DnsStatus>(IpcMethods.GetDnsStatus, null, CancellationToken.None).ConfigureAwait(true));
            CurrentNetwork = (await _services.Service.CallAsync<CurrentNetwork>(IpcMethods.GetCurrentNetwork, null, CancellationToken.None).ConfigureAwait(true)).WifiName;
        }
        catch (IpcException)
        {
            ServiceUnavailable();
        }
    }

    [RelayCommand]
    private async Task ApplyAsync()
    {
        DnsSettings settings = BuildSettings();
        try
        {
            settings = settings.Normalize();
            if (settings.Enabled)
            {
                settings.ResolveServer();
            }
        }
        catch (DnsConfigurationException ex)
        {
            Error = ex.Message;
            return;
        }

        IsBusy = true;
        Error = null;
        try
        {
            if (settings.Enabled && settings.IsCustom && !IsElevated())
            {
                // A custom server can redirect every lookup on this PC, so Windows asks an administrator.
                if (!await ElevatedActions.ApplyDnsAsync(settings).ConfigureAwait(true))
                {
                    Error = "The custom server wasn't applied: administrator approval was cancelled or failed.";
                }

                await RefreshAsync().ConfigureAwait(true);
                return;
            }

            ApplyStatus(await _services.Service.CallAsync<DnsStatus>(IpcMethods.ApplyDns, settings, CancellationToken.None).ConfigureAwait(true));
            _services.Activity.Add(new ActivityEntry(DateTimeOffset.Now, ActivityKind.Dns, ActivityLevel.Info,
                settings.Enabled ? $"Encrypted DNS: {Summary}" : "Encrypted DNS turned off"));
        }
        catch (IpcException ex)
        {
            Error = ex.Message;
            await RefreshAsync().ConfigureAwait(true);
        }
        finally
        {
            IsBusy = false;
            _main.RefreshStatus();
        }
    }

    [RelayCommand]
    private Task ToggleAsync()
    {
        IsEnabled = !IsEnabled; // OnIsEnabledChanged applies it
        return Task.CompletedTask;
    }

    [RelayCommand]
    private Task AddDomainAsync()
    {
        string? domain = DnsValidation.NormalizeDomain(NewDomain);
        if (domain is null)
        {
            Error = $"“{NewDomain}” isn't a valid domain name.";
            return Task.CompletedTask;
        }

        if (!ExcludedDomains.Contains(domain))
        {
            ExcludedDomains.Add(domain);
        }

        NewDomain = string.Empty;
        return ApplyAsync();
    }

    [RelayCommand]
    private Task RemoveDomainAsync(string domain)
    {
        ExcludedDomains.Remove(domain);
        return ApplyAsync();
    }

    [RelayCommand]
    private Task AddNetworkAsync()
    {
        string name = NewNetwork.Trim();
        if (name.Length == 0)
        {
            return Task.CompletedTask;
        }

        if (!DisabledNetworks.Contains(name))
        {
            DisabledNetworks.Add(name);
        }

        NewNetwork = string.Empty;
        return ApplyAsync();
    }

    [RelayCommand]
    private Task AddCurrentNetworkAsync()
    {
        if (CurrentNetwork is null)
        {
            Error = "This PC isn't connected to a Wi-Fi network right now.";
            return Task.CompletedTask;
        }

        NewNetwork = CurrentNetwork;
        return AddNetworkAsync();
    }

    [RelayCommand]
    private Task RemoveNetworkAsync(string network)
    {
        DisabledNetworks.Remove(network);
        return ApplyAsync();
    }

    [RelayCommand]
    private async Task RunLeakTestAsync()
    {
        LeakSummary = "Testing…";
        LeakBrush = StatusBrushes.Neutral;
        LeakResolvers.Clear();
        DnsServerConfig? expected = null;
        if (_status?.IsProtecting == true)
        {
            try
            {
                expected = _status.Settings.ResolveServer();
            }
            catch (DnsConfigurationException)
            {
            }
        }

        LeakTestResult result = await new LeakTest(new WindowsTxtResolver()).RunAsync(expected, CancellationToken.None).ConfigureAwait(true);
        LeakSummary = result.Summary;
        LeakBrush = result.Verdict switch
        {
            LeakVerdict.Pass => StatusBrushes.For(ProtectionLevel.Protected),
            LeakVerdict.Leak => StatusBrushes.For(ProtectionLevel.Threat),
            LeakVerdict.Inconclusive => StatusBrushes.For(ProtectionLevel.Warning),
            _ => StatusBrushes.Neutral,
        };
        foreach (ResolverObservation resolver in result.Resolvers)
        {
            LeakResolvers.Add(new ResolverRow(resolver));
        }
    }

    private static bool IsElevated()
    {
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
}
