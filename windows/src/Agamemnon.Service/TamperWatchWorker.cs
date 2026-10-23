using System.Text.Json;
using Agamemnon.Core.Ipc;
using Agamemnon.Core.Protection;
using Agamemnon.Platform.Windows;
using Microsoft.Win32;

namespace Agamemnon.Service;

/// <summary>
/// 4.0 self-protection for the PC's own defences. Malware commonly (1) edits the hosts file so
/// antivirus and Windows Update sites stop resolving, or to send people to fake sign-in pages,
/// and (2) adds Microsoft Defender exclusions so Defender stops looking at its folder. Both are
/// readable only with administrator rights, so this runs in the LocalSystem service and tells
/// every signed-in user's Agamemnon. Nothing is changed automatically: a person decides.
/// </summary>
public sealed class TamperWatchWorker(ILogger<TamperWatchWorker> logger, EventHub events) : BackgroundService
{
    private static readonly string HostsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");
    private static readonly string BaselinePath = Path.Combine(AgamemnonPaths.MachineData, "tamper-baseline.json");
    private const string ExclusionsKey = @"SOFTWARE\Microsoft\Windows Defender\Exclusions";

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        Baseline baseline = LoadBaseline();
        bool first = baseline.HostsRedirects is null;
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                baseline = Check(baseline, report: !first);
                first = false;
                SaveBaseline(baseline);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or System.Security.SecurityException)
            {
                logger.LogWarning(ex, "Tamper check failed");
            }

            try
            {
                await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    private Baseline Check(Baseline before, bool report)
    {
        string[] redirects = File.Exists(HostsPath)
            ? [.. HostsFile.Suspicious(HostsFile.Parse(File.ReadAllText(HostsPath))).Select(e => $"{e.Address} {e.Host}").Distinct()]
            : [];
        string[] exclusions = [.. DefenderExclusions()];

        if (report)
        {
            foreach (string added in redirects.Except(before.HostsRedirects ?? [], StringComparer.OrdinalIgnoreCase))
            {
                Publish("hosts", added);
            }

            foreach (string added in exclusions.Except(before.Exclusions ?? [], StringComparer.OrdinalIgnoreCase))
            {
                Publish("defender-exclusion", added);
            }
        }

        return new Baseline(redirects, exclusions);
    }

    private void Publish(string kind, string detail)
    {
        logger.LogWarning("Protection setting changed: {Kind} {Detail}", kind, detail);
        events.Publish(new ServiceEvent { Kind = ServiceEventKind.TamperDetected, TamperKind = kind, Detail = detail });
    }

    private static IEnumerable<string> DefenderExclusions()
    {
        using RegistryKey? root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64).OpenSubKey(ExclusionsKey);
        if (root is null)
        {
            yield break;
        }

        foreach (string kind in new[] { "Paths", "Processes", "Extensions" })
        {
            using RegistryKey? key = root.OpenSubKey(kind);
            foreach (string name in key?.GetValueNames() ?? [])
            {
                yield return $"{kind}: {name}";
            }
        }
    }

    private static Baseline LoadBaseline()
    {
        try
        {
            return File.Exists(BaselinePath) ? JsonSerializer.Deserialize<Baseline>(File.ReadAllText(BaselinePath)) ?? new Baseline(null, null) : new Baseline(null, null);
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            return new Baseline(null, null);
        }
    }

    private static void SaveBaseline(Baseline baseline)
    {
        Directory.CreateDirectory(AgamemnonPaths.MachineData);
        File.WriteAllText(BaselinePath, JsonSerializer.Serialize(baseline));
    }

    private sealed record Baseline(IReadOnlyList<string>? HostsRedirects, IReadOnlyList<string>? Exclusions);
}
