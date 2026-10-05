using Agamemnon.Core.Downloads;
using Agamemnon.Core.Quarantine;
using Agamemnon.Core.Scanning;
using Agamemnon.Core.Settings;

namespace Agamemnon.App.Services;

/// <summary>
/// Blocks unsafe downloads: every file that lands in a watched folder is scanned as soon as the
/// browser finishes writing it. Threats are quarantined immediately; unsigned programs from the
/// internet are quarantined or flagged depending on the user's policy.
/// </summary>
public sealed class DownloadGuard(AppServices services, Notifier notifier) : IDisposable
{
    private readonly SemaphoreSlim _scanSlots = new(2);
    private DownloadWatcher? _watcher;

    public event EventHandler? StateChanged;

    public bool IsRunning => _watcher is not null;

    public int CheckedToday { get; private set; }

    public static string DefaultDownloadsFolder => KnownFolders.Downloads;

    public IReadOnlyList<string> WatchedFolders =>
        [DefaultDownloadsFolder, .. services.Settings.ExtraDownloadFolders.Where(f => !f.Equals(DefaultDownloadsFolder, StringComparison.OrdinalIgnoreCase))];

    public void Restart()
    {
        _watcher?.Dispose();
        _watcher = null;
        if (services.Settings.DownloadProtection)
        {
            _watcher = new DownloadWatcher(WatchedFolders);
            _watcher.FileReady += (_, path) => _ = HandleAsync(path);
            _watcher.Start();
        }

        StateChanged?.Invoke(this, EventArgs.Empty);
    }

    private async Task HandleAsync(string path)
    {
        await _scanSlots.WaitAsync().ConfigureAwait(false);
        try
        {
            var scanner = services.CreateScanner(forDownloads: true);
            var (result, _, _) = await scanner.ScanFileAsync(path, services.CreateScanOptions(), CancellationToken.None).ConfigureAwait(false);
            CheckedToday++;
            Act(path, result);
            StateChanged?.Invoke(this, EventArgs.Empty);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // The file was moved or deleted before we got to it.
        }
        finally
        {
            _scanSlots.Release();
        }
    }

    private void Act(string path, FileScanResult result)
    {
        string name = Path.GetFileName(path);
        Detection? worst = result.Detections.MaxBy(d => d.Severity);
        bool unsignedFromInternet = result.Detections.Any(d => d.Engine == "Code signature" && d.Name.StartsWith("Unsigned", StringComparison.Ordinal)
                                                               && d.Severity == Severity.Suspicious);
        bool block = result.Verdict == Severity.Malicious
                     || (result.Verdict == Severity.Suspicious && !(unsignedFromInternet && OnlyUnsignedFinding(result)))
                     || (unsignedFromInternet && services.Settings.UnsignedDownloads == UnsignedDownloadPolicy.Block);

        if (worst is null || worst.Severity == Severity.Info)
        {
            services.Activity.Add(new ActivityEntry(DateTimeOffset.Now, ActivityKind.Download, ActivityLevel.Good, $"{name} looks safe",
                result.Errors.Count > 0 ? string.Join(" ", result.Errors) : null));
            return;
        }

        if (block)
        {
            try
            {
                services.Quarantine.Add(path, result.Detections, "Download");
                services.Activity.Add(new ActivityEntry(DateTimeOffset.Now, ActivityKind.Download, ActivityLevel.Threat,
                    $"Blocked {name}", $"{worst.Name} ({worst.Engine}). Moved to quarantine."));
                notifier.Show(NotificationLevel.Threat, $"Blocked unsafe download: {name}",
                    $"{worst.Name}. It's in quarantine, so it can't run.", NavigationTarget.Quarantine);
            }
            catch (QuarantineException ex)
            {
                services.Activity.Add(new ActivityEntry(DateTimeOffset.Now, ActivityKind.Download, ActivityLevel.Threat,
                    $"Unsafe download: {name}", $"{worst.Name}. {ex.Message}"));
                notifier.Show(NotificationLevel.Threat, $"Unsafe download: {name}", $"{worst.Name}. Delete it, don't open it.", NavigationTarget.Downloads);
            }

            return;
        }

        services.Activity.Add(new ActivityEntry(DateTimeOffset.Now, ActivityKind.Download, ActivityLevel.Warning,
            $"Check before opening: {name}", $"{worst.Name}. {worst.Detail}"));
        notifier.Show(NotificationLevel.Warning, $"Check before opening: {name}", worst.Detail ?? worst.Name, NavigationTarget.Downloads);
    }

    private static bool OnlyUnsignedFinding(FileScanResult result) =>
        result.Detections.Where(d => d.Severity >= Severity.Suspicious).All(d => d.Engine == "Code signature" && d.Name.StartsWith("Unsigned", StringComparison.Ordinal));

    public void Dispose()
    {
        _watcher?.Dispose();
        _scanSlots.Dispose();
    }
}
