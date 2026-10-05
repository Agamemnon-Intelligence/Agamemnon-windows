using Agamemnon.Core.Ipc;
using Agamemnon.Platform.Windows;

namespace Agamemnon.Service;

/// <summary>Forwards administrator-rights events from <see cref="ElevationMonitor"/> to the apps.</summary>
public sealed class AlertsWorker(ILogger<AlertsWorker> logger, EventHub events) : BackgroundService
{
    private ElevationMonitor? _monitor;

    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            _monitor = new ElevationMonitor(new AuthenticodeVerifier());
            _monitor.Alert += (_, alert) =>
            {
                logger.LogInformation("{Kind}: {Program} ({Path}), publisher {Publisher}",
                    alert.Kind, alert.ProgramName, alert.ProgramPath, alert.Publisher ?? "none");
                events.Publish(alert);
            };
            _monitor.Start();
        }
        catch (Exception ex) when (ex is System.Management.ManagementException or System.Diagnostics.Eventing.Reader.EventLogException or UnauthorizedAccessException)
        {
            logger.LogError(ex, "Administrator-rights monitoring is unavailable");
        }

        return Task.CompletedTask;
    }

    public override void Dispose()
    {
        _monitor?.Dispose();
        base.Dispose();
    }
}
