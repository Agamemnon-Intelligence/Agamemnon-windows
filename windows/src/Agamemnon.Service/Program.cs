using Agamemnon.Platform.Windows;
using Agamemnon.Service;

// Agamemnon.Service.exe                      → "Agamemnon" service (LocalSystem)
// Agamemnon.Service.exe --role scan-engine   → "AgamemnonScanEngine" service (LocalService)
// Agamemnon.Service.exe --restore-dns        → undo all DNS changes and exit (run by the uninstaller)
if (args.Contains("--restore-dns"))
{
    using var configurator = new WindowsDnsConfigurator(AgamemnonPaths.MachineData);
    try
    {
        await configurator.RestoreAsync(CancellationToken.None);
        return 0;
    }
    catch (Exception ex) when (ex is Agamemnon.Core.Dns.DnsConfigurationException or IOException)
    {
        Console.Error.WriteLine(ex.Message);
        return 1;
    }
}

bool scanEngine = args.SkipWhile(a => a != "--role").Skip(1).FirstOrDefault() == "scan-engine";

HostApplicationBuilder builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = scanEngine ? "AgamemnonScanEngine" : "Agamemnon");
builder.Logging.AddEventLog(settings => settings.SourceName = "Agamemnon");

if (scanEngine)
{
    builder.Services.AddHostedService<ScanEngineHost>();
}
else
{
    builder.Services.AddSingleton<EventHub>();
    builder.Services.AddSingleton<DnsController>();
    builder.Services.AddHostedService(sp => sp.GetRequiredService<DnsController>());
    builder.Services.AddHostedService<IpcServer>();
    builder.Services.AddHostedService<AlertsWorker>();
}

await builder.Build().RunAsync();
return 0;
