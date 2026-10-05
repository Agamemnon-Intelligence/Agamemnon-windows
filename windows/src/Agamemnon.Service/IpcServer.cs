using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Threading.Channels;
using Agamemnon.Core.Dns;
using Agamemnon.Core.Ipc;

namespace Agamemnon.Service;

/// <summary>Fan-out of service events to every subscribed app instance.</summary>
public sealed class EventHub
{
    private readonly Lock _gate = new();
    private readonly List<(int SessionId, Channel<ServiceEvent> Channel)> _subscribers = [];

    public void Publish(ServiceEvent serviceEvent)
    {
        lock (_gate)
        {
            foreach ((int session, Channel<ServiceEvent> channel) in _subscribers)
            {
                // Alerts about one user's desktop are only shown on that desktop.
                if (serviceEvent.SessionId is null || serviceEvent.SessionId == session)
                {
                    channel.Writer.TryWrite(serviceEvent);
                }
            }
        }
    }

    public ChannelReader<ServiceEvent> Subscribe(int sessionId, out Action unsubscribe)
    {
        var channel = Channel.CreateBounded<ServiceEvent>(new BoundedChannelOptions(64) { FullMode = BoundedChannelFullMode.DropOldest });
        var entry = (sessionId, channel);
        lock (_gate)
        {
            _subscribers.Add(entry);
        }

        unsubscribe = () =>
        {
            lock (_gate)
            {
                _subscribers.Remove(entry);
            }

            channel.Writer.TryComplete();
        };
        return channel.Reader;
    }
}

/// <summary>
/// Named-pipe endpoint for Agamemnon.exe. Local, authenticated users only (remote/network logons
/// are denied by the pipe's ACL). Custom DNS servers can redirect every lookup on the PC, so they
/// require an elevated administrator; presets can be chosen by any signed-in user.
/// </summary>
public sealed partial class IpcServer(ILogger<IpcServer> logger, DnsController dns, EventHub events) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            NamedPipeServerStream pipe = NamedPipeServerStreamAcl.Create(
                IpcProtocol.PipeName,
                PipeDirection.InOut,
                NamedPipeServerStream.MaxAllowedServerInstances,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous,
                inBufferSize: 0,
                outBufferSize: 0,
                CreateSecurity());
            try
            {
                await pipe.WaitForConnectionAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                await pipe.DisposeAsync().ConfigureAwait(false);
                return;
            }

            _ = Task.Run(() => ServeAsync(pipe, stoppingToken), stoppingToken);
        }
    }

    private static PipeSecurity CreateSecurity()
    {
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));
        return security;
    }

    private async Task ServeAsync(NamedPipeServerStream pipe, CancellationToken stoppingToken)
    {
        await using (pipe)
        {
            try
            {
                using var requestTimeout = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                requestTimeout.CancelAfter(TimeSpan.FromSeconds(10));
                IpcRequest? request = await IpcProtocol.ReadAsync<IpcRequest>(pipe, requestTimeout.Token).ConfigureAwait(false);
                if (request is null)
                {
                    return;
                }

                if (request.Method == IpcMethods.Subscribe)
                {
                    await StreamEventsAsync(pipe, stoppingToken).ConfigureAwait(false);
                    return;
                }

                IpcResponse response;
                try
                {
                    object? result = await HandleAsync(pipe, request, stoppingToken).ConfigureAwait(false);
                    response = new IpcResponse(true, result is null ? null : JsonSerializer.SerializeToElement(result, IpcProtocol.Json));
                }
                catch (Exception ex) when (ex is IpcException or DnsConfigurationException or JsonException or UnauthorizedAccessException)
                {
                    response = new IpcResponse(false, Error: ex.Message);
                }

                await IpcProtocol.WriteAsync(pipe, response, stoppingToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException or InvalidDataException or JsonException)
            {
                logger.LogDebug(ex, "IPC client disconnected");
            }
        }
    }

    private async Task<object?> HandleAsync(NamedPipeServerStream pipe, IpcRequest request, CancellationToken cancellationToken)
    {
        switch (request.Method)
        {
            case IpcMethods.GetDnsStatus:
                return dns.Status;

            case IpcMethods.GetCurrentNetwork:
                return new CurrentNetwork(DnsController.CurrentWifi());

            case IpcMethods.ApplyDns:
                DnsSettings settings = request.Params?.Deserialize<DnsSettings>(IpcProtocol.Json)
                    ?? throw new IpcException("Missing DNS settings.");
                if (settings.Enabled && settings.IsCustom && !CallerIsElevatedAdministrator(pipe))
                {
                    throw new UnauthorizedAccessException("Using a custom DNS server needs administrator approval.");
                }

                return await dns.ApplyAsync(settings, cancellationToken).ConfigureAwait(false);

            default:
                throw new IpcException($"Unknown request '{request.Method}'.");
        }
    }

    private static bool CallerIsElevatedAdministrator(NamedPipeServerStream pipe)
    {
        bool elevated = false;
        pipe.RunAsClient(() =>
        {
            using WindowsIdentity identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
            elevated = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        });
        return elevated;
    }

    private async Task StreamEventsAsync(NamedPipeServerStream pipe, CancellationToken stoppingToken)
    {
        if (!GetNamedPipeClientSessionId(pipe.SafePipeHandle, out uint sessionId))
        {
            return;
        }

        ChannelReader<ServiceEvent> reader = events.Subscribe((int)sessionId, out Action unsubscribe);
        try
        {
            // Send the current DNS state straight away so the tray icon is right from the start.
            await IpcProtocol.WriteAsync(pipe, new ServiceEvent { Kind = ServiceEventKind.DnsStatusChanged, Dns = dns.Status }, stoppingToken).ConfigureAwait(false);
            await foreach (ServiceEvent serviceEvent in reader.ReadAllAsync(stoppingToken).ConfigureAwait(false))
            {
                await IpcProtocol.WriteAsync(pipe, serviceEvent, stoppingToken).ConfigureAwait(false);
            }
        }
        finally
        {
            unsubscribe();
        }
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeClientSessionId(Microsoft.Win32.SafeHandles.SafePipeHandle pipe, out uint sessionId);
}
