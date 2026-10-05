using System.Buffers.Binary;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;
using Agamemnon.Core.Dns;

namespace Agamemnon.Core.Ipc;

/// <summary>
/// Wire format between Agamemnon.exe and the Agamemnon service: each message is a 4-byte
/// little-endian length followed by UTF-8 JSON. Requests get exactly one response; a
/// "subscribe" request turns the connection into a one-way event stream.
/// </summary>
public static class IpcProtocol
{
    public const string PipeName = "Agamemnon.Service.v1";
    public const int MaxMessageBytes = 1 << 20;

    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static async Task WriteAsync<T>(Stream stream, T message, CancellationToken cancellationToken)
    {
        byte[] body = JsonSerializer.SerializeToUtf8Bytes(message, Json);
        if (body.Length > MaxMessageBytes)
        {
            throw new InvalidDataException("IPC message too large.");
        }

        byte[] frame = new byte[body.Length + 4];
        BinaryPrimitives.WriteInt32LittleEndian(frame, body.Length);
        body.CopyTo(frame, 4);
        await stream.WriteAsync(frame, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Returns null on a clean end of stream.</summary>
    public static async Task<T?> ReadAsync<T>(Stream stream, CancellationToken cancellationToken)
        where T : class
    {
        byte[] lengthBytes = new byte[4];
        int first = await stream.ReadAtLeastAsync(lengthBytes, 4, throwOnEndOfStream: false, cancellationToken).ConfigureAwait(false);
        if (first == 0)
        {
            return null;
        }

        if (first < 4)
        {
            throw new EndOfStreamException();
        }

        int length = BinaryPrimitives.ReadInt32LittleEndian(lengthBytes);
        if (length is <= 0 or > MaxMessageBytes)
        {
            throw new InvalidDataException("Invalid IPC frame length.");
        }

        byte[] body = new byte[length];
        await stream.ReadExactlyAsync(body, cancellationToken).ConfigureAwait(false);
        return JsonSerializer.Deserialize<T>(body, Json);
    }
}

public static class IpcMethods
{
    public const string GetDnsStatus = "dns.status";
    public const string ApplyDns = "dns.apply";
    public const string GetCurrentNetwork = "network.current";
    public const string Subscribe = "subscribe";
}

public sealed record IpcRequest(string Method, JsonElement? Params = null);

public sealed record IpcResponse(bool Ok, JsonElement? Result = null, string? Error = null);

public enum DnsMode
{
    Off,

    /// <summary>Windows' own DoH/DoT client does the encryption (Windows 11).</summary>
    Native,

    /// <summary>Agamemnon's loopback forwarder does the encryption.</summary>
    Forwarder,

    /// <summary>Turned off temporarily by a Wi-Fi rule.</summary>
    Paused,

    Error,
}

public sealed record DnsStatus
{
    public required DnsSettings Settings { get; init; }

    public DnsMode Mode { get; init; }

    public string? ServerName { get; init; }

    public string Message { get; init; } = string.Empty;

    public string? CurrentNetwork { get; init; }

    public long Queries { get; init; }

    public long Failures { get; init; }

    public string? LastError { get; init; }

    [JsonIgnore]
    public bool IsProtecting => Mode is DnsMode.Native or DnsMode.Forwarder;
}

public sealed record CurrentNetwork(string? WifiName);

public enum ServiceEventKind
{
    /// <summary>A program was started with full administrator rights.</summary>
    ElevationGranted,

    /// <summary>A new Windows service (which runs as SYSTEM) was installed.</summary>
    ServiceInstalled,

    DnsStatusChanged,
}

public sealed record ServiceEvent
{
    public required ServiceEventKind Kind { get; init; }

    public DateTimeOffset At { get; init; } = DateTimeOffset.Now;

    /// <summary>Windows session the event belongs to; apps only show their own session's alerts.</summary>
    public int? SessionId { get; init; }

    public string? ProgramPath { get; init; }

    public string? ProgramName { get; init; }

    public string? CommandLine { get; init; }

    public string? Publisher { get; init; }

    public string? SignatureState { get; init; }

    public string? ParentName { get; init; }

    public DnsStatus? Dns { get; init; }
}

/// <summary>Request/response client for the service pipe.</summary>
/// <param name="pipeName">Pipe to connect to.</param>
/// <param name="verifyServer">
/// Checks who is on the other end before anything is sent, so a program that grabbed the pipe
/// name first can't pose as the service (on Windows: the server must be a service, in session 0).
/// </param>
public sealed class IpcClient(string pipeName = IpcProtocol.PipeName, Func<NamedPipeClientStream, bool>? verifyServer = null)
{
    // Identification lets the service check who is calling (e.g. "is this an elevated admin?")
    // without being able to act as the caller, even if the server isn't who it claims to be.
    private NamedPipeClientStream Connect() =>
        new(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);

    private void Verify(NamedPipeClientStream pipe)
    {
        if (verifyServer is not null && !verifyServer(pipe))
        {
            throw new IpcException("Another program is pretending to be the Agamemnon service. Run a full scan.");
        }
    }

    public async Task<TResult> CallAsync<TResult>(string method, object? parameters, CancellationToken cancellationToken)
    {
        await using NamedPipeClientStream pipe = Connect();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(60));
        try
        {
            await pipe.ConnectAsync(2000, timeout.Token).ConfigureAwait(false);
        }
        catch (TimeoutException ex)
        {
            throw new ServiceUnavailableException(ex);
        }

        Verify(pipe);
        JsonElement? p = parameters is null ? null : JsonSerializer.SerializeToElement(parameters, IpcProtocol.Json);
        await IpcProtocol.WriteAsync(pipe, new IpcRequest(method, p), timeout.Token).ConfigureAwait(false);
        IpcResponse response = await IpcProtocol.ReadAsync<IpcResponse>(pipe, timeout.Token).ConfigureAwait(false)
            ?? throw new ServiceUnavailableException(null);
        if (!response.Ok)
        {
            throw new IpcException(response.Error ?? "The Agamemnon service reported an error.");
        }

        return response.Result is { } result
            ? result.Deserialize<TResult>(IpcProtocol.Json)!
            : default!;
    }

    /// <summary>Streams service events until cancelled or the service goes away.</summary>
    public async IAsyncEnumerable<ServiceEvent> SubscribeAsync([System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await using NamedPipeClientStream pipe = Connect();
        try
        {
            await pipe.ConnectAsync(2000, cancellationToken).ConfigureAwait(false);
        }
        catch (TimeoutException ex)
        {
            throw new ServiceUnavailableException(ex);
        }

        Verify(pipe);
        await IpcProtocol.WriteAsync(pipe, new IpcRequest(IpcMethods.Subscribe), cancellationToken).ConfigureAwait(false);
        while (await IpcProtocol.ReadAsync<ServiceEvent>(pipe, cancellationToken).ConfigureAwait(false) is { } serviceEvent)
        {
            yield return serviceEvent;
        }
    }
}

public class IpcException(string message, Exception? inner = null) : Exception(message, inner);

public sealed class ServiceUnavailableException(Exception? inner)
    : IpcException("The Agamemnon service isn't running. Reinstall Agamemnon or start the service from Services.", inner);
