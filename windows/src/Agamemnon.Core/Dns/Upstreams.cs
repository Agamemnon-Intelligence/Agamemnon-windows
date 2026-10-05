using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;

namespace Agamemnon.Core.Dns;

public interface IDnsUpstream : IAsyncDisposable
{
    string Description { get; }

    /// <summary>Sends a wire-format query and returns the wire-format response.</summary>
    Task<byte[]> QueryAsync(ReadOnlyMemory<byte> query, CancellationToken cancellationToken);
}

public static class DnsUpstreams
{
    public static IDnsUpstream Create(DnsServerConfig server) => server.Protocol switch
    {
        DnsProtocol.Https => new DohUpstream(server),
        DnsProtocol.Tls => new DotUpstream(server),
        _ => throw new ArgumentOutOfRangeException(nameof(server)),
    };

    internal static IPAddress[] ParseAddresses(IEnumerable<string> addresses) =>
        [.. addresses.Select(IPAddress.Parse).OrderBy(a => a.AddressFamily == AddressFamily.InterNetworkV6 ? 1 : 0)];

    internal static async Task<Socket> ConnectAnyAsync(IPAddress[] addresses, int port, CancellationToken cancellationToken)
    {
        Exception? last = null;
        foreach (IPAddress address in addresses)
        {
            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(TimeSpan.FromSeconds(4));
                await socket.ConnectAsync(address, port, timeout.Token).ConfigureAwait(false);
                return socket;
            }
            catch (Exception ex) when (ex is SocketException or OperationCanceledException && !cancellationToken.IsCancellationRequested)
            {
                socket.Dispose();
                last = ex;
            }
        }

        throw new IOException("Could not reach any of the DNS server's addresses.", last);
    }
}

/// <summary>
/// DNS-over-HTTPS (RFC 8484, POST). TCP connections go straight to the configured bootstrap IPs,
/// so resolving the DoH host name never touches the system resolver (which may be us).
/// </summary>
public sealed class DohUpstream : IDnsUpstream
{
    private static readonly MediaTypeHeaderValue DnsMessageType = new("application/dns-message");
    private readonly HttpClient _client;
    private readonly Uri _endpoint;

    public DohUpstream(DnsServerConfig server, HttpMessageHandler? handler = null)
    {
        _endpoint = new Uri(server.DohTemplate);
        IPAddress[] addresses = DnsUpstreams.ParseAddresses(server.Addresses);
        handler ??= new SocketsHttpHandler
        {
            PooledConnectionIdleTimeout = TimeSpan.FromMinutes(2),
            EnableMultipleHttp2Connections = true,
            UseProxy = false,
            ConnectCallback = async (context, ct) =>
            {
                Socket socket = await DnsUpstreams.ConnectAnyAsync(addresses, context.DnsEndPoint.Port, ct).ConfigureAwait(false);
                return new NetworkStream(socket, ownsSocket: true);
            },
        };
        _client = new HttpClient(handler)
        {
            DefaultRequestVersion = HttpVersion.Version20,
            DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrLower,
            Timeout = TimeSpan.FromSeconds(8),
        };
        Description = $"{server.Name} (DNS-over-HTTPS, {_endpoint.Host})";
    }

    public string Description { get; }

    public async Task<byte[]> QueryAsync(ReadOnlyMemory<byte> query, CancellationToken cancellationToken)
    {
        // RFC 8484 §4.1: use ID 0 for cache friendliness, then restore the client's ID.
        ushort id = DnsMessage.ReadId(query.Span);
        byte[] body = query.ToArray();
        DnsMessage.WriteId(body, 0);

        using var request = new HttpRequestMessage(HttpMethod.Post, _endpoint) { Content = new ByteArrayContent(body) };
        request.Content.Headers.ContentType = DnsMessageType;
        request.Headers.Accept.ParseAdd("application/dns-message");

        using HttpResponseMessage response = await _client.SendAsync(request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        byte[] answer = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        if (answer.Length < DnsMessage.HeaderLength)
        {
            throw new IOException("The DNS-over-HTTPS server returned a malformed response.");
        }

        DnsMessage.WriteId(answer, id);
        return answer;
    }

    public ValueTask DisposeAsync()
    {
        _client.Dispose();
        return ValueTask.CompletedTask;
    }
}

/// <summary>DNS-over-TLS (RFC 7858) with a small pool of persistent connections.</summary>
public sealed class DotUpstream : IDnsUpstream
{
    private const int MaxIdleConnections = 4;
    private readonly IPAddress[] _addresses;
    private readonly string _host;
    private readonly ConcurrentBag<SslStream> _idle = [];

    public DotUpstream(DnsServerConfig server)
    {
        _addresses = DnsUpstreams.ParseAddresses(server.Addresses);
        _host = server.DotHost;
        Description = $"{server.Name} (DNS-over-TLS, {_host})";
    }

    public string Description { get; }

    public async Task<byte[]> QueryAsync(ReadOnlyMemory<byte> query, CancellationToken cancellationToken)
    {
        // A pooled connection may have been closed by the server; retry once on a fresh one.
        for (int attempt = 0; ; attempt++)
        {
            bool reused = _idle.TryTake(out SslStream? stream);
            stream ??= await ConnectAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(TimeSpan.FromSeconds(8));
                byte[] answer = await ExchangeAsync(stream, query, timeout.Token).ConfigureAwait(false);
                if (_idle.Count < MaxIdleConnections)
                {
                    _idle.Add(stream);
                }
                else
                {
                    await stream.DisposeAsync().ConfigureAwait(false);
                }

                return answer;
            }
            catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException)
            {
                await stream.DisposeAsync().ConfigureAwait(false);
                if (!reused || attempt > 0 || cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
            }
        }
    }

    private static async Task<byte[]> ExchangeAsync(SslStream stream, ReadOnlyMemory<byte> query, CancellationToken cancellationToken)
    {
        byte[] frame = new byte[query.Length + 2];
        BinaryPrimitives.WriteUInt16BigEndian(frame, (ushort)query.Length);
        query.CopyTo(frame.AsMemory(2));
        await stream.WriteAsync(frame, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

        ushort id = DnsMessage.ReadId(query.Span);
        while (true)
        {
            byte[] lengthBytes = new byte[2];
            await stream.ReadExactlyAsync(lengthBytes, cancellationToken).ConfigureAwait(false);
            byte[] answer = new byte[BinaryPrimitives.ReadUInt16BigEndian(lengthBytes)];
            await stream.ReadExactlyAsync(answer, cancellationToken).ConfigureAwait(false);
            if (answer.Length >= DnsMessage.HeaderLength && DnsMessage.ReadId(answer) == id)
            {
                return answer;
            }
        }
    }

    private async Task<SslStream> ConnectAsync(CancellationToken cancellationToken)
    {
        Socket socket = await DnsUpstreams.ConnectAnyAsync(_addresses, 853, cancellationToken).ConfigureAwait(false);
        var ssl = new SslStream(new NetworkStream(socket, ownsSocket: true), leaveInnerStreamOpen: false);
        try
        {
            await ssl.AuthenticateAsClientAsync(
                new SslClientAuthenticationOptions { TargetHost = _host },
                cancellationToken).ConfigureAwait(false);
            return ssl;
        }
        catch
        {
            await ssl.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    public async ValueTask DisposeAsync()
    {
        while (_idle.TryTake(out SslStream? stream))
        {
            await stream.DisposeAsync().ConfigureAwait(false);
        }
    }
}

/// <summary>Classic UDP DNS with TCP fallback. Only used for user-excluded domains (e.g. intranet names).</summary>
public sealed class PlainUpstream(IReadOnlyList<IPEndPoint> servers) : IDnsUpstream
{
    public string Description => "Network DNS (" + string.Join(", ", servers) + ")";

    public async Task<byte[]> QueryAsync(ReadOnlyMemory<byte> query, CancellationToken cancellationToken)
    {
        if (servers.Count == 0)
        {
            throw new IOException("No network DNS servers are known for excluded domains.");
        }

        ushort id = DnsMessage.ReadId(query.Span);
        Exception? last = null;
        foreach (IPEndPoint server in servers)
        {
            try
            {
                using var udp = new UdpClient(server.AddressFamily);
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(TimeSpan.FromSeconds(3));
                await udp.SendAsync(query, server, timeout.Token).ConfigureAwait(false);
                while (true)
                {
                    UdpReceiveResult result = await udp.ReceiveAsync(timeout.Token).ConfigureAwait(false);
                    if (!result.RemoteEndPoint.Equals(server) || result.Buffer.Length < DnsMessage.HeaderLength
                        || DnsMessage.ReadId(result.Buffer) != id)
                    {
                        continue;
                    }

                    return DnsMessage.IsTruncated(result.Buffer)
                        ? await QueryTcpAsync(server, query, cancellationToken).ConfigureAwait(false)
                        : result.Buffer;
                }
            }
            catch (Exception ex) when (ex is SocketException or OperationCanceledException && !cancellationToken.IsCancellationRequested)
            {
                last = ex;
            }
        }

        throw new IOException("The network's DNS servers did not answer.", last);
    }

    private static async Task<byte[]> QueryTcpAsync(IPEndPoint server, ReadOnlyMemory<byte> query, CancellationToken cancellationToken)
    {
        using Socket socket = await DnsUpstreams.ConnectAnyAsync([server.Address], server.Port, cancellationToken).ConfigureAwait(false);
        await using var stream = new NetworkStream(socket);
        byte[] frame = new byte[query.Length + 2];
        BinaryPrimitives.WriteUInt16BigEndian(frame, (ushort)query.Length);
        query.CopyTo(frame.AsMemory(2));
        await stream.WriteAsync(frame, cancellationToken).ConfigureAwait(false);
        byte[] lengthBytes = new byte[2];
        await stream.ReadExactlyAsync(lengthBytes, cancellationToken).ConfigureAwait(false);
        byte[] answer = new byte[BinaryPrimitives.ReadUInt16BigEndian(lengthBytes)];
        await stream.ReadExactlyAsync(answer, cancellationToken).ConfigureAwait(false);
        return answer;
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}
