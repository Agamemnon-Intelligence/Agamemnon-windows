using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace Agamemnon.Core.Dns;

/// <summary>
/// A loopback DNS stub that forwards every query over an encrypted upstream. Used where Windows
/// cannot do the job natively (DNS-over-TLS on builds without it, DNS-over-HTTPS on Windows 10).
/// Fails closed: if the encrypted upstream is unreachable the client gets SERVFAIL, never a
/// plaintext fallback. Only domains the user explicitly excluded go to the network's DNS.
/// </summary>
public sealed class DnsForwarder : IAsyncDisposable
{
    private readonly IDnsUpstream _encrypted;
    private readonly IDnsUpstream? _excludedUpstream;
    private readonly IReadOnlyCollection<string> _excludedDomains;
    private readonly IReadOnlyList<IPEndPoint> _listenOn;
    private readonly List<Socket> _sockets = [];
    private readonly CancellationTokenSource _stop = new();
    private readonly List<Task> _loops = [];
    private readonly SemaphoreSlim _concurrency = new(256);
    private long _queries;
    private long _failures;
    private long _lastSuccessTicks;
    private string? _lastError;

    public DnsForwarder(
        IDnsUpstream encrypted,
        IReadOnlyCollection<string> excludedDomains,
        IDnsUpstream? excludedUpstream,
        IReadOnlyList<IPEndPoint>? listenOn = null)
    {
        _encrypted = encrypted;
        _excludedDomains = excludedDomains;
        _excludedUpstream = excludedUpstream;
        _listenOn = listenOn ?? [new IPEndPoint(IPAddress.Loopback, 53), new IPEndPoint(IPAddress.IPv6Loopback, 53)];
    }

    /// <summary>The endpoints actually bound (useful when listening on port 0 in tests).</summary>
    public IReadOnlyList<IPEndPoint> BoundUdpEndpoints { get; private set; } = [];

    public IReadOnlyList<IPEndPoint> BoundTcpEndpoints { get; private set; } = [];

    public DnsForwarderStats Stats => new(
        Interlocked.Read(ref _queries),
        Interlocked.Read(ref _failures),
        Interlocked.Read(ref _lastSuccessTicks) is var t and > 0 ? new DateTimeOffset(t, TimeSpan.Zero) : null,
        Volatile.Read(ref _lastError));

    public void Start()
    {
        var udp = new List<IPEndPoint>();
        var tcp = new List<IPEndPoint>();
        foreach (IPEndPoint endpoint in _listenOn)
        {
            if (endpoint.AddressFamily == AddressFamily.InterNetworkV6 && !Socket.OSSupportsIPv6)
            {
                continue;
            }

            var udpSocket = new Socket(endpoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            var tcpSocket = new Socket(endpoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                // Exclusive bind so no other local process can hijack the port underneath us.
                udpSocket.ExclusiveAddressUse = true;
                tcpSocket.ExclusiveAddressUse = true;
                udpSocket.Bind(endpoint);
                var tcpEndpoint = new IPEndPoint(endpoint.Address, ((IPEndPoint)udpSocket.LocalEndPoint!).Port);
                tcpSocket.Bind(tcpEndpoint);
                tcpSocket.Listen(64);
            }
            catch (SocketException ex)
            {
                udpSocket.Dispose();
                tcpSocket.Dispose();
                foreach (Socket s in _sockets)
                {
                    s.Dispose();
                }

                throw new IOException($"Could not listen on {endpoint}: {ex.Message}. Another DNS service may be using port 53.", ex);
            }

            _sockets.Add(udpSocket);
            _sockets.Add(tcpSocket);
            udp.Add((IPEndPoint)udpSocket.LocalEndPoint!);
            tcp.Add((IPEndPoint)tcpSocket.LocalEndPoint!);
            _loops.Add(Task.Run(() => UdpLoopAsync(udpSocket)));
            _loops.Add(Task.Run(() => TcpLoopAsync(tcpSocket)));
        }

        BoundUdpEndpoints = udp;
        BoundTcpEndpoints = tcp;
    }

    /// <summary>Resolves one query exactly as a client of the forwarder would see it.</summary>
    public async Task<byte[]> ResolveAsync(ReadOnlyMemory<byte> query, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _queries);
        if (!DnsMessage.TryReadQuestion(query.Span, out string name, out _, out _))
        {
            Interlocked.Increment(ref _failures);
            return DnsMessage.ServerFailure(query.Span);
        }

        IDnsUpstream upstream = _excludedUpstream is not null && DnsValidation.IsExcluded(name, _excludedDomains)
            ? _excludedUpstream
            : _encrypted;
        try
        {
            byte[] answer = await upstream.QueryAsync(query, cancellationToken).ConfigureAwait(false);
            Interlocked.Exchange(ref _lastSuccessTicks, DateTimeOffset.UtcNow.UtcTicks);
            return answer;
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            Interlocked.Increment(ref _failures);
            Volatile.Write(ref _lastError, $"{upstream.Description}: {ex.Message}");
            return DnsMessage.ServerFailure(query.Span);
        }
    }

    private async Task UdpLoopAsync(Socket socket)
    {
        byte[] buffer = new byte[4096];
        EndPoint any = new IPEndPoint(socket.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0);
        while (!_stop.IsCancellationRequested)
        {
            SocketReceiveFromResult received;
            try
            {
                received = await socket.ReceiveFromAsync(buffer, SocketFlags.None, any, _stop.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (SocketException)
            {
                continue; // e.g. ICMP port unreachable surfaced as ConnectionReset on Windows
            }
            catch (ObjectDisposedException)
            {
                return;
            }

            if (received.ReceivedBytes < DnsMessage.HeaderLength)
            {
                continue;
            }

            byte[] query = buffer.AsSpan(0, received.ReceivedBytes).ToArray();
            EndPoint client = received.RemoteEndPoint;
            if (!await _concurrency.WaitAsync(0).ConfigureAwait(false))
            {
                continue; // overloaded: drop, the client will retry
            }

            _ = Task.Run(async () =>
            {
                try
                {
                    byte[] answer = await ResolveAsync(query, _stop.Token).ConfigureAwait(false);
                    answer = TruncateForUdp(query, answer);
                    await socket.SendToAsync(answer, SocketFlags.None, client, _stop.Token).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is OperationCanceledException or SocketException or ObjectDisposedException)
                {
                }
                finally
                {
                    _concurrency.Release();
                }
            });
        }
    }

    private async Task TcpLoopAsync(Socket listener)
    {
        while (!_stop.IsCancellationRequested)
        {
            Socket client;
            try
            {
                client = await listener.AcceptAsync(_stop.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException)
            {
                return;
            }
            catch (SocketException)
            {
                continue;
            }

            _ = Task.Run(() => ServeTcpClientAsync(client));
        }
    }

    private async Task ServeTcpClientAsync(Socket client)
    {
        using (client)
        await using (var stream = new NetworkStream(client))
        {
            try
            {
                byte[] lengthBytes = new byte[2];
                while (!_stop.IsCancellationRequested)
                {
                    using var idle = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
                    idle.CancelAfter(TimeSpan.FromSeconds(10));
                    await stream.ReadExactlyAsync(lengthBytes, idle.Token).ConfigureAwait(false);
                    byte[] query = new byte[BinaryPrimitives.ReadUInt16BigEndian(lengthBytes)];
                    await stream.ReadExactlyAsync(query, idle.Token).ConfigureAwait(false);
                    byte[] answer = await ResolveAsync(query, _stop.Token).ConfigureAwait(false);
                    byte[] frame = new byte[answer.Length + 2];
                    BinaryPrimitives.WriteUInt16BigEndian(frame, (ushort)answer.Length);
                    answer.CopyTo(frame, 2);
                    await stream.WriteAsync(frame, _stop.Token).ConfigureAwait(false);
                }
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException or SocketException or EndOfStreamException)
            {
            }
        }
    }

    /// <summary>Answers larger than the client's UDP limit are replaced by a truncated header so it retries over TCP.</summary>
    internal static byte[] TruncateForUdp(ReadOnlySpan<byte> query, byte[] answer)
    {
        int limit = 512;
        if (TryReadEdnsPayloadSize(query, out int ednsSize))
        {
            limit = Math.Clamp(ednsSize, 512, 4096);
        }

        if (answer.Length <= limit)
        {
            return answer;
        }

        byte[] truncated = DnsMessage.ServerFailure(query);
        truncated[2] |= 0x02; // TC
        truncated[3] = (byte)(truncated[3] & 0xF0); // RCODE NOERROR
        return truncated;
    }

    private static bool TryReadEdnsPayloadSize(ReadOnlySpan<byte> query, out int size)
    {
        size = 0;
        if (!DnsMessage.TryReadQuestion(query, out _, out _, out int offset)
            || BinaryPrimitives.ReadUInt16BigEndian(query[6..]) != 0
            || BinaryPrimitives.ReadUInt16BigEndian(query[8..]) != 0
            || BinaryPrimitives.ReadUInt16BigEndian(query[10..]) == 0)
        {
            return false;
        }

        // OPT RR: root name (0), TYPE 41, CLASS = UDP payload size.
        if (offset + 5 <= query.Length && query[offset] == 0
            && BinaryPrimitives.ReadUInt16BigEndian(query[(offset + 1)..]) == 41)
        {
            size = BinaryPrimitives.ReadUInt16BigEndian(query[(offset + 3)..]);
            return true;
        }

        return false;
    }

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync().ConfigureAwait(false);
        foreach (Socket socket in _sockets)
        {
            socket.Dispose();
        }

        try
        {
            await Task.WhenAll(_loops).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }

        await _encrypted.DisposeAsync().ConfigureAwait(false);
        if (_excludedUpstream is not null)
        {
            await _excludedUpstream.DisposeAsync().ConfigureAwait(false);
        }

        _stop.Dispose();
    }
}

public sealed record DnsForwarderStats(long Queries, long Failures, DateTimeOffset? LastSuccess, string? LastError);
