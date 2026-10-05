using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Agamemnon.Core.Scanning;

/// <summary>
/// Signature scanning through ClamAV's clamd daemon. Files are streamed with INSTREAM, so clamd
/// (which runs as a low-privilege service) never opens user files itself, and only files the
/// scanning user can read get scanned.
/// </summary>
public sealed class ClamAvEngine(IPEndPoint endpoint) : IScanEngine
{
    private const int ChunkSize = 64 * 1024;

    public ClamAvEngine()
        : this(new IPEndPoint(IPAddress.Loopback, 3310))
    {
    }

    public string Name => "ClamAV";

    public async Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken)
    {
        try
        {
            string version = await CommandAsync("zVERSION", cancellationToken).ConfigureAwait(false);
            ClamAvVersion? parsed = ClamAvVersion.Parse(version);
            return parsed is null
                ? new EngineStatus(true, version)
                : new EngineStatus(true, $"ClamAV {parsed.Engine}, signatures {parsed.DatabaseVersion} ({parsed.DatabaseDate})");
        }
        catch (Exception ex) when (ex is SocketException or IOException or OperationCanceledException && !cancellationToken.IsCancellationRequested)
        {
            return new EngineStatus(false, "ClamAV scan engine service isn't running.");
        }
    }

    public async Task<ClamAvVersion?> GetVersionAsync(CancellationToken cancellationToken)
    {
        try
        {
            return ClamAvVersion.Parse(await CommandAsync("zVERSION", cancellationToken).ConfigureAwait(false));
        }
        catch (Exception ex) when (ex is SocketException or IOException)
        {
            return null;
        }
    }

    public async Task<IReadOnlyList<EngineResult>> ScanAsync(IReadOnlyList<ScanTarget> batch, CancellationToken cancellationToken)
    {
        var results = new EngineResult[batch.Count];
        for (int i = 0; i < batch.Count; i++)
        {
            FileStream file;
            try
            {
                file = new FileStream(batch[i].Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, ChunkSize, FileOptions.SequentialScan | FileOptions.Asynchronous);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                results[i] = EngineResult.Failed(ex.Message);
                continue;
            }

            await using (file)
            {
                string reply = await InstreamAsync(file, cancellationToken).ConfigureAwait(false);
                try
                {
                    results[i] = new EngineResult(ParseReply(reply));
                }
                catch (EngineException ex)
                {
                    results[i] = EngineResult.Failed(ex.Message);
                }
            }
        }

        return results;
    }

    internal async Task<string> InstreamAsync(Stream content, CancellationToken cancellationToken)
    {
        using Socket socket = await ConnectAsync(cancellationToken).ConfigureAwait(false);
        await using var stream = new NetworkStream(socket);
        await stream.WriteAsync("zINSTREAM\0"u8.ToArray(), cancellationToken).ConfigureAwait(false);

        byte[] buffer = new byte[ChunkSize + 4];
        int read;
        while ((read = await content.ReadAsync(buffer.AsMemory(4, ChunkSize), cancellationToken).ConfigureAwait(false)) > 0)
        {
            BinaryPrimitives.WriteUInt32BigEndian(buffer, (uint)read);
            try
            {
                await stream.WriteAsync(buffer.AsMemory(0, read + 4), cancellationToken).ConfigureAwait(false);
            }
            catch (IOException)
            {
                // clamd closes the connection once StreamMaxLength is exceeded; its reply explains why.
                break;
            }
        }

        try
        {
            await stream.WriteAsync(new byte[4], cancellationToken).ConfigureAwait(false);
        }
        catch (IOException)
        {
        }

        return await ReadReplyAsync(stream, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Parses "stream: OK", "stream: Win.Trojan.Agent-1 FOUND", "INSTREAM size limit exceeded. ERROR".</summary>
    internal static IReadOnlyList<Detection> ParseReply(string reply)
    {
        string text = reply.TrimEnd('\0', '\n', ' ');
        if (text.EndsWith(" FOUND", StringComparison.Ordinal))
        {
            int colon = text.IndexOf(": ", StringComparison.Ordinal);
            string signature = text[(colon >= 0 ? colon + 2 : 0)..^" FOUND".Length].Trim();
            Severity severity = signature.StartsWith("Heuristics.", StringComparison.Ordinal)
                || signature.StartsWith("PUA.", StringComparison.Ordinal)
                ? Severity.Suspicious
                : Severity.Malicious;
            return [new Detection("ClamAV", signature, severity)];
        }

        if (text.EndsWith(": OK", StringComparison.Ordinal) || text == "OK")
        {
            return [];
        }

        if (text.Contains("size limit exceeded", StringComparison.OrdinalIgnoreCase))
        {
            throw new EngineException("File is larger than ClamAV's stream limit, so it was only partly scanned.");
        }

        throw new EngineException($"ClamAV error: {text}");
    }

    private async Task<string> CommandAsync(string command, CancellationToken cancellationToken)
    {
        using Socket socket = await ConnectAsync(cancellationToken).ConfigureAwait(false);
        await using var stream = new NetworkStream(socket);
        await stream.WriteAsync(Encoding.ASCII.GetBytes(command + "\0"), cancellationToken).ConfigureAwait(false);
        return await ReadReplyAsync(stream, cancellationToken).ConfigureAwait(false);
    }

    private async Task<Socket> ConnectAsync(CancellationToken cancellationToken)
    {
        var socket = new Socket(endpoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(3));
            await socket.ConnectAsync(endpoint, timeout.Token).ConfigureAwait(false);
            return socket;
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    private static async Task<string> ReadReplyAsync(Stream stream, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromMinutes(5));
        using var reply = new MemoryStream();
        byte[] buffer = new byte[1024];
        int read;
        while ((read = await stream.ReadAsync(buffer, timeout.Token).ConfigureAwait(false)) > 0)
        {
            int nul = Array.IndexOf(buffer, (byte)0, 0, read);
            reply.Write(buffer, 0, nul >= 0 ? nul : read);
            if (nul >= 0 || reply.Length > 64 * 1024)
            {
                break;
            }
        }

        return Encoding.UTF8.GetString(reply.ToArray());
    }
}

/// <summary>Parsed "ClamAV 1.4.3/27788/Sun Oct  5 08:24:01 2026".</summary>
public sealed record ClamAvVersion(string Engine, int DatabaseVersion, string DatabaseDate)
{
    public static ClamAvVersion? Parse(string text)
    {
        string[] parts = text.Trim('\0', '\n', ' ').Split('/');
        if (parts.Length < 3 || !parts[0].StartsWith("ClamAV ", StringComparison.Ordinal)
            || !int.TryParse(parts[1], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int db))
        {
            return null;
        }

        return new ClamAvVersion(parts[0]["ClamAV ".Length..], db, string.Join(' ', parts[2].Split(' ', StringSplitOptions.RemoveEmptyEntries)));
    }
}
