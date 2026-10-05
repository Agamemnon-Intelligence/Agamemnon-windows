using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Agamemnon.Core.Scanning;

namespace Agamemnon.Core.Quarantine;

/// <summary>Wraps the store's data key at rest (DPAPI on Windows).</summary>
public interface IKeyProtector
{
    byte[] Protect(byte[] secret);

    byte[] Unprotect(byte[] protectedSecret);
}

public sealed record QuarantineItem
{
    public required string Id { get; init; }

    public required string OriginalPath { get; init; }

    public required string Sha256 { get; init; }

    public required long Size { get; init; }

    public required DateTimeOffset QuarantinedAt { get; init; }

    public required IReadOnlyList<Detection> Detections { get; init; }

    /// <summary>"Scan" or "Download".</summary>
    public string Source { get; init; } = "Scan";

    [JsonIgnore]
    public string FileName => Path.GetFileName(OriginalPath);

    [JsonIgnore]
    public string Summary => Detections.Count == 0 ? "Quarantined by you" : Detections.MaxBy(d => d.Severity)!.Name;
}

public sealed class QuarantineException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>
/// Holds quarantined files encrypted (AES-256-GCM, 1 MiB chunks) so they can't be run, opened or
/// picked up by other tools, and can be restored byte-for-byte. Each item is a pair of files:
/// <c>{id}.agq</c> (ciphertext) and <c>{id}.json</c> (metadata).
/// </summary>
public sealed class QuarantineStore
{
    private const int ChunkSize = 1 << 20;
    private const int TagSize = 16;
    private const int NonceSize = 12;
    private static readonly byte[] Magic = "AGQ1"u8.ToArray();
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly string _root;
    private readonly byte[] _key;
    private readonly Lock _gate = new();

    public QuarantineStore(string root, IKeyProtector protector)
    {
        _root = root;
        Directory.CreateDirectory(root);
        _key = LoadOrCreateKey(Path.Combine(root, "store.key"), protector);
    }

    public event EventHandler? Changed;

    public string Root => _root;

    public IReadOnlyList<QuarantineItem> List()
    {
        var items = new List<QuarantineItem>();
        foreach (string meta in Directory.EnumerateFiles(_root, "*.json"))
        {
            try
            {
                QuarantineItem? item = JsonSerializer.Deserialize<QuarantineItem>(File.ReadAllText(meta), JsonOptions);
                if (item is not null && File.Exists(DataPath(item.Id)))
                {
                    items.Add(item);
                }
            }
            catch (Exception ex) when (ex is JsonException or IOException)
            {
            }
        }

        return [.. items.OrderByDescending(i => i.QuarantinedAt)];
    }

    /// <summary>
    /// Moves <paramref name="path"/> into quarantine. The original is deleted only after the
    /// encrypted copy is safely written; if it can't be deleted, nothing is kept and this throws.
    /// </summary>
    public QuarantineItem Add(string path, IReadOnlyList<Detection> detections, string source = "Scan")
    {
        string id = Guid.NewGuid().ToString("N");
        string data = DataPath(id);
        string fullPath = Path.GetFullPath(path);
        string sha256;
        long size;
        try
        {
            // Deny writers while we copy, so the bytes we keep are the bytes we delete.
            using (var input = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete, 1, FileOptions.SequentialScan))
            using (var output = new FileStream(data, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                (sha256, size) = Encrypt(input, output, id);
                output.Flush(flushToDisk: true);
            }

            File.Delete(fullPath);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            TryDelete(data);
            throw new QuarantineException(ex is UnauthorizedAccessException
                ? $"Windows wouldn't let Agamemnon move “{Path.GetFileName(fullPath)}”. It may need administrator rights."
                : $"Couldn't move “{Path.GetFileName(fullPath)}”: {ex.Message}", ex);
        }

        var item = new QuarantineItem
        {
            Id = id,
            OriginalPath = fullPath,
            Sha256 = sha256,
            Size = size,
            QuarantinedAt = DateTimeOffset.Now,
            Detections = detections,
            Source = source,
        };
        lock (_gate)
        {
            File.WriteAllText(MetaPath(id), JsonSerializer.Serialize(item, JsonOptions));
        }

        Changed?.Invoke(this, EventArgs.Empty);
        return item;
    }

    /// <summary>Decrypts an item back to disk and removes it from quarantine. Returns the restored path.</summary>
    public string Restore(string id, string? destination = null)
    {
        QuarantineItem item = Get(id);
        string target = destination ?? item.OriginalPath;
        target = FreePath(target);
        Directory.CreateDirectory(Path.GetDirectoryName(target)!);
        string partial = target + ".agamemnon-restoring";
        try
        {
            using (var input = File.OpenRead(DataPath(id)))
            using (var output = new FileStream(partial, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                string sha256 = Decrypt(input, output, id);
                if (!string.Equals(sha256, item.Sha256, StringComparison.OrdinalIgnoreCase))
                {
                    throw new QuarantineException("The quarantined copy is damaged and can't be restored.");
                }
            }

            File.Move(partial, target);
        }
        catch
        {
            TryDelete(partial);
            throw;
        }

        Delete(id);
        return target;
    }

    public void Delete(string id)
    {
        ValidateId(id);
        lock (_gate)
        {
            TryDelete(DataPath(id));
            TryDelete(MetaPath(id));
        }

        Changed?.Invoke(this, EventArgs.Empty);
    }

    public QuarantineItem Get(string id)
    {
        ValidateId(id);
        string meta = MetaPath(id);
        if (!File.Exists(meta) || !File.Exists(DataPath(id)))
        {
            throw new QuarantineException("That item is no longer in quarantine.");
        }

        return JsonSerializer.Deserialize<QuarantineItem>(File.ReadAllText(meta), JsonOptions)
            ?? throw new QuarantineException("Quarantine record is damaged.");
    }

    private (string Sha256, long Size) Encrypt(Stream input, Stream output, string id)
    {
        using var aes = new AesGcm(_key, TagSize);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] baseNonce = RandomNumberGenerator.GetBytes(NonceSize);
        output.Write(Magic);
        output.Write(baseNonce);

        byte[] plain = new byte[ChunkSize];
        byte[] next = new byte[ChunkSize];
        byte[] cipher = new byte[ChunkSize];
        byte[] tag = new byte[TagSize];
        byte[] lengthBytes = new byte[4];
        int length = input.ReadAtLeast(plain, ChunkSize, throwOnEndOfStream: false);
        long total = 0;
        for (long index = 0; ; index++)
        {
            int nextLength = length == ChunkSize ? input.ReadAtLeast(next, ChunkSize, throwOnEndOfStream: false) : 0;
            bool final = nextLength == 0;
            hash.AppendData(plain, 0, length);
            total += length;
            aes.Encrypt(ChunkNonce(baseNonce, index), plain.AsSpan(0, length), cipher.AsSpan(0, length), tag, Aad(id, index, final));
            BinaryPrimitives.WriteInt32LittleEndian(lengthBytes, length);
            output.Write(lengthBytes);
            output.Write(cipher, 0, length);
            output.Write(tag);
            if (final)
            {
                break;
            }

            (plain, next) = (next, plain);
            length = nextLength;
        }

        return (Convert.ToHexStringLower(hash.GetHashAndReset()), total);
    }

    private string Decrypt(Stream input, Stream output, string id)
    {
        using var aes = new AesGcm(_key, TagSize);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] header = new byte[Magic.Length + NonceSize];
        input.ReadExactly(header);
        if (!header.AsSpan(0, Magic.Length).SequenceEqual(Magic))
        {
            throw new QuarantineException("Not an Agamemnon quarantine file.");
        }

        byte[] baseNonce = header[Magic.Length..];
        byte[] cipher = new byte[ChunkSize];
        byte[] plain = new byte[ChunkSize];
        byte[] tag = new byte[TagSize];
        byte[] lengthBytes = new byte[4];
        for (long index = 0; ; index++)
        {
            input.ReadExactly(lengthBytes);
            int length = BinaryPrimitives.ReadInt32LittleEndian(lengthBytes);
            if (length is < 0 or > ChunkSize)
            {
                throw new QuarantineException("Quarantine file is corrupt.");
            }

            input.ReadExactly(cipher, 0, length);
            input.ReadExactly(tag);
            bool final = input.Position == input.Length;
            try
            {
                aes.Decrypt(ChunkNonce(baseNonce, index), cipher.AsSpan(0, length), tag, plain.AsSpan(0, length), Aad(id, index, final));
            }
            catch (AuthenticationTagMismatchException ex)
            {
                throw new QuarantineException("The quarantined copy is damaged and can't be restored.", ex);
            }

            hash.AppendData(plain, 0, length);
            output.Write(plain, 0, length);
            if (final)
            {
                break;
            }
        }

        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }

    private static byte[] ChunkNonce(byte[] baseNonce, long index)
    {
        byte[] nonce = (byte[])baseNonce.Clone();
        long counter = BinaryPrimitives.ReadInt64LittleEndian(nonce.AsSpan(4)) ^ index;
        BinaryPrimitives.WriteInt64LittleEndian(nonce.AsSpan(4), counter);
        return nonce;
    }

    /// <summary>Binds each chunk to its item, position and finality so chunks can't be reordered, swapped or truncated.</summary>
    private static byte[] Aad(string id, long index, bool final)
    {
        byte[] aad = new byte[32 + 8 + 1];
        System.Text.Encoding.ASCII.GetBytes(id, aad);
        BinaryPrimitives.WriteInt64LittleEndian(aad.AsSpan(32), index);
        aad[40] = final ? (byte)1 : (byte)0;
        return aad;
    }

    private static byte[] LoadOrCreateKey(string keyFile, IKeyProtector protector)
    {
        if (File.Exists(keyFile))
        {
            return protector.Unprotect(File.ReadAllBytes(keyFile));
        }

        byte[] key = RandomNumberGenerator.GetBytes(32);
        File.WriteAllBytes(keyFile, protector.Protect(key));
        return key;
    }

    private static string FreePath(string path)
    {
        if (!File.Exists(path))
        {
            return path;
        }

        string directory = Path.GetDirectoryName(path)!;
        string name = Path.GetFileNameWithoutExtension(path);
        string ext = Path.GetExtension(path);
        for (int n = 1; ; n++)
        {
            string candidate = Path.Combine(directory, $"{name} (restored{(n == 1 ? string.Empty : " " + n)}){ext}");
            if (!File.Exists(candidate))
            {
                return candidate;
            }
        }
    }

    private static void ValidateId(string id)
    {
        if (id.Length != 32 || !id.All(char.IsAsciiHexDigitLower))
        {
            throw new QuarantineException("Invalid quarantine item.");
        }
    }

    private string DataPath(string id) => Path.Combine(_root, id + ".agq");

    private string MetaPath(string id) => Path.Combine(_root, id + ".json");

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
