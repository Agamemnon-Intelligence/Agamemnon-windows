using System.Buffers.Binary;
using System.Globalization;
using System.IO.MemoryMappedFiles;

namespace Agamemnon.Core.Intelligence;

public enum HashKind
{
    Md5 = 1,
    Sha256 = 2,
}

/// <summary>
/// Turns hex hashes into the 64-bit keys stored in a <see cref="HashDatabase"/>: the first eight
/// bytes of the hash, big-endian. Malware hashes are uniformly distributed, so with 50 million
/// entries the chance that a clean file collides with one is about 3 in a trillion per lookup.
/// </summary>
public static class HashKey
{
    public static int HexLength(HashKind kind) => kind == HashKind.Md5 ? 32 : 64;

    /// <summary>Parses one feed line ("hash", "hash  comment", "hash,..."). Comments and junk give false.</summary>
    public static bool TryParseLine(ReadOnlySpan<char> line, HashKind kind, out ulong key)
    {
        key = 0;
        line = line.Trim();
        int length = HexLength(kind);
        if (line.Length < length || line[0] == '#')
        {
            return false;
        }

        if (line.Length > length && char.IsAsciiHexDigit(line[length]))
        {
            return false;
        }

        foreach (char c in line[..length])
        {
            if (!char.IsAsciiHexDigit(c))
            {
                return false;
            }
        }

        return ulong.TryParse(line[..16], NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out key);
    }

    public static ulong FromHex(string hex) =>
        TryParseLine(hex, hex.Length == 32 ? HashKind.Md5 : HashKind.Sha256, out ulong key)
            ? key
            : throw new FormatException("Not an MD5 or SHA-256 hash.");
}

/// <summary>
/// A read-only, memory-mapped set of malware hash keys. Lookups touch a handful of pages, so a
/// 50-million-entry database (about 400 MB on disk) costs almost no memory.
/// </summary>
/// <remarks>
/// Layout, little-endian:
/// <code>
///   0  magic "AGHASHDB"
///   8  format version (uint32) = 1
///  12  hash kind (uint32)
///  16  entry count (int64)
///  24  created, Unix seconds (int64)
///  32  reserved (32 bytes)
///  64  bucket table: 65,537 uint32 start indexes, by the key's top 16 bits
///  ... entries: sorted, distinct uint64 keys
/// </code>
/// </remarks>
public sealed class HashDatabase : IDisposable
{
    internal const int HeaderSize = 64;
    internal const int BucketCount = 1 << 16;
    internal const long EntriesOffset = HeaderSize + ((BucketCount + 1) * 4L);
    internal static ReadOnlySpan<byte> Magic => "AGHASHDB"u8;

    private readonly MemoryMappedFile? _file;
    private readonly MemoryMappedViewAccessor? _view;

    private HashDatabase(string path, HashKind kind, long count, DateTimeOffset created, MemoryMappedFile? file, MemoryMappedViewAccessor? view)
    {
        Path = path;
        Kind = kind;
        Count = count;
        Created = created;
        _file = file;
        _view = view;
    }

    public string Path { get; }

    public HashKind Kind { get; }

    public long Count { get; }

    public DateTimeOffset Created { get; }

    public static HashDatabase Open(string path)
    {
        // FileShare.Delete lets the updater remove an old generation while a scan still uses it.
        var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
        try
        {
            Span<byte> header = stackalloc byte[HeaderSize];
            stream.ReadExactly(header);
            if (!header[..8].SequenceEqual(Magic) || BinaryPrimitives.ReadUInt32LittleEndian(header[8..]) != 1)
            {
                throw new InvalidDataException($"{path} is not an Agamemnon hash database.");
            }

            var kind = (HashKind)BinaryPrimitives.ReadUInt32LittleEndian(header[12..]);
            long count = BinaryPrimitives.ReadInt64LittleEndian(header[16..]);
            var created = DateTimeOffset.FromUnixTimeSeconds(BinaryPrimitives.ReadInt64LittleEndian(header[24..]));
            if (kind is not (HashKind.Md5 or HashKind.Sha256) || count < 0 || stream.Length != EntriesOffset + (count * 8))
            {
                throw new InvalidDataException($"{path} is damaged.");
            }

            var mapped = MemoryMappedFile.CreateFromFile(stream, null, 0, MemoryMappedFileAccess.Read, HandleInheritability.None, leaveOpen: false);
            var view = mapped.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Read);
            return new HashDatabase(path, kind, count, created, mapped, view);
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    public bool Contains(ulong key)
    {
        if (Count == 0 || _view is null)
        {
            return false;
        }

        int bucket = (int)(key >> 48);
        long lo = _view.ReadUInt32(HeaderSize + (bucket * 4L));
        long hi = (long)_view.ReadUInt32(HeaderSize + ((bucket + 1) * 4L)) - 1;
        while (lo <= hi)
        {
            long mid = lo + ((hi - lo) >> 1);
            ulong value = _view.ReadUInt64(EntriesOffset + (mid * 8));
            if (value == key)
            {
                return true;
            }

            if (value < key)
            {
                lo = mid + 1;
            }
            else
            {
                hi = mid - 1;
            }
        }

        return false;
    }

    /// <summary>Every key in ascending order (used to merge new feed data into a new generation).</summary>
    public IEnumerable<ulong> ReadAll()
    {
        for (long i = 0; i < Count; i++)
        {
            yield return _view!.ReadUInt64(EntriesOffset + (i * 8));
        }
    }

    public void Dispose()
    {
        _view?.Dispose();
        _file?.Dispose();
    }

    /// <summary>
    /// Writes a database from keys that are already sorted ascending (duplicates are dropped).
    /// Streams, so building a 50-million-entry file needs only the bucket table in memory.
    /// </summary>
    public static long Write(string path, HashKind kind, IEnumerable<ulong> sortedKeys, DateTimeOffset created)
    {
        var buckets = new uint[BucketCount + 1];
        long count = 0;
        using (var stream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20))
        {
            stream.SetLength(EntriesOffset);
            stream.Position = EntriesOffset;
            Span<byte> entry = stackalloc byte[8];
            ulong previous = 0;
            foreach (ulong key in sortedKeys)
            {
                if (count > 0)
                {
                    if (key == previous)
                    {
                        continue;
                    }

                    if (key < previous)
                    {
                        throw new ArgumentException("Keys must be sorted ascending.", nameof(sortedKeys));
                    }
                }

                if (count == uint.MaxValue)
                {
                    throw new InvalidOperationException("Too many entries for one database.");
                }

                BinaryPrimitives.WriteUInt64LittleEndian(entry, key);
                stream.Write(entry);
                buckets[(int)(key >> 48) + 1]++;
                previous = key;
                count++;
            }

            for (int i = 1; i <= BucketCount; i++)
            {
                buckets[i] += buckets[i - 1];
            }

            Span<byte> header = stackalloc byte[HeaderSize];
            header.Clear();
            Magic.CopyTo(header);
            BinaryPrimitives.WriteUInt32LittleEndian(header[8..], 1);
            BinaryPrimitives.WriteUInt32LittleEndian(header[12..], (uint)kind);
            BinaryPrimitives.WriteInt64LittleEndian(header[16..], count);
            BinaryPrimitives.WriteInt64LittleEndian(header[24..], created.ToUnixTimeSeconds());
            stream.Position = 0;
            stream.Write(header);
            byte[] table = new byte[buckets.Length * 4];
            for (int i = 0; i < buckets.Length; i++)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(table.AsSpan(i * 4), buckets[i]);
            }

            stream.Write(table);
            stream.Flush(flushToDisk: true);
        }

        return count;
    }

    /// <summary>Merges two ascending sequences into one ascending sequence.</summary>
    public static IEnumerable<ulong> Merge(IEnumerable<ulong> a, IEnumerable<ulong> b)
    {
        using IEnumerator<ulong> x = a.GetEnumerator();
        using IEnumerator<ulong> y = b.GetEnumerator();
        bool hasX = x.MoveNext();
        bool hasY = y.MoveNext();
        while (hasX && hasY)
        {
            if (x.Current <= y.Current)
            {
                yield return x.Current;
                hasX = x.MoveNext();
            }
            else
            {
                yield return y.Current;
                hasY = y.MoveNext();
            }
        }

        while (hasX)
        {
            yield return x.Current;
            hasX = x.MoveNext();
        }

        while (hasY)
        {
            yield return y.Current;
            hasY = y.MoveNext();
        }
    }
}
