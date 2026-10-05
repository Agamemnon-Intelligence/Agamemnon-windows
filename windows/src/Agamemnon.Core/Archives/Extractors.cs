using Agamemnon.Core.Scanning;
using DiscUtils.Iso9660;
using SharpCompress.Archives;
using SharpCompress.Readers;

namespace Agamemnon.Core.Archives;

/// <summary>zip (incl. MSIX/APPX/Office/JAR), 7z, rar, tar, gzip, bzip2 and xz via SharpCompress.</summary>
public sealed class SharpCompressExtractor : IContainerExtractor
{
    public bool CanExtract(string path, FileKind kind)
    {
        if (kind != FileKind.Archive)
        {
            return false;
        }

        // Cabinets are handled by the Windows extractor.
        Span<byte> head = stackalloc byte[4];
        using var stream = File.OpenRead(path);
        return stream.ReadAtLeast(head, 4, throwOnEndOfStream: false) < 4 || !head.SequenceEqual("MSCF"u8);
    }

    public IEnumerable<ContainerEntry> Entries(string path)
    {
        using IArchive archive = ArchiveFactory.OpenArchive(path, new ReaderOptions { LeaveStreamOpen = false });
        if (archive.IsSolid)
        {
            // Solid 7z/rar: random access would decompress from the start for every entry.
            using IReader reader = archive.ExtractAllEntries();
            while (reader.MoveToNextEntry())
            {
                if (reader.Entry.IsDirectory)
                {
                    continue;
                }

                IReader current = reader;
                yield return new ContainerEntry(
                    reader.Entry.Key ?? "(unnamed)",
                    reader.Entry.IsEncrypted,
                    reader.Entry.CompressedSize,
                    () => current.OpenEntryStream());
            }

            yield break;
        }

        foreach (IArchiveEntry entry in archive.Entries)
        {
            if (entry.IsDirectory)
            {
                continue;
            }

            IArchiveEntry current = entry;
            yield return new ContainerEntry(
                entry.Key ?? "(unnamed)",
                entry.IsEncrypted,
                entry.CompressedSize,
                () => current.OpenEntryStream());
        }
    }
}

/// <summary>ISO 9660/Joliet images, a popular way to deliver malware past Mark-of-the-Web.</summary>
public sealed class IsoExtractor : IContainerExtractor
{
    public bool CanExtract(string path, FileKind kind) =>
        kind == FileKind.DiskImage && Path.GetExtension(path).Equals(".iso", StringComparison.OrdinalIgnoreCase)
        && LooksLikeIso(path);

    public IEnumerable<ContainerEntry> Entries(string path)
    {
        using FileStream stream = File.OpenRead(path);
        using var reader = new CDReader(stream, joliet: true);
        foreach (string file in reader.GetFiles("\\", "*.*", SearchOption.AllDirectories))
        {
            string name = file.TrimStart('\\');
            int version = name.LastIndexOf(';');
            if (version > 0)
            {
                name = name[..version];
            }

            yield return new ContainerEntry(name, false, null, () => reader.OpenFile(file, FileMode.Open, FileAccess.Read));
        }
    }

    private static bool LooksLikeIso(string path)
    {
        using FileStream stream = File.OpenRead(path);
        if (stream.Length < 0x8006)
        {
            return false;
        }

        stream.Position = 0x8001;
        Span<byte> magic = stackalloc byte[5];
        return stream.ReadAtLeast(magic, 5, throwOnEndOfStream: false) == 5 && magic.SequenceEqual("CD001"u8);
    }
}
