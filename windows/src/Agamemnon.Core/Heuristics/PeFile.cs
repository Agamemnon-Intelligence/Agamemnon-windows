using System.Buffers.Binary;
using System.Text;

namespace Agamemnon.Core.Heuristics;

public sealed record PeSection(
    string Name,
    uint VirtualAddress,
    uint VirtualSize,
    uint RawPointer,
    uint RawSize,
    uint Characteristics,
    double Entropy)
{
    private const uint Executable = 0x20000000;
    private const uint Writable = 0x80000000;
    private const uint ContainsCode = 0x00000020;

    public bool IsExecutable => (Characteristics & (Executable | ContainsCode)) != 0;

    public bool IsWritable => (Characteristics & Writable) != 0;

    public bool Contains(uint rva) => rva >= VirtualAddress && rva < VirtualAddress + Math.Max(VirtualSize, RawSize);
}

/// <summary>
/// The parts of a Windows program's layout (PE format) that the smart analysis looks at:
/// sections and how random their contents are, the import table's size, the entry point,
/// resources, an appended overlay and whether it is a .NET program. Read-only, bounds-checked
/// everywhere, and never runs or loads the file.
/// </summary>
public sealed class PeFile
{
    private const int MaxSections = 96;

    private PeFile()
    {
    }

    public bool Is64Bit { get; private init; }

    public bool IsDll { get; private init; }

    public bool IsDotNet { get; private init; }

    public uint EntryPoint { get; private init; }

    public IReadOnlyList<PeSection> Sections { get; private init; } = [];

    /// <summary>DLLs named in the import table.</summary>
    public int ImportedLibraries { get; private init; }

    /// <summary>Functions imported by name or ordinal across all DLLs.</summary>
    public int ImportedFunctions { get; private init; }

    public bool HasVersionInfo { get; private init; }

    public bool HasCertificate { get; private init; }

    /// <summary>Bytes after the last section that aren't the signature.</summary>
    public long OverlaySize { get; private init; }

    public long FileSize { get; private init; }

    public PeSection? EntrySection => Sections.FirstOrDefault(s => s.Contains(EntryPoint));

    /// <summary>Parses a PE file, or returns null if it isn't one (or is damaged beyond reading).</summary>
    public static PeFile? Parse(ReadOnlySpan<byte> data)
    {
        try
        {
            return ParseCore(data);
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    private static PeFile? ParseCore(ReadOnlySpan<byte> data)
    {
        if (data.Length < 0x40 || data[0] != 'M' || data[1] != 'Z')
        {
            return null;
        }

        int pe = BinaryPrimitives.ReadInt32LittleEndian(data[0x3C..]);
        if (pe <= 0 || pe > data.Length - 24 || data[pe] != 'P' || data[pe + 1] != 'E' || data[pe + 2] != 0 || data[pe + 3] != 0)
        {
            return null;
        }

        int coff = pe + 4;
        int sectionCount = BinaryPrimitives.ReadUInt16LittleEndian(data[(coff + 2)..]);
        int optionalSize = BinaryPrimitives.ReadUInt16LittleEndian(data[(coff + 16)..]);
        ushort characteristics = BinaryPrimitives.ReadUInt16LittleEndian(data[(coff + 18)..]);
        int optional = coff + 20;
        if (optionalSize < 0x60 || optional + optionalSize > data.Length || sectionCount is 0 or > MaxSections)
        {
            return null;
        }

        ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(data[optional..]);
        bool is64 = magic == 0x20B;
        if (!is64 && magic != 0x10B)
        {
            return null;
        }

        uint entry = BinaryPrimitives.ReadUInt32LittleEndian(data[(optional + 16)..]);
        int directories = optional + (is64 ? 112 : 96);
        int directoryCount = (int)Math.Min(16u, BinaryPrimitives.ReadUInt32LittleEndian(data[(directories - 4)..]));
        int directoriesEnd = optional + optionalSize;
        var sections = new List<PeSection>(sectionCount);
        int table = optional + optionalSize;
        long endOfSections = 0;
        for (int i = 0; i < sectionCount; i++)
        {
            int s = table + (i * 40);
            if (s + 40 > data.Length)
            {
                return null;
            }

            string name = Encoding.ASCII.GetString(data.Slice(s, 8)).TrimEnd('\0');
            uint virtualSize = BinaryPrimitives.ReadUInt32LittleEndian(data[(s + 8)..]);
            uint virtualAddress = BinaryPrimitives.ReadUInt32LittleEndian(data[(s + 12)..]);
            uint rawSize = BinaryPrimitives.ReadUInt32LittleEndian(data[(s + 16)..]);
            uint rawPointer = BinaryPrimitives.ReadUInt32LittleEndian(data[(s + 20)..]);
            uint flags = BinaryPrimitives.ReadUInt32LittleEndian(data[(s + 36)..]);
            long start = Math.Min(rawPointer, (uint)data.Length);
            long length = Math.Min(rawSize, data.Length - start);
            sections.Add(new PeSection(name, virtualAddress, virtualSize, rawPointer, rawSize, flags,
                Entropy(data.Slice((int)start, (int)length))));
            if (rawSize > 0)
            {
                endOfSections = Math.Max(endOfSections, (long)rawPointer + rawSize);
            }
        }

        (int libraries, int functions) = CountImports(data, Directory(data, directories, directoryCount, directoriesEnd, 1).Rva, is64, sections);
        (uint certOffset, uint certSize) = Directory(data, directories, directoryCount, directoriesEnd, 4); // a file offset, not an RVA
        long overlay = Math.Max(0, data.Length - endOfSections);
        if (certSize > 0 && certOffset >= endOfSections && certOffset <= data.Length)
        {
            overlay = Math.Max(0, overlay - Math.Min(certSize, data.Length - certOffset));
        }

        return new PeFile
        {
            Is64Bit = is64,
            IsDll = (characteristics & 0x2000) != 0,
            IsDotNet = Directory(data, directories, directoryCount, directoriesEnd, 14).Rva != 0,
            EntryPoint = entry,
            Sections = sections,
            ImportedLibraries = libraries,
            ImportedFunctions = functions,
            HasVersionInfo = HasResourceType(data, Directory(data, directories, directoryCount, directoriesEnd, 2).Rva, sections, 16),
            HasCertificate = certSize > 0,
            OverlaySize = overlay,
            FileSize = data.Length,
        };
    }

    private static (uint Rva, uint Size) Directory(ReadOnlySpan<byte> data, int directories, int count, int end, int index) =>
        index < count && directories + (index * 8) + 8 <= end
            ? (BinaryPrimitives.ReadUInt32LittleEndian(data[(directories + (index * 8))..]), BinaryPrimitives.ReadUInt32LittleEndian(data[(directories + (index * 8) + 4)..]))
            : (0, 0);

    /// <summary>File offset of an address in the loaded image, or null if no section holds it.</summary>
    private static int? Offset(List<PeSection> sections, uint rva, int length)
    {
        foreach (PeSection section in sections)
        {
            if (section.Contains(rva))
            {
                long offset = (long)section.RawPointer + (rva - section.VirtualAddress);
                return offset < length ? (int)offset : null;
            }
        }

        return null;
    }

    private static (int Libraries, int Functions) CountImports(ReadOnlySpan<byte> data, uint rva, bool is64, List<PeSection> sections)
    {
        if (rva == 0 || Offset(sections, rva, data.Length) is not int start)
        {
            return (0, 0);
        }

        int libraries = 0;
        int functions = 0;
        for (int d = start; d + 20 <= data.Length && libraries < 1024; d += 20)
        {
            uint lookup = BinaryPrimitives.ReadUInt32LittleEndian(data[d..]);
            uint name = BinaryPrimitives.ReadUInt32LittleEndian(data[(d + 12)..]);
            uint thunks = BinaryPrimitives.ReadUInt32LittleEndian(data[(d + 16)..]);
            if (name == 0 && lookup == 0 && thunks == 0)
            {
                break;
            }

            libraries++;
            if (Offset(sections, lookup != 0 ? lookup : thunks, data.Length) is not int t)
            {
                continue;
            }

            int width = is64 ? 8 : 4;
            for (int e = t; e + width <= data.Length && functions < 100_000; e += width)
            {
                ulong value = is64 ? BinaryPrimitives.ReadUInt64LittleEndian(data[e..]) : BinaryPrimitives.ReadUInt32LittleEndian(data[e..]);
                if (value == 0)
                {
                    break;
                }

                functions++;
            }
        }

        return (libraries, functions);
    }

    private static bool HasResourceType(ReadOnlySpan<byte> data, uint rva, List<PeSection> sections, int type)
    {
        if (rva == 0 || Offset(sections, rva, data.Length) is not int root || root + 16 > data.Length)
        {
            return false;
        }

        int named = BinaryPrimitives.ReadUInt16LittleEndian(data[(root + 12)..]);
        int ids = BinaryPrimitives.ReadUInt16LittleEndian(data[(root + 14)..]);
        for (int i = 0; i < named + ids && i < 256; i++)
        {
            int entry = root + 16 + (i * 8);
            if (entry + 8 > data.Length)
            {
                break;
            }

            uint id = BinaryPrimitives.ReadUInt32LittleEndian(data[entry..]);
            if ((id & 0x80000000) == 0 && id == type)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Shannon entropy in bits per byte: 0 (all the same) to 8 (random, i.e. compressed or encrypted).</summary>
    public static double Entropy(ReadOnlySpan<byte> bytes)
    {
        if (bytes.IsEmpty)
        {
            return 0;
        }

        Span<int> counts = stackalloc int[256];
        foreach (byte b in bytes)
        {
            counts[b]++;
        }

        double entropy = 0;
        foreach (int count in counts)
        {
            if (count > 0)
            {
                double p = (double)count / bytes.Length;
                entropy -= p * Math.Log2(p);
            }
        }

        return entropy;
    }
}
