using System.Text;
using Agamemnon.Core.Archives;
using Agamemnon.Core.Scanning;
using WixToolset.Dtf.Compression.Cab;
using WixToolset.Dtf.WindowsInstaller;

namespace Agamemnon.Platform.Windows;

/// <summary>
/// Opens Windows Installer packages read-only (nothing is installed or executed) and exposes what
/// an installer can run: custom-action binaries and scripts, command lines it would launch, and the
/// cabinets holding the files it installs.
/// </summary>
public sealed class MsiExtractor : IContainerExtractor
{
    // msidbCustomActionType source/target bits for inline script text.
    private const int TypeJScript = 0x05;
    private const int TypeVbScript = 0x06;
    private const int SourceTextData = 0x20;

    public bool CanExtract(string path, FileKind kind) => kind == FileKind.WindowsInstaller;

    public IEnumerable<ContainerEntry> Entries(string path)
    {
        using var database = new Database(path, DatabaseOpenMode.ReadOnly);

        if (database.Tables.Contains("Binary"))
        {
            using View view = database.OpenView("SELECT `Name`, `Data` FROM `Binary`");
            view.Execute();
            foreach (Record record in view)
            {
                using (record)
                {
                    byte[] data = ReadStream(record, 2);
                    yield return Bytes($"Binary/{record.GetString(1)}", data);
                }
            }
        }

        if (database.Tables.Contains("CustomAction"))
        {
            using View view = database.OpenView("SELECT `Action`, `Type`, `Target` FROM `CustomAction`");
            view.Execute();
            foreach (Record record in view)
            {
                using (record)
                {
                    string action = record.GetString(1);
                    int type = record.GetInteger(2);
                    string target = record.GetString(3);
                    if (string.IsNullOrWhiteSpace(target))
                    {
                        continue;
                    }

                    int basic = type & 0x07;
                    bool inlineScript = (type & 0x30) == SourceTextData && basic is TypeJScript or TypeVbScript;
                    string extension = inlineScript ? (basic == TypeJScript ? ".js" : ".vbs") : ".txt";
                    yield return Bytes($"CustomAction/{action}{extension}", Encoding.UTF8.GetBytes(target));
                }
            }
        }

        if (database.Tables.Contains("Media"))
        {
            using View view = database.OpenView("SELECT `Cabinet` FROM `Media`");
            view.Execute();
            var cabinets = new List<string>();
            foreach (Record record in view)
            {
                using (record)
                {
                    if (record.GetString(1) is { Length: > 0 } cabinet)
                    {
                        cabinets.Add(cabinet);
                    }
                }
            }

            foreach (string cabinet in cabinets)
            {
                if (cabinet.StartsWith('#'))
                {
                    using View stream = database.OpenView("SELECT `Data` FROM `_Streams` WHERE `Name` = ?");
                    using var parameters = new Record(cabinet[1..]);
                    stream.Execute(parameters);
                    using Record? row = stream.Fetch();
                    if (row is not null)
                    {
                        yield return Bytes($"Cabinet/{cabinet[1..]}", ReadStream(row, 1));
                    }
                }
                else
                {
                    string external = Path.Combine(Path.GetDirectoryName(path)!, cabinet);
                    if (File.Exists(external))
                    {
                        yield return new ContainerEntry($"Cabinet/{cabinet}", false, null, () => File.OpenRead(external));
                    }
                }
            }
        }
    }

    private static byte[] ReadStream(Record record, int field)
    {
        using Stream stream = record.GetStream(field);
        using var buffer = new MemoryStream();
        stream.CopyTo(buffer);
        return buffer.ToArray();
    }

    private static ContainerEntry Bytes(string name, byte[] data) =>
        new(name, false, null, () => new MemoryStream(data, writable: false));
}

/// <summary>Microsoft cabinet files (.cab, and the cabinets inside MSI packages).</summary>
public sealed class CabExtractor : IContainerExtractor
{
    public bool CanExtract(string path, FileKind kind)
    {
        if (kind != FileKind.Archive)
        {
            return false;
        }

        Span<byte> head = stackalloc byte[4];
        using FileStream stream = File.OpenRead(path);
        return stream.ReadAtLeast(head, 4, throwOnEndOfStream: false) == 4 && head.SequenceEqual("MSCF"u8);
    }

    public IEnumerable<ContainerEntry> Entries(string path)
    {
        var cabinet = new CabInfo(path);
        foreach (CabFileInfo file in cabinet.GetFiles())
        {
            CabFileInfo current = file;
            yield return new ContainerEntry(file.Name, false, null, () => current.OpenRead());
        }
    }
}
