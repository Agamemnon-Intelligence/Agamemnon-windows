namespace Agamemnon.Core.Scanning;

public enum FileKind
{
    Other,
    PortableExecutable,
    WindowsInstaller,
    Script,
    Shortcut,
    Document,
    Archive,
    DiskImage,
}

/// <summary>Identifies files by content first (magic bytes), falling back to the extension.</summary>
public static class FileClassifier
{
    private static readonly HashSet<string> ScriptExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".sct", ".reg", ".scr",
    };

    private static readonly HashSet<string> ArchiveExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".cab", ".msix", ".msixbundle", ".appx", ".appxbundle",
        ".nupkg", ".jar", ".apk",
    };

    private static readonly HashSet<string> DocumentExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".doc", ".docm", ".docx", ".xls", ".xlsm", ".xlsx", ".xlsb", ".ppt", ".pptm", ".pptx", ".rtf", ".pdf", ".one", ".chm",
    };

    private static readonly HashSet<string> DiskImageExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".iso", ".img", ".vhd", ".vhdx",
    };

    /// <summary>Kinds worth a hash-reputation lookup and a code-signature check.</summary>
    public static bool IsRiskyKind(FileKind kind) => kind is FileKind.PortableExecutable or FileKind.WindowsInstaller
        or FileKind.Script or FileKind.Shortcut or FileKind.Document or FileKind.Archive or FileKind.DiskImage;

    public static bool IsExecutableName(string name)
    {
        string ext = Path.GetExtension(name);
        return ext.Equals(".exe", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".dll", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".msi", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".lnk", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".com", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".pif", StringComparison.OrdinalIgnoreCase)
            || ScriptExtensions.Contains(ext);
    }

    public static FileKind Classify(string path, ReadOnlySpan<byte> head)
    {
        if (head.Length >= 2 && head[0] == 'M' && head[1] == 'Z')
        {
            return FileKind.PortableExecutable;
        }

        if (head.Length >= 8 && head[..8].SequenceEqual(new byte[] { 0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00 }))
        {
            return FileKind.Shortcut;
        }

        string ext = Path.GetExtension(path);
        bool isOle = head.Length >= 8 && head[..8].SequenceEqual(new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 });
        if (isOle && (ext.Equals(".msi", StringComparison.OrdinalIgnoreCase) || ext.Equals(".msp", StringComparison.OrdinalIgnoreCase)))
        {
            return FileKind.WindowsInstaller;
        }

        if (isOle)
        {
            return FileKind.Document;
        }

        if (head.Length >= 4 && head[0] == 'M' && head[1] == 'S' && head[2] == 'C' && head[3] == 'F')
        {
            return FileKind.Archive; // Microsoft cabinet
        }

        if (IsArchiveMagic(head))
        {
            // Office Open XML documents are zip files too; treat them as archives so macros and embedded files are scanned.
            return FileKind.Archive;
        }

        if (head.Length >= 4 && head[0] == '%' && head[1] == 'P' && head[2] == 'D' && head[3] == 'F')
        {
            return FileKind.Document;
        }

        if (ScriptExtensions.Contains(ext))
        {
            return FileKind.Script;
        }

        if (ext.Equals(".lnk", StringComparison.OrdinalIgnoreCase))
        {
            return FileKind.Shortcut;
        }

        if (DiskImageExtensions.Contains(ext))
        {
            return FileKind.DiskImage;
        }

        if (ArchiveExtensions.Contains(ext))
        {
            return FileKind.Archive;
        }

        return DocumentExtensions.Contains(ext) ? FileKind.Document : FileKind.Other;
    }

    public static FileKind Classify(string path)
    {
        Span<byte> head = stackalloc byte[16];
        int read;
        using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1, FileOptions.None))
        {
            read = stream.ReadAtLeast(head, head.Length, throwOnEndOfStream: false);
        }

        return Classify(path, head[..read]);
    }

    private static bool IsArchiveMagic(ReadOnlySpan<byte> head) =>
        (head.Length >= 4 && head[0] == 'P' && head[1] == 'K' && head[2] is 3 or 5 or 7) // zip
        || (head.Length >= 6 && head[..6].SequenceEqual(new byte[] { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C })) // 7z
        || (head.Length >= 4 && head[0] == 'R' && head[1] == 'a' && head[2] == 'r' && head[3] == '!') // rar
        || (head.Length >= 2 && head[0] == 0x1F && head[1] == 0x8B) // gzip
        || (head.Length >= 3 && head[0] == 'B' && head[1] == 'Z' && head[2] == 'h') // bzip2
        || (head.Length >= 6 && head[..6].SequenceEqual(new byte[] { 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00 })); // xz
}
