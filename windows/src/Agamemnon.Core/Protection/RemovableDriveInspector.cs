using Agamemnon.Core.Archives;
using Agamemnon.Core.Scanning;

namespace Agamemnon.Core.Protection;

public sealed record DriveFinding(string Path, Detection Detection);

/// <summary>
/// USB protection: looks at the top two levels of a newly connected drive for the tricks used by
/// drives that spread malware. Windows no longer runs programs from a drive by itself, so these
/// drives rely on the user opening something:
/// <list type="bullet">
/// <item>an autorun.inf that names a program to start;</item>
/// <item>the user's files moved into a hidden folder, with a shortcut in their place that runs
/// something else (the shortcut often has the drive's or folder's name);</item>
/// <item>programs named like documents (<c>photos.jpg.exe</c>, right-to-left override);</item>
/// <item>hidden programs and scripts at the top of the drive.</item>
/// </list>
/// The drive's programs, scripts, archives and installers are then scanned with every engine.
/// </summary>
public static class RemovableDriveInspector
{
    public const int MaxDepth = 2;
    private const int MaxEntries = 5000;

    public static IReadOnlyList<DriveFinding> Inspect(string root)
    {
        var findings = new List<DriveFinding>();
        string autorun = Path.Combine(root, "autorun.inf");
        if (File.Exists(autorun) && AutorunLaunches(SafeRead(autorun)) is { } program)
        {
            findings.Add(new DriveFinding(autorun, new Detection("USB protection", "autorun.inf starts a program", Severity.Suspicious, program)));
        }

        var hiddenFolders = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int seen = 0;
        Visit(root, 0, findings, hiddenFolders, ref seen);

        // A shortcut at the top named like a hidden folder: the classic "your files are a shortcut now" worm.
        foreach (string shortcut in SafeFiles(root, "*.lnk"))
        {
            string name = Path.GetFileNameWithoutExtension(shortcut);
            if (hiddenFolders.Contains(name) || (hiddenFolders.Count > 0 && name.Trim().Length == 0))
            {
                findings.Add(new DriveFinding(shortcut, new Detection("USB protection", "Shortcut replacing a hidden folder", Severity.Malicious,
                    "The drive's files were hidden and replaced by a shortcut that runs a program.")));
            }
        }

        return findings;
    }

    private static void Visit(string directory, int depth, List<DriveFinding> findings, HashSet<string> hiddenFolders, ref int seen)
    {
        IEnumerable<string> entries;
        try
        {
            entries = [.. Directory.EnumerateFileSystemEntries(directory)];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return;
        }

        foreach (string entry in entries)
        {
            if (++seen > MaxEntries)
            {
                return;
            }

            FileAttributes attributes;
            try
            {
                attributes = File.GetAttributes(entry);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                continue;
            }

            bool hidden = (attributes & FileAttributes.Hidden) != 0;
            string name = Path.GetFileName(entry);
            if ((attributes & FileAttributes.Directory) != 0)
            {
                if (depth == 0 && hidden && !IsSystemFolder(name))
                {
                    hiddenFolders.Add(name);
                }

                if (depth + 1 < MaxDepth && (attributes & FileAttributes.ReparsePoint) == 0)
                {
                    Visit(entry, depth + 1, findings, hiddenFolders, ref seen);
                }

                continue;
            }

            if (FileNameHeuristics.Inspect(name) is { } disguised)
            {
                findings.Add(new DriveFinding(entry, disguised with { Engine = "USB protection" }));
            }
            else if (depth == 0 && hidden && FileClassifier.IsExecutableName(name) && !name.Equals("autorun.inf", StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(new DriveFinding(entry, new Detection("USB protection", "Hidden program at the top of the drive", Severity.Suspicious)));
            }
        }
    }

    /// <summary>The program an autorun.inf starts ("open=", "shellexecute=", "shell\…\command="), or null.</summary>
    public static string? AutorunLaunches(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return null;
        }

        bool inAutorun = false;
        foreach (string rawLine in text.Split('\n'))
        {
            string line = rawLine.Trim();
            if (line.StartsWith('['))
            {
                inAutorun = line.Equals("[autorun]", StringComparison.OrdinalIgnoreCase);
                continue;
            }

            int eq = line.IndexOf('=', StringComparison.Ordinal);
            if (!inAutorun || eq <= 0)
            {
                continue;
            }

            string key = line[..eq].Trim().ToLowerInvariant();
            string value = line[(eq + 1)..].Trim();
            if (value.Length > 0 && (key is "open" or "shellexecute" || (key.StartsWith("shell\\", StringComparison.Ordinal) && key.EndsWith("\\command", StringComparison.Ordinal))))
            {
                return value;
            }
        }

        return null;
    }

    private static bool IsSystemFolder(string name) =>
        name.Equals("System Volume Information", StringComparison.OrdinalIgnoreCase)
        || name.Equals("$RECYCLE.BIN", StringComparison.OrdinalIgnoreCase)
        || name.StartsWith('.');

    private static string? SafeRead(string path)
    {
        try
        {
            return new FileInfo(path).Length > 64 * 1024 ? null : File.ReadAllText(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static IEnumerable<string> SafeFiles(string directory, string pattern)
    {
        try
        {
            return [.. Directory.EnumerateFiles(directory, pattern)];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }
}
