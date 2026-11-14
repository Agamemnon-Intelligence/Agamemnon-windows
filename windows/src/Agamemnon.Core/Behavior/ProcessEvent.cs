namespace Agamemnon.Core.Behavior;

/// <summary>
/// One program starting, as the service sees it (Windows' process-start trace, read as SYSTEM).
/// Paths are Windows paths; the helpers below split them the same way on every OS, so the
/// behaviour engine is unit-tested on Linux and macOS too.
/// </summary>
public sealed record ProcessEvent(
    int ProcessId,
    int ParentProcessId,
    int SessionId,
    string ImagePath,
    string? CommandLine,
    DateTimeOffset At)
{
    /// <summary>"powershell.exe", lower case.</summary>
    public string Name => WinPath.FileName(ImagePath).ToLowerInvariant();

    /// <summary>The command line without the program itself, or empty.</summary>
    public string Arguments => WinPath.Arguments(CommandLine);
}

/// <summary>Windows path helpers that don't depend on the OS the code runs on.</summary>
public static class WinPath
{
    public static string FileName(string? path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return string.Empty;
        }

        int slash = path.LastIndexOfAny(['\\', '/']);
        return slash >= 0 ? path[(slash + 1)..] : path;
    }

    public static string? Directory(string? path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return null;
        }

        int slash = path.LastIndexOfAny(['\\', '/']);
        return slash > 0 ? path[..slash] : null;
    }

    /// <summary>"C:\Windows\System32\cmd.exe" /c dir → /c dir.</summary>
    public static string Arguments(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            return string.Empty;
        }

        string text = commandLine.TrimStart();
        if (text.StartsWith('"'))
        {
            int end = text.IndexOf('"', 1);
            return end < 0 ? string.Empty : text[(end + 1)..].Trim();
        }

        int space = text.IndexOf(' ', StringComparison.Ordinal);
        return space < 0 ? string.Empty : text[(space + 1)..].Trim();
    }

    /// <summary>True when <paramref name="path"/> is inside <paramref name="folder"/> (any depth).</summary>
    public static bool IsUnder(string? path, string? folder)
    {
        if (string.IsNullOrEmpty(path) || string.IsNullOrEmpty(folder))
        {
            return false;
        }

        string f = folder.Replace('/', '\\').TrimEnd('\\') + "\\";
        return path.Replace('/', '\\').StartsWith(f, StringComparison.OrdinalIgnoreCase);
    }
}
