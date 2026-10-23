using System.Text.RegularExpressions;
using Agamemnon.Core.Scanning;

namespace Agamemnon.Core.Startup;

public enum StartupLocation
{
    /// <summary>HKCU\…\Run and RunOnce.</summary>
    UserRunKey,

    /// <summary>HKLM\…\Run and RunOnce (and their 32-bit copies).</summary>
    MachineRunKey,

    /// <summary>The Startup folder in the Start menu (yours or everyone's).</summary>
    StartupFolder,

    ScheduledTask,

    Service,

    /// <summary>Winlogon Shell/Userinit, Image File Execution Options debuggers and similar hooks.</summary>
    SystemHook,
}

/// <summary>Something that starts by itself: where it is registered, its name and the command it runs.</summary>
public sealed record StartupItem(StartupLocation Location, string Name, string Command, string? Program = null)
{
    /// <summary>Stable identity for spotting new and changed items.</summary>
    public string Key => $"{Location}|{Name}";
}

public sealed record StartupFinding(StartupItem Item, Detection Detection);

/// <summary>
/// The startup items check (everything that already starts with Windows) and the watcher's
/// comparison (what's new since last time). Programs are scanned with the normal engines too;
/// these checks add what a file scan can't see: how the item is started.
/// </summary>
public static partial class StartupAudit
{
    private static readonly string[] Interpreters =
    [
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
    ];

    /// <summary>The program a command line starts: the quoted part, or up to the first ".exe".</summary>
    public static string? ProgramOf(string? command)
    {
        if (string.IsNullOrWhiteSpace(command))
        {
            return null;
        }

        string text = command.Trim();
        if (text.StartsWith('"'))
        {
            int end = text.IndexOf('"', 1);
            return end > 1 ? text[1..end] : null;
        }

        foreach (string ext in new[] { ".exe", ".com", ".bat", ".cmd", ".vbs", ".js", ".ps1", ".lnk" })
        {
            int at = text.IndexOf(ext, StringComparison.OrdinalIgnoreCase);
            if (at > 0 && (at + ext.Length == text.Length || text[at + ext.Length] == ' '))
            {
                return text[..(at + ext.Length)];
            }
        }

        return text.Split(' ')[0];
    }

    /// <summary>What's wrong with how an item starts, or null.</summary>
    public static Detection? Inspect(StartupItem item, Func<string, string> expandEnvironment)
    {
        string command = expandEnvironment(item.Command);
        string? program = item.Program is { } p ? expandEnvironment(p) : ProgramOf(command);
        string fileName = program is null ? string.Empty : Path.GetFileName(program);
        bool viaInterpreter = Interpreters.Contains(fileName, StringComparer.OrdinalIgnoreCase);

        if (viaInterpreter && RunsHiddenOrDownloadedCode().IsMatch(command))
        {
            return new Detection("Startup check", "Starts a hidden or downloaded script every time", Severity.Suspicious, command);
        }

        if (program is not null && IsInRiskyFolder(program))
        {
            return new Detection("Startup check", "Starts a program from a temporary or hidden folder", Severity.Suspicious, program);
        }

        if (program is not null && MasqueradesAsWindows(program))
        {
            return new Detection("Startup check", "Program uses a Windows name but isn't in the Windows folder", Severity.Suspicious, program);
        }

        return null;
    }

    /// <summary>Items that are new or now start something different, compared with an earlier list.</summary>
    public static IReadOnlyList<StartupItem> NewOrChanged(IReadOnlyCollection<StartupItem> before, IReadOnlyCollection<StartupItem> now)
    {
        var known = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (StartupItem item in before)
        {
            known[item.Key] = item.Command;
        }

        return [.. now.Where(item => !known.TryGetValue(item.Key, out string? command) || !string.Equals(command, item.Command, StringComparison.OrdinalIgnoreCase))];
    }

    internal static bool IsInRiskyFolder(string program)
    {
        string path = program.Replace('/', '\\');
        return path.Contains(@"\AppData\Local\Temp\", StringComparison.OrdinalIgnoreCase)
               || path.Contains(@"\Windows\Temp\", StringComparison.OrdinalIgnoreCase)
               || path.Contains(@"\Users\Public\", StringComparison.OrdinalIgnoreCase)
               || path.Contains(@"\$Recycle.Bin\", StringComparison.OrdinalIgnoreCase)
               || RootOfAppData().IsMatch(path)
               || RootOfProgramData().IsMatch(path);
    }

    private static readonly string[] WindowsNames =
    [
        "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "smss.exe", "explorer.exe", "taskhostw.exe",
        "dllhost.exe", "conhost.exe", "spoolsv.exe", "wininit.exe", "runtimebroker.exe",
    ];

    internal static bool MasqueradesAsWindows(string program)
    {
        string name = Path.GetFileName(program.Replace('/', '\\').Split('\\')[^1]);
        if (!WindowsNames.Contains(name, StringComparer.OrdinalIgnoreCase))
        {
            return false;
        }

        string directory = program.Replace('/', '\\');
        return !directory.Contains(@"\Windows\", StringComparison.OrdinalIgnoreCase);
    }

    [GeneratedRegex(@"(\s-(e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}|-w(indowstyle)?\s+h(idden)?|downloadstring|downloadfile|invoke-webrequest|\biwr\b|\birm\b|net\.webclient|frombase64string|\biex\b|invoke-expression|https?://|javascript:|vbscript:|scrobj)", RegexOptions.IgnoreCase)]
    private static partial Regex RunsHiddenOrDownloadedCode();

    // A program straight inside %APPDATA% or %LOCALAPPDATA% (not in a vendor folder).
    [GeneratedRegex(@"\\AppData\\(Roaming|Local)\\[^\\]+\.(exe|scr|com|bat|cmd|vbs|js|ps1)$", RegexOptions.IgnoreCase)]
    private static partial Regex RootOfAppData();

    [GeneratedRegex(@"^[A-Z]:\\ProgramData\\[^\\]+\.(exe|scr|com|bat|cmd|vbs|js|ps1)$", RegexOptions.IgnoreCase)]
    private static partial Regex RootOfProgramData();
}
