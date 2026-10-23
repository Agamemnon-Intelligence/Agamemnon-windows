using Agamemnon.Core.Scanning;

namespace Agamemnon.Core.Protection;

/// <summary>
/// Which newly saved files the on-access scanner looks at: things that can run or carry
/// something that runs (programs, scripts, shortcuts, installers, archives, disk images,
/// macro documents), outside caches, build output and package folders, where thousands of
/// harmless files are written all the time.
/// </summary>
public static class OnAccessFilter
{
    private static readonly HashSet<string> Extensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".scr", ".com", ".pif", ".msi", ".msp", ".msix", ".appx", ".ps1", ".psm1", ".bat", ".cmd", ".vbs",
        ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".sct", ".lnk", ".url", ".jar", ".iso", ".img", ".vhd", ".vhdx",
        ".zip", ".7z", ".rar", ".cab", ".docm", ".xlsm", ".pptm", ".one", ".chm", ".cpl", ".reg", ".xll",
    };

    private static readonly string[] SkippedFolders =
    [
        @"\node_modules\", @"\.git\", @"\.nuget\", @"\.cargo\", @"\.rustup\", @"\.vscode\extensions\", @"\obj\", @"\bin\Debug\",
        @"\bin\Release\", @"\Cache\", @"\Code Cache\", @"\GPUCache\", @"\Service Worker\", @"\AppData\Local\Packages\",
        @"\AppData\Local\Microsoft\Windows\INetCache\", @"\AppData\Local\Microsoft\Edge\User Data\", @"\AppData\Local\Google\Chrome\User Data\",
        @"\AppData\Local\Agamemnon\", @"\AppData\Roaming\Agamemnon\", @"\AppData\Local\pip\", @"\AppData\Local\npm-cache\",
        @"\AppData\Local\Microsoft\WindowsApps\", @"\AppData\Local\Temp\WinGet\", @"\$Recycle.Bin\", @"\site-packages\",
    ];

    public static bool ShouldScan(string path)
    {
        if (!Extensions.Contains(Path.GetExtension(path)))
        {
            return false;
        }

        string normalized = path.Replace('/', '\\');
        return !SkippedFolders.Any(folder => normalized.Contains(folder, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Files under these roots that could run, for scanning a USB drive (photos and documents are skipped so big drives are quick).</summary>
    public static IEnumerable<string> RiskyFiles(string root, int limit)
    {
        var options = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint | FileAttributes.Offline };
        IEnumerable<string> files;
        try
        {
            files = Directory.EnumerateFiles(root, "*", options);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            yield break;
        }

        int count = 0;
        foreach (string file in files)
        {
            if (Extensions.Contains(Path.GetExtension(file)) || FileClassifier.IsExecutableName(file))
            {
                yield return file;
                if (++count >= limit)
                {
                    yield break;
                }
            }
        }
    }
}
