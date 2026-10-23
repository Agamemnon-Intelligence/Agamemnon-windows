using System.Text;
using Agamemnon.Platform.Windows;

namespace Agamemnon.App.Services;

/// <summary>
/// Files and folders sent with "Scan with Agamemnon" in File Explorer. A second Agamemnon.exe
/// started by Explorer writes them to the user's own data folder and wakes the running one,
/// which scans them. A request can only ask for a scan, so nothing is gained by faking one.
/// </summary>
public static class ScanRequests
{
    public const string Switch = "--scan";

    private static string Folder => Path.Combine(AgamemnonPaths.UserLocalData, "ScanRequests");

    public static bool HasPending => Directory.Exists(Folder) && Directory.EnumerateFiles(Folder, "*.txt").Any();

    public static void Queue(IEnumerable<string> paths)
    {
        Directory.CreateDirectory(Folder);
        string file = Path.Combine(Folder, $"{Guid.NewGuid():N}.txt");
        File.WriteAllLines(file + ".tmp", paths.Where(p => !string.IsNullOrWhiteSpace(p)), new UTF8Encoding(false));
        File.Move(file + ".tmp", file);
    }

    public static IReadOnlyList<string> TakeAll()
    {
        if (!Directory.Exists(Folder))
        {
            return [];
        }

        var paths = new List<string>();
        foreach (string file in Directory.EnumerateFiles(Folder, "*.txt").ToList())
        {
            try
            {
                paths.AddRange(File.ReadAllLines(file).Where(p => File.Exists(p) || Directory.Exists(p)));
                File.Delete(file);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
            }
        }

        return [.. paths.Distinct(StringComparer.OrdinalIgnoreCase).Take(1000)];
    }
}
