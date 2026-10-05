namespace Agamemnon.Platform.Windows;

/// <summary>Where Agamemnon keeps its files on Windows.</summary>
public static class AgamemnonPaths
{
    /// <summary>Install directory (Program Files\Agamemnon): binaries, bundled engines and rules.</summary>
    public static string InstallDirectory => AppContext.BaseDirectory;

    public static string ClamAvBinaries => Path.Combine(InstallDirectory, "engines", "clamav");

    public static string YaraBinaries => Path.Combine(InstallDirectory, "engines", "yara");

    public static string BundledRules => Path.Combine(InstallDirectory, "rules");

    /// <summary>Machine-wide service state (%ProgramData%\Agamemnon), writable only by SYSTEM and administrators.</summary>
    public static string MachineData =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Agamemnon");

    public static string ClamAvData => Path.Combine(MachineData, "ClamAV");

    /// <summary>Per-user settings (%APPDATA%\Agamemnon).</summary>
    public static string UserSettings =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Agamemnon");

    /// <summary>Per-user data that doesn't roam (%LOCALAPPDATA%\Agamemnon): quarantine, caches, user YARA rules.</summary>
    public static string UserLocalData =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Agamemnon");

    public static string UserRules => Path.Combine(UserLocalData, "Rules");

    public static string Quarantine => Path.Combine(UserLocalData, "Quarantine");

    public static string ScanWork => Path.Combine(UserLocalData, "Work");
}
