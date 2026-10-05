using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Agamemnon.Core.Dns;
using Agamemnon.Core.Ipc;
using Microsoft.Win32;

namespace Agamemnon.App.Services;

public static partial class KnownFolders
{
    private static readonly Guid DownloadsId = new("374DE290-123F-4565-9164-39C4925E467B");

    /// <summary>The user's Downloads folder, even if they moved it to another drive.</summary>
    public static string Downloads
    {
        get
        {
            if (SHGetKnownFolderPath(DownloadsId, 0, IntPtr.Zero, out IntPtr path) == 0)
            {
                try
                {
                    return Marshal.PtrToStringUni(path)!;
                }
                finally
                {
                    Marshal.FreeCoTaskMem(path);
                }
            }

            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        }
    }

    [LibraryImport("shell32.dll")]
    private static partial int SHGetKnownFolderPath(in Guid id, uint flags, IntPtr token, out IntPtr path);
}

/// <summary>Start with Windows, via the per-user Run key (no admin rights needed).</summary>
public static class AutoStart
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string ValueName = "Agamemnon";

    public static bool IsEnabled
    {
        get
        {
            using RegistryKey? key = Registry.CurrentUser.OpenSubKey(RunKey);
            return key?.GetValue(ValueName) is string;
        }
    }

    public static void Set(bool enabled)
    {
        using RegistryKey key = Registry.CurrentUser.CreateSubKey(RunKey);
        if (enabled)
        {
            key.SetValue(ValueName, $"\"{Environment.ProcessPath}\" --background");
        }
        else
        {
            key.DeleteValue(ValueName, throwOnMissingValue: false);
        }
    }
}

/// <summary>
/// The two actions that need administrator rights run in a short-lived elevated copy of
/// Agamemnon. Their input travels on the command line, which another process can't change
/// after launch (a temp file could be swapped between the UAC prompt and the read).
/// </summary>
public static class ElevatedActions
{
    public const string ApplyDnsSwitch = "--apply-dns";
    public const string QuarantineSwitch = "--quarantine";

    public static Task<bool> ApplyDnsAsync(DnsSettings settings) =>
        RunElevatedAsync(ApplyDnsSwitch, Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(settings, IpcProtocol.Json)));

    public static Task<bool> QuarantineAsync(string path) =>
        RunElevatedAsync(QuarantineSwitch, Convert.ToBase64String(Encoding.UTF8.GetBytes(path)));

    public static DnsSettings DecodeDns(string argument) =>
        JsonSerializer.Deserialize<DnsSettings>(Convert.FromBase64String(argument), IpcProtocol.Json)
        ?? throw new InvalidDataException("Invalid DNS settings.");

    public static string DecodePath(string argument) => Encoding.UTF8.GetString(Convert.FromBase64String(argument));

    private static async Task<bool> RunElevatedAsync(string action, string argument)
    {
        // Both parts are a fixed switch and base64 (no spaces or quotes), so plain joining is safe.
        var info = new ProcessStartInfo(Environment.ProcessPath!)
        {
            UseShellExecute = true,
            Verb = "runas",
            Arguments = $"{action} {argument}",
        };
        try
        {
            using Process? process = Process.Start(info);
            if (process is null)
            {
                return false;
            }

            await process.WaitForExitAsync().ConfigureAwait(false);
            return process.ExitCode == 0;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return false; // the user said no at the UAC prompt
        }
    }
}

public static partial class DarkTitleBar
{
    /// <summary>Asks Windows to draw the title bar dark, matching the app.</summary>
    public static void Apply(System.Windows.Window window)
    {
        IntPtr handle = new System.Windows.Interop.WindowInteropHelper(window).EnsureHandle();
        int enabled = 1;
        // DWMWA_USE_IMMERSIVE_DARK_MODE: 20 on Windows 10 2004+ and 11.
        _ = DwmSetWindowAttribute(handle, 20, ref enabled, sizeof(int));
    }

    [LibraryImport("dwmapi.dll")]
    private static partial int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);
}

public static class Shell
{
    public static void Open(string target)
    {
        try
        {
            Process.Start(new ProcessStartInfo(target) { UseShellExecute = true })?.Dispose();
        }
        catch (System.ComponentModel.Win32Exception)
        {
        }
    }

    public static void RevealInExplorer(string path)
    {
        try
        {
            Process.Start(new ProcessStartInfo("explorer.exe") { ArgumentList = { "/select,", path } })?.Dispose();
        }
        catch (System.ComponentModel.Win32Exception)
        {
        }
    }
}
