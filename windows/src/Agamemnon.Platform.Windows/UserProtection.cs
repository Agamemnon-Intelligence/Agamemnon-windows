using System.ComponentModel;
using System.Runtime.InteropServices;
using Agamemnon.Core.Protection;
using Agamemnon.Core.Startup;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace Agamemnon.Platform.Windows;

/// <summary>Everything that starts with Windows that the signed-in user can see.</summary>
public static class StartupEnumerator
{
    private static readonly string[] RunKeys =
    [
        @"Software\Microsoft\Windows\CurrentVersion\Run",
        @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    ];

    public static IReadOnlyList<StartupItem> List(bool includeTasks)
    {
        var items = new List<StartupItem>();
        foreach (string key in RunKeys)
        {
            ReadRunKey(Registry.CurrentUser, key, StartupLocation.UserRunKey, items);
            ReadRunKey(Registry.LocalMachine, key, StartupLocation.MachineRunKey, items);
        }

        foreach (string folder in new[] { Environment.GetFolderPath(Environment.SpecialFolder.Startup), Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup) })
        {
            if (string.IsNullOrEmpty(folder) || !Directory.Exists(folder))
            {
                continue;
            }

            foreach (string file in SafeFiles(folder).Where(f => !Path.GetFileName(f).Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)))
            {
                items.Add(new StartupItem(StartupLocation.StartupFolder, Path.GetFileName(file), file, file));
            }
        }

        ReadWinlogon(items);
        if (includeTasks)
        {
            ReadScheduledTasks(items);
        }

        return items;
    }

    private static void ReadRunKey(RegistryKey hive, string path, StartupLocation location, List<StartupItem> items)
    {
        try
        {
            using RegistryKey? key = hive.OpenSubKey(path);
            if (key is null)
            {
                return;
            }

            foreach (string name in key.GetValueNames())
            {
                if (key.GetValue(name) is string command && command.Length > 0)
                {
                    items.Add(new StartupItem(location, $@"{(hive == Registry.CurrentUser ? "HKCU" : "HKLM")}\{path}\{name}", command));
                }
            }
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
        }
    }

    /// <summary>Winlogon's Shell and Userinit should be explorer.exe and userinit.exe; anything added runs at every sign-in.</summary>
    private static void ReadWinlogon(List<StartupItem> items)
    {
        try
        {
            using RegistryKey? key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon");
            if (key?.GetValue("Shell") is string shell && !shell.Trim().Equals("explorer.exe", StringComparison.OrdinalIgnoreCase))
            {
                items.Add(new StartupItem(StartupLocation.SystemHook, "Winlogon Shell", shell));
            }

            if (key?.GetValue("Userinit") is string userinit
                && userinit.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .Any(p => !p.EndsWith(@"\system32\userinit.exe", StringComparison.OrdinalIgnoreCase) && !p.Equals("userinit.exe", StringComparison.OrdinalIgnoreCase)))
            {
                items.Add(new StartupItem(StartupLocation.SystemHook, "Winlogon Userinit", userinit));
            }
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
        }
    }

    /// <summary>Scheduled tasks that run a program, through the Task Scheduler's COM interface.</summary>
    private static void ReadScheduledTasks(List<StartupItem> items)
    {
        if (Type.GetTypeFromProgID("Schedule.Service") is not { } type)
        {
            return;
        }

        dynamic? service = null;
        try
        {
            service = Activator.CreateInstance(type);
            service!.Connect();
            var folders = new Stack<dynamic>();
            folders.Push(service.GetFolder(@"\"));
            while (folders.Count > 0 && items.Count < 5000)
            {
                dynamic folder = folders.Pop();
                string folderPath = folder.Path;
                if (folderPath.StartsWith(@"\Microsoft\", StringComparison.OrdinalIgnoreCase))
                {
                    continue; // Windows' own tasks
                }

                foreach (dynamic sub in folder.GetFolders(0))
                {
                    folders.Push(sub);
                }

                foreach (dynamic task in folder.GetTasks(1 /* include hidden */))
                {
                    try
                    {
                        foreach (dynamic action in task.Definition.Actions)
                        {
                            if ((int)action.Type == 0)
                            {
                                string program = action.Path ?? string.Empty;
                                string arguments = action.Arguments ?? string.Empty;
                                items.Add(new StartupItem(StartupLocation.ScheduledTask, (string)task.Path, $"\"{program}\" {arguments}".Trim(), program));
                            }
                        }
                    }
                    catch (COMException)
                    {
                    }
                }
            }
        }
        catch (Exception ex) when (ex is COMException or UnauthorizedAccessException or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException or InvalidCastException)
        {
        }
        finally
        {
            if (service is not null)
            {
                Marshal.FinalReleaseComObject(service);
            }
        }
    }

    private static IEnumerable<string> SafeFiles(string folder)
    {
        try
        {
            return [.. Directory.EnumerateFiles(folder)];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }
}

/// <summary>Which apps are using the camera and microphone, from Windows' privacy records.</summary>
public static class DeviceUsageReader
{
    private const string Store = @"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore";

    public static IReadOnlyList<DeviceUse> Read()
    {
        var uses = new List<DeviceUse>();
        Read(PrivacyDevice.Camera, "webcam", uses);
        Read(PrivacyDevice.Microphone, "microphone", uses);
        return uses;
    }

    private static void Read(PrivacyDevice device, string capability, List<DeviceUse> uses)
    {
        try
        {
            using RegistryKey? root = Registry.CurrentUser.OpenSubKey($@"{Store}\{capability}");
            if (root is null)
            {
                return;
            }

            foreach (string name in root.GetSubKeyNames())
            {
                using RegistryKey? app = root.OpenSubKey(name);
                if (app is null)
                {
                    continue;
                }

                if (name.Equals("NonPackaged", StringComparison.OrdinalIgnoreCase))
                {
                    foreach (string program in app.GetSubKeyNames())
                    {
                        using RegistryKey? entry = app.OpenSubKey(program);
                        if (entry is not null)
                        {
                            uses.Add(new DeviceUse(device, program, true, Time(entry, "LastUsedTimeStart"), Time(entry, "LastUsedTimeStop")));
                        }
                    }
                }
                else
                {
                    uses.Add(new DeviceUse(device, name, false, Time(app, "LastUsedTimeStart"), Time(app, "LastUsedTimeStop")));
                }
            }
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
        }
    }

    private static long Time(RegistryKey key, string name) => key.GetValue(name) is long value ? value : 0;
}

/// <summary>Safely ejects a removable drive, like "Eject" in File Explorer.</summary>
public static partial class DriveEjector
{
    private const uint GenericRead = 0x80000000;
    private const uint GenericWrite = 0x40000000;
    private const uint FileShareReadWrite = 3;
    private const uint OpenExisting = 3;
    private const uint FsctlLockVolume = 0x00090018;
    private const uint FsctlDismountVolume = 0x00090020;
    private const uint IoctlStorageMediaRemoval = 0x002D4804;
    private const uint IoctlStorageEjectMedia = 0x002D4808;

    /// <param name="root">"E:\".</param>
    /// <returns>True when Windows let go of the drive; false when a program still has files open on it.</returns>
    public static bool TryEject(string root)
    {
        string letter = root.TrimEnd('\\', ':');
        using SafeFileHandle volume = CreateFileW($@"\\.\{letter}:", GenericRead | GenericWrite, FileShareReadWrite, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
        if (volume.IsInvalid)
        {
            return false;
        }

        if (!DeviceIoControl(volume, FsctlLockVolume, IntPtr.Zero, 0, IntPtr.Zero, 0, out _, IntPtr.Zero)
            || !DeviceIoControl(volume, FsctlDismountVolume, IntPtr.Zero, 0, IntPtr.Zero, 0, out _, IntPtr.Zero))
        {
            return false;
        }

        byte allowRemoval = 0;
        _ = DeviceIoControl(volume, IoctlStorageMediaRemoval, ref allowRemoval, 1, IntPtr.Zero, 0, out _, IntPtr.Zero);
        return DeviceIoControl(volume, IoctlStorageEjectMedia, IntPtr.Zero, 0, IntPtr.Zero, 0, out _, IntPtr.Zero);
    }

    [LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool DeviceIoControl(SafeFileHandle device, uint code, IntPtr input, uint inputSize, IntPtr output, uint outputSize, out uint returned, IntPtr overlapped);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool DeviceIoControl(SafeFileHandle device, uint code, ref byte input, uint inputSize, IntPtr output, uint outputSize, out uint returned, IntPtr overlapped);
}

public sealed record FileUser(int ProcessId, string Name, string? Path);

/// <summary>
/// Which programs have given files open, from the Restart Manager (the same API installers use to
/// say "close these apps first"). The ransomware shield uses it to find who is changing files.
/// </summary>
public static partial class FileUsers
{
    private const int ErrorMoreData = 234;
    private const int CchRmMaxAppName = 255;
    private const int CchRmMaxSvcName = 63;

    public static IReadOnlyList<FileUser> Find(IReadOnlyList<string> files)
    {
        if (files.Count == 0 || RmStartSession(out uint session, 0, new string('\0', 33)) != 0)
        {
            return [];
        }

        try
        {
            string[] resources = [.. files.Take(64)];
            if (RmRegisterResources(session, (uint)resources.Length, resources, 0, IntPtr.Zero, 0, IntPtr.Zero) != 0)
            {
                return [];
            }

            uint needed = 0;
            uint count = 0;
            int result = RmGetList(session, out needed, ref count, null, out _);
            if (result != ErrorMoreData || needed == 0)
            {
                return [];
            }

            var infos = new RmProcessInfo[needed];
            count = needed;
            if (RmGetList(session, out needed, ref count, infos, out _) != 0)
            {
                return [];
            }

            var users = new List<FileUser>();
            foreach (RmProcessInfo info in infos.Take((int)count))
            {
                int pid = info.Process.ProcessId;
                string? path = null;
                try
                {
                    using var process = System.Diagnostics.Process.GetProcessById(pid);
                    path = process.MainModule?.FileName;
                }
                catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or Win32Exception)
                {
                }

                users.Add(new FileUser(pid, info.AppName, path));
            }

            return users;
        }
        finally
        {
            _ = RmEndSession(session);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct RmUniqueProcess
    {
        public int ProcessId;
        public System.Runtime.InteropServices.ComTypes.FILETIME StartTime;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct RmProcessInfo
    {
        public RmUniqueProcess Process;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CchRmMaxAppName + 1)]
        public string AppName;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CchRmMaxSvcName + 1)]
        public string ServiceShortName;

        public int ApplicationType;
        public uint AppStatus;
        public uint TSSessionId;

        [MarshalAs(UnmanagedType.Bool)]
        public bool Restartable;
    }

#pragma warning disable SYSLIB1054 // RmGetList fills an array of structs with inline strings; classic marshalling handles that.
    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmStartSession(out uint session, int flags, string key);

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmRegisterResources(uint session, uint files, string[] fileNames, uint applications, IntPtr processes, uint services, IntPtr serviceNames);

    [DllImport("rstrtmgr.dll")]
    private static extern int RmGetList(uint session, out uint needed, ref uint count, [In, Out] RmProcessInfo[]? processes, out uint rebootReasons);

    [DllImport("rstrtmgr.dll")]
    private static extern int RmEndSession(uint session);
#pragma warning restore SYSLIB1054
}
