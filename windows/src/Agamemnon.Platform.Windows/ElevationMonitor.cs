using System.Collections.Concurrent;
using System.Diagnostics.Eventing.Reader;
using System.Management;
using System.Runtime.InteropServices;
using Agamemnon.Core.Ipc;
using Agamemnon.Core.Scanning;
using Microsoft.Win32.SafeHandles;

namespace Agamemnon.Platform.Windows;

/// <summary>
/// Watches for programs gaining administrator rights. Runs in the LocalSystem service.
/// <list type="bullet">
/// <item>A process starts with a full (elevated) token whose parent had a limited token: that is
/// exactly a UAC elevation from the user's desktop, whether by prompt or silent auto-elevation.</item>
/// <item>The Service Control Manager logs event 7045: a new service was installed. Services run
/// as SYSTEM, so this is the other common way software takes over a PC.</item>
/// </list>
/// Windows itself already shows the UAC prompt; these alerts add who signed the program and
/// where it lives, and catch silent elevations the user never saw.
/// </summary>
public sealed partial class ElevationMonitor(ISignatureVerifier verifier) : IDisposable
{
    private const int TokenElevationTypeQuery = 18;
    private const int ElevationTypeFull = 2;
    private const int ElevationTypeLimited = 3;
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint TokenQuery = 0x0008;

    private readonly ConcurrentDictionary<string, DateTimeOffset> _recent = new(StringComparer.OrdinalIgnoreCase);
    private ManagementEventWatcher? _processWatcher;
    private EventLogWatcher? _serviceWatcher;

    public event EventHandler<ServiceEvent>? Alert;

    public void Start()
    {
        _processWatcher = new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));
        _processWatcher.EventArrived += (_, e) => OnProcessStarted(e.NewEvent);
        _processWatcher.Start();

        var query = new EventLogQuery("System", PathType.LogName,
            "*[System[Provider[@Name='Service Control Manager'] and (EventID=7045)]]");
        _serviceWatcher = new EventLogWatcher(query);
        _serviceWatcher.EventRecordWritten += (_, e) => OnServiceInstalled(e.EventRecord);
        _serviceWatcher.Enabled = true;
    }

    private void OnProcessStarted(ManagementBaseObject trace)
    {
        try
        {
            int pid = Convert.ToInt32(trace["ProcessID"], System.Globalization.CultureInfo.InvariantCulture);
            int parentPid = Convert.ToInt32(trace["ParentProcessID"], System.Globalization.CultureInfo.InvariantCulture);
            int sessionId = Convert.ToInt32(trace["SessionID"], System.Globalization.CultureInfo.InvariantCulture);
            if (sessionId == 0 || ElevationType(pid) != ElevationTypeFull || ElevationType(parentPid) != ElevationTypeLimited)
            {
                return;
            }

            string? path = ImagePath(pid);
            if (path is null || !FirstTimeRecently(path))
            {
                return;
            }

            SignatureInfo signature = verifier.Verify(path, onlineRevocationCheck: false);
            if (IsWindowsComponent(path, signature))
            {
                return; // Task Manager, Registry Editor, etc. auto-elevating for an admin: not news.
            }

            Alert?.Invoke(this, new ServiceEvent
            {
                Kind = ServiceEventKind.ElevationGranted,
                SessionId = sessionId,
                ProgramPath = path,
                ProgramName = Path.GetFileName(path),
                CommandLine = CommandLine(pid),
                Publisher = signature.Publisher,
                SignatureState = signature.State.ToString(),
                ParentName = ImagePath(parentPid) is { } parent ? Path.GetFileName(parent) : null,
            });
        }
        catch (Exception ex) when (ex is ManagementException or InvalidCastException or FormatException or IOException or UnauthorizedAccessException)
        {
            // Short-lived processes may be gone before we look; nothing to report.
        }
    }

    private void OnServiceInstalled(EventRecord? record)
    {
        if (record is null)
        {
            return;
        }

        using (record)
        {
            string? name = record.Properties.ElementAtOrDefault(0)?.Value as string;
            string? image = record.Properties.ElementAtOrDefault(1)?.Value as string;
            string? path = ExecutableFromCommand(image);
            SignatureInfo? signature = null;
            if (path is not null && File.Exists(path))
            {
                signature = verifier.Verify(path, onlineRevocationCheck: true);
            }

            Alert?.Invoke(this, new ServiceEvent
            {
                Kind = ServiceEventKind.ServiceInstalled,
                ProgramName = name,
                ProgramPath = path,
                CommandLine = image,
                Publisher = signature?.Publisher,
                SignatureState = signature?.State.ToString(),
            });
        }
    }

    private static bool IsWindowsComponent(string path, SignatureInfo signature) =>
        signature.State == SignatureState.Trusted
        && string.Equals(signature.Publisher, "Microsoft Windows", StringComparison.Ordinal)
        && path.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Windows) + "\\", StringComparison.OrdinalIgnoreCase);

    private bool FirstTimeRecently(string path)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        foreach (var stale in _recent.Where(kv => now - kv.Value > TimeSpan.FromMinutes(1)))
        {
            _recent.TryRemove(stale);
        }

        return _recent.TryAdd(path, now);
    }

    /// <summary>"\"C:\Program Files\X\svc.exe\" -k" or "C:\x\svc.exe -k" → the executable path.</summary>
    internal static string? ExecutableFromCommand(string? command)
    {
        if (string.IsNullOrWhiteSpace(command))
        {
            return null;
        }

        string text = Environment.ExpandEnvironmentVariables(command.Trim());
        if (text.StartsWith('"'))
        {
            int end = text.IndexOf('"', 1);
            return end > 1 ? text[1..end] : null;
        }

        int exe = text.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        return exe > 0 ? text[..(exe + 4)] : text.Split(' ')[0];
    }

    private static int ElevationType(int pid)
    {
        using SafeProcessHandle process = OpenProcess(ProcessQueryLimitedInformation, false, (uint)pid);
        if (process.IsInvalid || !OpenProcessToken(process, TokenQuery, out SafeAccessTokenHandle token))
        {
            return 0;
        }

        using (token)
        {
            return GetTokenInformation(token, TokenElevationTypeQuery, out int type, sizeof(int), out _) ? type : 0;
        }
    }

    private static string? ImagePath(int pid)
    {
        using SafeProcessHandle process = OpenProcess(ProcessQueryLimitedInformation, false, (uint)pid);
        if (process.IsInvalid)
        {
            return null;
        }

        char[] buffer = new char[32768];
        uint length = (uint)buffer.Length;
        return QueryFullProcessImageNameW(process, 0, buffer, ref length) ? new string(buffer, 0, (int)length) : null;
    }

    private static string? CommandLine(int pid)
    {
        using var searcher = new ManagementObjectSearcher($"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
        foreach (ManagementBaseObject process in searcher.Get())
        {
            using (process)
            {
                return process["CommandLine"] as string;
            }
        }

        return null;
    }

    public void Dispose()
    {
        _processWatcher?.Stop();
        _processWatcher?.Dispose();
        _serviceWatcher?.Dispose();
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint processId);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool OpenProcessToken(SafeProcessHandle process, uint access, out SafeAccessTokenHandle token);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetTokenInformation(SafeAccessTokenHandle token, int informationClass, out int information, int length, out int returnLength);

    [LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool QueryFullProcessImageNameW(SafeProcessHandle process, uint flags, [Out] char[] name, ref uint size);
}
