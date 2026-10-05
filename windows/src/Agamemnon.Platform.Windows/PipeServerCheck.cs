using System.IO.Pipes;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Agamemnon.Platform.Windows;

/// <summary>
/// Confirms a named pipe is served from session 0, where Windows services run. Signed-in users'
/// programs run in session 1 or higher and can't start processes in session 0, so a program
/// that grabbed the pipe name before the service started can't pass this check.
/// </summary>
public static partial class PipeServerCheck
{
    public static bool IsService(NamedPipeClientStream pipe) =>
        GetNamedPipeServerSessionId(pipe.SafePipeHandle, out uint sessionId) && sessionId == 0;

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeServerSessionId(SafePipeHandle pipe, out uint sessionId);
}
