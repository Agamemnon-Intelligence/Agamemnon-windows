using System.Runtime.InteropServices;
using Agamemnon.Core.Scanning;

namespace Agamemnon.Platform.Windows;

/// <summary>
/// Windows' Antimalware Scan Interface: hands file contents to the antivirus registered with
/// Windows (normally Microsoft Defender) and reads its verdict. This is Windows' counterpart of
/// the Mac app using Apple's XProtect rules: Microsoft's own, constantly updated detections
/// become one more engine, without Agamemnon replacing Defender. Only content is passed;
/// Defender doesn't remove or move anything for a buffer scan, Agamemnon's quarantine does that.
/// </summary>
public sealed partial class AmsiEngine : IScanEngine, IDisposable
{
    /// <summary>AMSI is meant for scripts and small payloads; big files are left to the other engines.</summary>
    public const long MaxBytes = 16L * 1024 * 1024;

    private const int AmsiResultDetected = 32768;
    private const int AmsiResultBlockedByAdminStart = 0x4000;
    private const int AmsiResultBlockedByAdminEnd = 0x4FFF;

    private readonly Lock _gate = new();
    private IntPtr _context;
    private bool _unavailable;

    public string Name => "Microsoft Defender (AMSI)";

    public Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken) =>
        Task.FromResult(EnsureContext() != IntPtr.Zero
            ? new EngineStatus(true, "Windows' antivirus checks scripts, documents and programs")
            : new EngineStatus(false, "No antivirus is registered with Windows' scan interface."));

    public async Task<IReadOnlyList<EngineResult>> ScanAsync(IReadOnlyList<ScanTarget> batch, CancellationToken cancellationToken)
    {
        IntPtr context = EnsureContext();
        var results = new EngineResult[batch.Count];
        for (int i = 0; i < batch.Count; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ScanTarget target = batch[i];
            if (context == IntPtr.Zero || target.Size is 0 or > MaxBytes || !FileClassifier.IsRiskyKind(target.Kind))
            {
                results[i] = EngineResult.Clean;
                continue;
            }

            try
            {
                byte[] content = await File.ReadAllBytesAsync(target.Path, cancellationToken).ConfigureAwait(false);
                results[i] = Scan(context, content, target.DisplayPath);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                results[i] = EngineResult.Failed($"AMSI: {ex.Message}");
            }
        }

        return results;
    }

    private static EngineResult Scan(IntPtr context, byte[] content, string name)
    {
        int hr = AmsiScanBuffer(context, content, (uint)content.Length, name, IntPtr.Zero, out int result);
        if (hr != 0)
        {
            return EngineResult.Failed($"AMSI: scan failed (0x{hr:X8})");
        }

        if (result >= AmsiResultDetected)
        {
            return new EngineResult([new Detection("Microsoft Defender (AMSI)", "Detected by Windows' antivirus", Severity.Malicious)]);
        }

        return result is >= AmsiResultBlockedByAdminStart and <= AmsiResultBlockedByAdminEnd
            ? new EngineResult([new Detection("Microsoft Defender (AMSI)", "Blocked by your organisation's policy", Severity.Suspicious)])
            : EngineResult.Clean;
    }

    private IntPtr EnsureContext()
    {
        lock (_gate)
        {
            if (_context != IntPtr.Zero || _unavailable)
            {
                return _context;
            }

            try
            {
                if (AmsiInitialize("Agamemnon", out IntPtr context) == 0)
                {
                    _context = context;
                }
                else
                {
                    _unavailable = true;
                }
            }
            catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
            {
                _unavailable = true;
            }

            return _context;
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_context != IntPtr.Zero)
            {
                AmsiUninitialize(_context);
                _context = IntPtr.Zero;
            }
        }
    }

    [LibraryImport("amsi.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int AmsiInitialize(string appName, out IntPtr context);

    [LibraryImport("amsi.dll")]
    private static partial void AmsiUninitialize(IntPtr context);

    [LibraryImport("amsi.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int AmsiScanBuffer(IntPtr context, byte[] buffer, uint length, string contentName, IntPtr session, out int result);
}
