using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Agamemnon.Core.Ipc;
using Agamemnon.Core.Recovery;
using Agamemnon.Platform.Windows;

namespace Agamemnon.Service;

/// <summary>
/// 5.0 ransomware recovery, run as SYSTEM. Takes a restore point of the system drive every day,
/// keeps Agamemnon's last seven, and gives people back earlier copies of their own files:
/// <list type="number">
/// <item>the caller's permissions on the file <i>in the restore point</i> are checked with Windows'
/// AccessCheck, so nobody gets a copy of a file they couldn't open;</item>
/// <item>the copy goes into a new folder under %ProgramData%\Agamemnon\Recovery that only SYSTEM and
/// the caller can open. The service never writes into a folder the caller chose, so a link or
/// junction can't trick it into writing somewhere else;</item>
/// <item>the app, running as the user, copies it to its place and deletes the temporary copy.</item>
/// </list>
/// </summary>
public sealed class RecoveryWorker(ILogger<RecoveryWorker> logger) : BackgroundService
{
    private static readonly string StatePath = Path.Combine(AgamemnonPaths.MachineData, "recovery.json");
    private static readonly string TempRoot = Path.Combine(AgamemnonPaths.MachineData, "Recovery");
    private readonly Lock _gate = new();
    private DateTimeOffset _lastManual = DateTimeOffset.MinValue;
    private string? _lastError;

    private static string SystemDrive => Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows)) ?? "C:\\";

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Let Windows finish starting before asking VSS for anything.
        try
        {
            await Task.Delay(TimeSpan.FromMinutes(3), stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                CleanTemporaryCopies();
                if (RecoveryPlanner.IsDailyPointDue(ListPoints(), DateTimeOffset.Now))
                {
                    Create(manual: false);
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Management.ManagementException or System.Runtime.InteropServices.COMException)
            {
                _lastError = ex.Message;
                logger.LogWarning(ex, "Daily restore point failed");
            }

            try
            {
                await Task.Delay(TimeSpan.FromHours(1), stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    public RecoveryStatus Status()
    {
        try
        {
            return new RecoveryStatus(ListPoints(), _lastError);
        }
        catch (System.Management.ManagementException ex)
        {
            return new RecoveryStatus([], ex.Message);
        }
    }

    /// <summary>Takes a restore point of the system drive and prunes Agamemnon's oldest ones.</summary>
    public RecoveryStatus Create(bool manual)
    {
        lock (_gate)
        {
            if (manual && DateTimeOffset.Now - _lastManual < RecoveryPlanner.ManualCooldown)
            {
                throw new IpcException("A restore point was taken a few minutes ago. Try again later.");
            }

            string id = ShadowCopies.Create(SystemDrive);
            if (manual)
            {
                _lastManual = DateTimeOffset.Now;
            }

            State state = LoadState();
            state = state with { AgamemnonIds = [.. state.AgamemnonIds.Append(id).Distinct(StringComparer.OrdinalIgnoreCase)] };
            foreach (RestorePoint old in RecoveryPlanner.ToRemove(ShadowCopies.List(Ids(state))))
            {
                try
                {
                    ShadowCopies.Delete(old.Id);
                    state = state with { AgamemnonIds = [.. state.AgamemnonIds.Where(i => !i.Equals(old.Id, StringComparison.OrdinalIgnoreCase))] };
                }
                catch (System.Management.ManagementException ex)
                {
                    logger.LogWarning(ex, "Couldn't remove old restore point {Id}", old.Id);
                }
            }

            SaveState(state);
            _lastError = null;
            logger.LogInformation("Restore point {Id} taken of {Drive}", id, SystemDrive);
            return new RecoveryStatus(ShadowCopies.List(Ids(state)));
        }
    }

    public IReadOnlyList<FileVersion> Versions(string path, PipeCaller caller)
    {
        string normalized = RecoveryPlanner.Normalize(path) ?? throw new IpcException("That isn't a file on this PC.");
        var versions = new List<FileVersion>();
        foreach (RestorePoint point in ListPoints())
        {
            if (RecoveryPlanner.PathInPoint(point, normalized) is { } inPoint && Readable(inPoint, caller) is { } info)
            {
                versions.Add(new FileVersion(point.Id, point.CreatedAt, info.Length, new DateTimeOffset(info.LastWriteTimeUtc, TimeSpan.Zero)));
            }
        }

        logger.LogDebug("{Count} earlier copies of {Path} for {User}", versions.Count, normalized, caller.Sid);
        return versions;
    }

    public RecoveryFetchResult Fetch(RecoveryFetchRequest request, PipeCaller caller)
    {
        string normalized = RecoveryPlanner.Normalize(request.Path) ?? throw new IpcException("That isn't a file on this PC.");
        RestorePoint point = ListPoints().FirstOrDefault(p => p.Id.Equals(request.PointId, StringComparison.OrdinalIgnoreCase))
            ?? throw new IpcException("That restore point no longer exists.");
        string source = RecoveryPlanner.PathInPoint(point, normalized) ?? throw new IpcException("That restore point is of another drive.");
        if (Readable(source, caller) is null)
        {
            throw new UnauthorizedAccessException("That restore point has no copy of this file that you can open.");
        }

        string folder = Path.Combine(TempRoot, Guid.NewGuid().ToString("N"));
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(caller.Sid, FileSystemRights.ReadAndExecute | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles, inherit, PropagationFlags.None, AccessControlType.Allow));
        Directory.CreateDirectory(TempRoot);
        new DirectoryInfo(folder).Create(security);
        string target = Path.Combine(folder, WinFileName(normalized));
        File.Copy(source, target);
        logger.LogInformation("Earlier copy of {Path} from restore point {Point} handed to {User}", normalized, point.Id, caller.Sid);
        return new RecoveryFetchResult(target);
    }

    private static string WinFileName(string path) => path[(path.LastIndexOf('\\') + 1)..];

    /// <summary>The file in the restore point, if it exists and the caller may read it.</summary>
    private static FileInfo? Readable(string pathInPoint, PipeCaller caller)
    {
        try
        {
            var info = new FileInfo(pathInPoint);
            if (!info.Exists || info.Attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                return null;
            }

            using var stream = new FileStream(pathInPoint, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            return FileAccessCheck.CanRead(stream.GetAccessControl(), caller.Token) ? info : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return null;
        }
    }

    private static void CleanTemporaryCopies()
    {
        if (!Directory.Exists(TempRoot))
        {
            return;
        }

        foreach (DirectoryInfo folder in new DirectoryInfo(TempRoot).EnumerateDirectories())
        {
            if (DateTime.UtcNow - folder.CreationTimeUtc > TimeSpan.FromHours(1))
            {
                try
                {
                    folder.Delete(recursive: true);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                }
            }
        }
    }

    private static IReadOnlyList<RestorePoint> ListPoints() => ShadowCopies.List(Ids(LoadState()));

    private static HashSet<string> Ids(State state) => new(state.AgamemnonIds, StringComparer.OrdinalIgnoreCase);

    private static State LoadState()
    {
        try
        {
            return File.Exists(StatePath) ? JsonSerializer.Deserialize<State>(File.ReadAllText(StatePath)) ?? new State() : new State();
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            return new State();
        }
    }

    private static void SaveState(State state)
    {
        Directory.CreateDirectory(AgamemnonPaths.MachineData);
        File.WriteAllText(StatePath, JsonSerializer.Serialize(state));
    }

    private sealed record State
    {
        public IReadOnlyList<string> AgamemnonIds { get; init; } = [];
    }
}
