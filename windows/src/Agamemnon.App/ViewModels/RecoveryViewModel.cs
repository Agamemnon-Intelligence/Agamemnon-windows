using System.Collections.ObjectModel;
using System.Globalization;
using System.Windows.Media;
using Agamemnon.App.Localization;
using Agamemnon.App.Services;
using Agamemnon.Core.Ipc;
using Agamemnon.Core.Recovery;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;

namespace Agamemnon.App.ViewModels;

public sealed class RestorePointRow(RestorePoint point)
{
    public string When => point.CreatedAt.ToLocalTime().ToString("g", CultureInfo.CurrentCulture);

    public string Detail => L.F(point.ByAgamemnon ? "recovery.point.agamemnon" : "recovery.point.windows", point.Volume.TrimEnd('\\'));
}

public sealed partial class FileVersionRow(FileVersion version, RecoveryViewModel owner) : ObservableObject
{
    public FileVersion Version => version;

    public string When => L.F("recovery.version.when", version.PointCreatedAt.ToLocalTime().ToString("g", CultureInfo.CurrentCulture));

    public string Detail => L.F("recovery.version.detail", version.LastWrite.ToLocalTime().ToString("g", CultureInfo.CurrentCulture), version.Size / 1024.0);

    [RelayCommand]
    private Task RestoreAsync() => owner.RestoreVersionAsync(this);
}

/// <summary>
/// 5.0's Recovery page: Windows restore points taken every day by the service, earlier copies of
/// any of your files, and "put them all back" after the ransomware shield stepped in.
/// </summary>
public sealed partial class RecoveryViewModel(AppServices services) : PageViewModel
{
    public override NavigationTarget Target => NavigationTarget.Recovery;

    public ObservableCollection<RestorePointRow> Points { get; } = [];

    public ObservableCollection<FileVersionRow> Versions { get; } = [];

    /// <summary>The newest restore point, for the protection score.</summary>
    public DateTimeOffset? NewestPoint { get; private set; }

    public bool HasRecentPoint => NewestPoint is { } at && DateTimeOffset.Now - at < TimeSpan.FromHours(48);

    public event EventHandler? PointsChanged;

    [ObservableProperty]
    public partial string PointsSummary { get; set; } = L.T("recovery.points.loading");

    [ObservableProperty]
    public partial string? SelectedFile { get; set; }

    [ObservableProperty]
    public partial string Message { get; set; } = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsIdle))]
    public partial bool IsBusy { get; set; }

    public bool IsIdle => !IsBusy;

    public RansomwareIncident? Incident => services.LastIncident is { Files.Count: > 0 } incident ? incident : null;

    public bool HasIncident => Incident is not null;

    public string IncidentText => Incident is { } i
        ? L.F("recovery.incident.text", i.At.ToLocalTime().ToString("g", CultureInfo.CurrentCulture), i.Files.Count)
        : string.Empty;

    public Brush MessageBrush { get; private set; } = StatusBrushes.Neutral;

    public override void OnShown()
    {
        OnPropertyChanged(string.Empty);
        _ = RefreshAsync();
    }

    public async Task RefreshAsync()
    {
        try
        {
            RecoveryStatus status = await services.Service.CallAsync<RecoveryStatus>(IpcMethods.RecoveryList, null, CancellationToken.None).ConfigureAwait(true);
            Points.Clear();
            foreach (RestorePoint point in status.Points)
            {
                Points.Add(new RestorePointRow(point));
            }

            NewestPoint = status.Points.Count > 0 ? status.Points.Max(p => p.CreatedAt) : null;
            PointsSummary = NewestPoint is { } newest
                ? L.F("recovery.points.summary", status.Points.Count, newest.ToLocalTime().ToString("g", CultureInfo.CurrentCulture))
                : status.LastError is { } error ? L.F("recovery.points.error", error) : L.T("recovery.points.none");
        }
        catch (IpcException ex)
        {
            PointsSummary = L.F("recovery.points.error", ex.Message);
        }

        OnPropertyChanged(nameof(HasRecentPoint));
        PointsChanged?.Invoke(this, EventArgs.Empty);
    }

    [RelayCommand]
    private async Task CreatePointAsync()
    {
        IsBusy = true;
        Show(L.T("recovery.creating"), ProtectionLevel.Protected, neutral: true);
        try
        {
            await services.Service.CallAsync<RecoveryStatus>(IpcMethods.RecoveryCreate, null, CancellationToken.None).ConfigureAwait(true);
            Show(L.T("recovery.created"), ProtectionLevel.Protected);
            services.Activity.Add(new ActivityEntry(DateTimeOffset.Now, ActivityKind.Recovery, ActivityLevel.Good, L.T("recovery.created")));
        }
        catch (IpcException ex)
        {
            Show(ex.Message, ProtectionLevel.Warning);
        }
        finally
        {
            IsBusy = false;
        }

        await RefreshAsync().ConfigureAwait(true);
    }

    [RelayCommand]
    private async Task ChooseFileAsync()
    {
        var dialog = new OpenFileDialog { Title = L.T("recovery.file.choose"), CheckFileExists = false };
        if (dialog.ShowDialog() == true)
        {
            SelectedFile = dialog.FileName;
            await FindVersionsAsync().ConfigureAwait(true);
        }
    }

    [RelayCommand]
    private async Task FindVersionsAsync()
    {
        Versions.Clear();
        if (RecoveryPlanner.Normalize(SelectedFile) is not { } path)
        {
            Show(L.T("recovery.file.invalid"), ProtectionLevel.Warning);
            return;
        }

        IsBusy = true;
        try
        {
            IReadOnlyList<FileVersion> versions = await services.Service.CallAsync<IReadOnlyList<FileVersion>>(
                IpcMethods.RecoveryVersions, new RecoveryVersionsRequest(path), CancellationToken.None).ConfigureAwait(true);
            foreach (FileVersion version in versions.OrderByDescending(v => v.PointCreatedAt))
            {
                Versions.Add(new FileVersionRow(version, this));
            }

            Show(versions.Count == 0 ? L.T("recovery.file.none") : L.F("recovery.file.found", versions.Count),
                versions.Count == 0 ? ProtectionLevel.Warning : ProtectionLevel.Protected, neutral: versions.Count > 0);
        }
        catch (IpcException ex)
        {
            Show(ex.Message, ProtectionLevel.Warning);
        }
        finally
        {
            IsBusy = false;
        }
    }

    public async Task RestoreVersionAsync(FileVersionRow row)
    {
        if (RecoveryPlanner.Normalize(SelectedFile) is not { } path)
        {
            return;
        }

        IsBusy = true;
        try
        {
            string restored = await RestoreAsync(path, row.Version).ConfigureAwait(true);
            Show(L.F("recovery.restored", Path.GetFileName(restored)), ProtectionLevel.Protected);
            Shell.RevealInExplorer(restored);
        }
        catch (Exception ex) when (ex is IpcException or IOException or UnauthorizedAccessException)
        {
            Show(L.F("recovery.restoreFailed", ex.Message), ProtectionLevel.Warning);
        }
        finally
        {
            IsBusy = false;
        }
    }

    /// <summary>After the ransomware shield stepped in: every damaged file from the newest copy before the attack.</summary>
    [RelayCommand]
    private async Task RestoreIncidentAsync()
    {
        if (Incident is not { } incident)
        {
            return;
        }

        IsBusy = true;
        int restored = 0;
        int missing = 0;
        try
        {
            foreach (string damaged in incident.Files)
            {
                string original = RansomwareIncident.OriginalName(damaged, incident.AddedExtension);
                if (RecoveryPlanner.Normalize(original) is not { } path)
                {
                    missing++;
                    continue;
                }

                Show(L.F("recovery.incident.progress", restored + missing + 1, incident.Files.Count), ProtectionLevel.Protected, neutral: true);
                try
                {
                    IReadOnlyList<FileVersion> versions = await services.Service.CallAsync<IReadOnlyList<FileVersion>>(
                        IpcMethods.RecoveryVersions, new RecoveryVersionsRequest(path), CancellationToken.None).ConfigureAwait(true);
                    if (RecoveryPlanner.BestBefore(versions, incident.At) is { } best)
                    {
                        await RestoreAsync(path, best).ConfigureAwait(true);
                        restored++;
                    }
                    else
                    {
                        missing++;
                    }
                }
                catch (Exception ex) when (ex is IpcException or IOException or UnauthorizedAccessException)
                {
                    missing++;
                }
            }

            string summary = L.F("recovery.incident.done", restored, missing);
            Show(summary, missing == 0 ? ProtectionLevel.Protected : ProtectionLevel.Warning);
            services.Activity.Add(new ActivityEntry(DateTimeOffset.Now, ActivityKind.Recovery, missing == 0 ? ActivityLevel.Good : ActivityLevel.Warning,
                L.T("recovery.incident.title"), summary));
            if (missing == 0)
            {
                services.SaveIncident(null);
                OnPropertyChanged(nameof(Incident));
                OnPropertyChanged(nameof(HasIncident));
            }
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private void DismissIncident()
    {
        services.SaveIncident(null);
        OnPropertyChanged(nameof(Incident));
        OnPropertyChanged(nameof(HasIncident));
    }

    /// <summary>
    /// Asks the service for the earlier copy (it checks this user may read it), then, as this
    /// user, copies it next to the original without overwriting anything.
    /// </summary>
    private async Task<string> RestoreAsync(string path, FileVersion version)
    {
        RecoveryFetchResult fetched = await services.Service.CallAsync<RecoveryFetchResult>(
            IpcMethods.RecoveryFetch, new RecoveryFetchRequest(path, version.PointId), CancellationToken.None).ConfigureAwait(true);
        try
        {
            string target = File.Exists(path)
                ? RecoveryPlanner.RestoredPath(path, version.PointCreatedAt, L.T("recovery.restoredWord"), p => File.Exists(p) || Directory.Exists(p))
                : path;
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            await Task.Run(() => File.Copy(fetched.TempPath, target, overwrite: false)).ConfigureAwait(true);
            return target;
        }
        finally
        {
            try
            {
                File.Delete(fetched.TempPath);
                Directory.Delete(Path.GetDirectoryName(fetched.TempPath)!);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // The service removes leftovers after an hour.
            }
        }
    }

    private void Show(string message, ProtectionLevel level, bool neutral = false)
    {
        Message = message;
        MessageBrush = neutral ? StatusBrushes.Neutral : StatusBrushes.For(level);
        OnPropertyChanged(nameof(MessageBrush));
    }
}
