using System.Collections.ObjectModel;
using System.Windows.Media;
using Agamemnon.App.Localization;
using Agamemnon.App.Services;
using Agamemnon.Core.Quarantine;
using Agamemnon.Core.Scanning;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;

namespace Agamemnon.App.ViewModels;

public sealed partial class FindingViewModel(FileScanResult result, ScanViewModel owner) : ObservableObject
{
    public FileScanResult Result => result;

    public string FileName => result.IsArchiveMember ? result.DisplayPath.Split(" › ")[^1] : Path.GetFileName(result.DisplayPath);

    public string Location => result.DisplayPath;

    public Brush Brush => StatusBrushes.For(result.Verdict);

    public string VerdictText => result.Verdict switch
    {
        Severity.Malicious => L.T("finding.threat"),
        Severity.Suspicious => L.T("finding.suspicious"),
        Severity.Info => L.T("finding.note"),
        _ => L.T("finding.unscanned"),
    };

    /// <summary>What to do about it, in plain words.</summary>
    public string Advice => result.Verdict switch
    {
        Severity.Malicious => L.T("finding.threat.advice"),
        Severity.Suspicious => L.T("finding.suspicious.advice"),
        Severity.Info => L.T("finding.note.advice"),
        _ => L.T("finding.unscanned.advice"),
    };

    public IReadOnlyList<string> Lines =>
    [
        .. result.Detections.Select(d => d.Detail is { Length: > 0 } detail ? $"{d.Engine}: {d.Name} — {detail}" : $"{d.Engine}: {d.Name}"),
        .. result.Errors,
    ];

    public bool CanAct => result.OnDiskPath is not null && Status is null && result.Detections.Count > 0;

    public bool IsThreat => result.IsThreat && result.OnDiskPath is not null;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanAct))]
    public partial string? Status { get; set; }

    [RelayCommand]
    private Task Quarantine() => owner.QuarantineAsync(this);

    [RelayCommand]
    private void Trust() => owner.Trust(this);

    [RelayCommand]
    private void Reveal()
    {
        if (result.OnDiskPath is { } path)
        {
            Shell.RevealInExplorer(path);
        }
    }
}

public sealed partial class ScanViewModel(AppServices services, MainViewModel main) : PageViewModel
{
    private CancellationTokenSource? _cancel;

    public override NavigationTarget Target => NavigationTarget.Scan;

    public ObservableCollection<FindingViewModel> Findings { get; } = [];

    public ObservableCollection<string> Warnings { get; } = [];

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(QuickScanCommand), nameof(FullScanCommand), nameof(ScanFilesCommand), nameof(ScanFolderCommand), nameof(CancelCommand))]
    public partial bool IsScanning { get; set; }

    [ObservableProperty]
    public partial string ProgressText { get; set; } = L.T("scan.choose");

    [ObservableProperty]
    public partial string? CurrentPath { get; set; }

    [ObservableProperty]
    public partial string? Summary { get; set; }

    public int UnresolvedThreats => Findings.Count(f => f.IsThreat && f.Status is null);

    public bool HasFindings => Findings.Count > 0;

    private bool CanStart => !IsScanning;

    /// <summary>The display name of a scan kind as stored in the settings ("Quick", "Full", "Custom", "Automatic").</summary>
    public static string KindName(string? kind) => kind switch
    {
        "Quick" => L.T("scan.kind.quick"),
        "Full" => L.T("scan.kind.full"),
        "Automatic" => L.T("scan.kind.automatic"),
        _ => L.T("scan.kind.custom"),
    };

    /// <summary>The scheduled quick scan. It only interrupts the user when it finds something.</summary>
    public async Task RunAutomaticScanAsync()
    {
        int threats = await RunAsync("Automatic", QuickScanLocations()).ConfigureAwait(true);
        if (threats > 0)
        {
            main.NotifyAutomaticScanThreats(threats);
        }
    }

    [RelayCommand(CanExecute = nameof(CanStart))]
    private Task QuickScan() => RunAsync("Quick", QuickScanLocations());

    [RelayCommand(CanExecute = nameof(CanStart))]
    private Task FullScan() => RunAsync("Full", [.. DriveInfo.GetDrives().Where(d => d.IsReady && d.DriveType == DriveType.Fixed).Select(d => d.RootDirectory.FullName)]);

    [RelayCommand(CanExecute = nameof(CanStart))]
    private Task ScanFiles()
    {
        var dialog = new OpenFileDialog { Title = L.T("scan.dialog.files"), Multiselect = true };
        return dialog.ShowDialog() == true ? RunAsync("Custom", dialog.FileNames) : Task.CompletedTask;
    }

    [RelayCommand(CanExecute = nameof(CanStart))]
    private Task ScanFolder()
    {
        var dialog = new OpenFolderDialog { Title = L.T("scan.dialog.folders"), Multiselect = true };
        return dialog.ShowDialog() == true ? RunAsync("Custom", dialog.FolderNames) : Task.CompletedTask;
    }

    /// <summary>Files or folders dropped on the Scan page.</summary>
    public Task ScanDroppedAsync(IReadOnlyList<string> paths) => IsScanning ? Task.CompletedTask : RunAsync("Custom", paths);

    [RelayCommand(CanExecute = nameof(IsScanning))]
    private void Cancel() => _cancel?.Cancel();

    [RelayCommand]
    private async Task QuarantineAllThreats()
    {
        foreach (FindingViewModel finding in Findings.Where(f => f.IsThreat && f.Status is null).ToList())
        {
            await QuarantineAsync(finding).ConfigureAwait(true);
        }
    }

    public async Task QuarantineAsync(FindingViewModel finding)
    {
        string path = finding.Result.OnDiskPath!;
        try
        {
            services.Quarantine.Add(path, finding.Result.Detections);
            finding.Status = L.T("finding.status.quarantined");
        }
        catch (QuarantineException ex) when (ex.InnerException is UnauthorizedAccessException)
        {
            // Files under Program Files or Windows need an administrator to move them.
            finding.Status = await ElevatedActions.QuarantineAsync(path).ConfigureAwait(true)
                ? L.T("finding.status.quarantined")
                : null;
            if (finding.Status is null)
            {
                Summary = ex.Message;
            }
        }
        catch (QuarantineException ex)
        {
            Summary = ex.Message;
        }

        OnPropertyChanged(nameof(UnresolvedThreats));
        if (finding.Status is not null)
        {
            services.Activity.Add(new ActivityEntry(DateTimeOffset.Now, ActivityKind.Quarantine, ActivityLevel.Good,
                L.F("activity.quarantined", finding.FileName), finding.Result.Detections.Count > 0 ? finding.Result.Detections[0].Name : null));
        }

        main.RefreshStatus();
    }

    public void Trust(FindingViewModel finding)
    {
        services.Trust(finding.Result.Sha256);
        finding.Status = L.T("finding.status.trusted");
        OnPropertyChanged(nameof(UnresolvedThreats));
        main.RefreshStatus();
    }

    private static List<string> QuickScanLocations()
    {
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string[] candidates =
        [
            KnownFolders.Downloads,
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory),
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
            Path.GetTempPath(),
            Path.Combine(appData, "Microsoft", "Windows", "Start Menu", "Programs"),
        ];
        return [.. candidates.Where(p => !string.IsNullOrEmpty(p) && Directory.Exists(p)).Distinct(StringComparer.OrdinalIgnoreCase)];
    }

    /// <summary>Runs a scan and shows its results; returns the number of threats found.</summary>
    private async Task<int> RunAsync(string kind, IReadOnlyList<string> paths)
    {
        // Commands started from the tray or the welcome guide can arrive while a scan is running.
        if (paths.Count == 0 || IsScanning)
        {
            return 0;
        }

        IsScanning = true;
        Findings.Clear();
        Warnings.Clear();
        Summary = null;
        ProgressText = L.F("scan.starting", KindName(kind));
        OnPropertyChanged(nameof(HasFindings));
        using var cancel = new CancellationTokenSource();
        _cancel = cancel;
        var progress = new Progress<ScanProgress>(p =>
        {
            ProgressText = L.F("scan.progress", p.FilesScanned, p.ThreatsFound);
            if (p.CurrentPath is not null)
            {
                CurrentPath = p.CurrentPath;
            }
        });

        try
        {
            ScanReport report = await Task.Run(() => services.CreateScanner(forDownloads: false)
                .ScanAsync(paths, services.CreateScanOptions(), progress, cancel.Token)).ConfigureAwait(true);

            // Quick and full scans list threats only; a scan of chosen files also shows notes
            // (e.g. "unsigned program") and files that couldn't be read.
            foreach (FileScanResult result in report.Findings
                         .Where(f => !f.IsArchiveMember && (f.IsThreat || kind == "Custom"))
                         .OrderByDescending(f => f.Verdict.HasValue ? (int)f.Verdict.Value : -1))
            {
                Findings.Add(new FindingViewModel(result, this));
            }

            foreach (string warning in report.Warnings)
            {
                Warnings.Add(warning);
            }

            int threats = report.ThreatCount;
            ProgressText = L.F("scan.finished", report.FilesScanned, (report.FinishedAt - report.StartedAt).TotalMinutes);
            Summary = report.Cancelled
                ? L.T("scan.summary.stopped")
                : threats == 0 ? L.T("scan.summary.clean") : L.F("scan.summary.threats", threats);
            if (!report.Cancelled)
            {
                services.UpdateSettings(s => s with
                {
                    LastScanAt = report.FinishedAt,
                    LastScanFiles = report.FilesScanned,
                    LastScanThreats = threats,
                    LastScanKind = kind,
                });
                services.Activity.Add(new ActivityEntry(DateTimeOffset.Now, ActivityKind.Scan,
                    threats == 0 ? ActivityLevel.Good : ActivityLevel.Threat,
                    threats == 0 ? L.F("activity.scan.clean", KindName(kind)) : L.F("activity.scan.threats", KindName(kind), threats),
                    L.F("activity.scan.files", report.FilesScanned)));
            }

            return report.Cancelled ? 0 : threats;
        }
        finally
        {
            CurrentPath = null;
            IsScanning = false;
            _cancel = null;
            OnPropertyChanged(nameof(HasFindings));
            OnPropertyChanged(nameof(UnresolvedThreats));
            main.RefreshStatus();
        }
    }
}
