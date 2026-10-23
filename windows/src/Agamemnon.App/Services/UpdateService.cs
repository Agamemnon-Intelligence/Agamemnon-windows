using System.Diagnostics;
using Agamemnon.Core.Scanning;
using Agamemnon.Core.Updates;
using Agamemnon.Core.Util;
using Agamemnon.Platform.Windows;

namespace Agamemnon.App.Services;

/// <summary>
/// Agamemnon's own updates, and the list of other programs with updates waiting (winget).
/// An update is installed only after its download matches the fingerprint GitHub publishes and
/// its code signature checks out: when this copy of Agamemnon is signed, the update must be
/// signed by the same publisher.
/// </summary>
public sealed class UpdateService(AppServices services)
{
    public event EventHandler? Changed;

    public AvailableUpdate? Available { get; private set; }

    public bool Checking { get; private set; }

    public static Version CurrentVersion => Version.Parse(AppServices.Version);

    /// <summary>Checks once a day when automatic checks are on; <paramref name="force"/> checks now.</summary>
    public async Task CheckAsync(bool force, CancellationToken cancellationToken)
    {
        if (Checking || (!force && (!services.Settings.CheckForUpdates
                                    || services.Settings.LastUpdateCheck is { } last && DateTimeOffset.Now - last < TimeSpan.FromDays(1))))
        {
            return;
        }

        Checking = true;
        Changed?.Invoke(this, EventArgs.Empty);
        try
        {
            Available = await services.Updates.CheckAsync(CurrentVersion, cancellationToken).ConfigureAwait(false);
            services.UpdateSettings(s => s with { LastUpdateCheck = DateTimeOffset.Now });
        }
        catch (Exception ex) when (ex is System.Net.Http.HttpRequestException or TaskCanceledException or System.Text.Json.JsonException)
        {
        }
        finally
        {
            Checking = false;
            Changed?.Invoke(this, EventArgs.Empty);
        }
    }

    /// <summary>Downloads, verifies and starts the setup program. Returns null on success, or what went wrong.</summary>
    public async Task<string?> InstallAsync(CancellationToken cancellationToken)
    {
        if (Available is not { } update)
        {
            return null;
        }

        string setup = Path.Combine(AgamemnonPaths.UserLocalData, "Updates", $"Agamemnon-{update.Version}-Setup.exe");
        try
        {
            await services.Updates.DownloadAsync(update, setup, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is System.Net.Http.HttpRequestException or IOException or InvalidDataException or TaskCanceledException)
        {
            return ex.Message;
        }

        var verifier = new AuthenticodeVerifier();
        SignatureInfo downloaded = verifier.Verify(setup, onlineRevocationCheck: true);
        SignatureInfo running = verifier.Verify(Environment.ProcessPath!, onlineRevocationCheck: false);
        bool ok = running.State == SignatureState.Trusted
            ? downloaded.State == SignatureState.Trusted && downloaded.Publisher == running.Publisher
            : downloaded.State == SignatureState.Trusted || (downloaded.State == SignatureState.Unsigned && update.Sha256 is not null);
        if (!ok)
        {
            TryDelete(setup);
            return Localization.L.T("update.badSignature");
        }

        try
        {
            Process.Start(new ProcessStartInfo(setup) { UseShellExecute = true })?.Dispose();
            return null;
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            return ex.Message;
        }
    }

    /// <summary>Programs with newer versions available, from winget (included with Windows 10 and 11).</summary>
    public static async Task<IReadOnlyList<SoftwareUpdate>?> ListSoftwareUpdatesAsync(CancellationToken cancellationToken)
    {
        string winget = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "WindowsApps", "winget.exe");
        if (!File.Exists(winget))
        {
            return null;
        }

        try
        {
            ProcessResult result = await ProcessRunner.Instance.RunAsync(winget,
                ["upgrade", "--include-unknown", "--accept-source-agreements", "--disable-interactivity"],
                TimeSpan.FromMinutes(3), cancellationToken).ConfigureAwait(false);
            return WingetOutput.ParseUpgrades(result.StandardOutput);
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or IOException or TimeoutException)
        {
            return null;
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (IOException)
        {
        }
    }
}
