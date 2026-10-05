namespace Agamemnon.Core.Scanning;

[System.Diagnostics.CodeAnalysis.SuppressMessage("Naming", "CA1720", Justification = "'Unsigned' is the domain term.")]
public enum SignatureState
{
    /// <summary>Signed with a certificate that chains to a trusted root and verifies.</summary>
    Trusted,

    /// <summary>No Authenticode signature and not in a Windows security catalog.</summary>
    Unsigned,

    /// <summary>Self-signed or chains to an untrusted root: Windows' equivalent of an ad-hoc signature.</summary>
    UntrustedRoot,

    /// <summary>Signature present but the file's hash no longer matches: the file was modified after signing.</summary>
    Invalid,

    /// <summary>The signing certificate has been revoked by its issuer.</summary>
    Revoked,

    /// <summary>Certificate expired and the signature carries no timestamp.</summary>
    Expired,

    /// <summary>Publisher or certificate is explicitly distrusted on this PC.</summary>
    Distrusted,

    /// <summary>Verification itself failed (e.g. revocation server unreachable).</summary>
    Unknown,
}

public sealed record SignatureInfo(SignatureState State, string? Publisher = null, string? Detail = null);

/// <summary>Platform hook: Authenticode/catalog verification on Windows (WinVerifyTrust).</summary>
public interface ISignatureVerifier
{
    /// <param name="path">File to verify.</param>
    /// <param name="onlineRevocationCheck">
    /// Contact the certificate authority to check for revocation. Slower, so only used for files
    /// that came from the internet; otherwise only cached revocation data is used.
    /// </param>
    SignatureInfo Verify(string path, bool onlineRevocationCheck);
}

/// <summary>Flags unsigned, self-signed, tampered and revoked programs, installers and PowerShell scripts.</summary>
public sealed class CodeSignatureEngine(ISignatureVerifier verifier) : IScanEngine
{
    public string Name => "Code signature";

    public Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken) =>
        Task.FromResult(new EngineStatus(true, "Authenticode and catalog signatures"));

    public Task<IReadOnlyList<EngineResult>> ScanAsync(IReadOnlyList<ScanTarget> batch, CancellationToken cancellationToken)
    {
        var results = new EngineResult[batch.Count];
        for (int i = 0; i < batch.Count; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ScanTarget target = batch[i];
            if (!Applies(target))
            {
                results[i] = EngineResult.Clean;
                continue;
            }

            try
            {
                SignatureInfo info = verifier.Verify(target.Path, onlineRevocationCheck: target.Origin?.IsFromInternet == true);
                Detection? detection = Interpret(info, target);
                results[i] = detection is null ? EngineResult.Clean : new EngineResult([detection]);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                results[i] = EngineResult.Failed($"Signature check: {ex.Message}");
            }
        }

        return Task.FromResult<IReadOnlyList<EngineResult>>(results);
    }

    private static bool Applies(ScanTarget target) =>
        target.Kind is FileKind.PortableExecutable or FileKind.WindowsInstaller
        || (target.Kind == FileKind.Script && Path.GetExtension(target.DisplayPath) is var ext
            && (ext.Equals(".ps1", StringComparison.OrdinalIgnoreCase) || ext.Equals(".psm1", StringComparison.OrdinalIgnoreCase)));

    internal static Detection? Interpret(SignatureInfo info, ScanTarget target)
    {
        bool fromInternet = target.Origin?.IsFromInternet == true;
        string what = target.Kind switch
        {
            FileKind.WindowsInstaller => "installer",
            FileKind.Script => "script",
            _ => "program",
        };
        return info.State switch
        {
            SignatureState.Trusted => null,
            SignatureState.Unsigned when target.Kind == FileKind.Script => fromInternet
                ? new Detection("Code signature", $"Unsigned {what} from the internet", Severity.Info)
                : null,
            SignatureState.Unsigned => fromInternet
                ? new Detection("Code signature", $"Unsigned {what} from the internet", Severity.Suspicious,
                    "Nobody vouches for who made this file. Only run it if you trust where it came from.")
                : new Detection("Code signature", $"Unsigned {what}", Severity.Info),
            SignatureState.UntrustedRoot => new Detection("Code signature", "Self-signed or untrusted certificate", Severity.Suspicious,
                Join(info.Publisher, "The signature doesn't chain to a certificate authority Windows trusts.")),
            SignatureState.Invalid => new Detection("Code signature", "Signature broken: file modified after signing", Severity.Suspicious,
                Join(info.Publisher, "Tampered copies of legitimate software are a common way to spread malware.")),
            SignatureState.Revoked => new Detection("Code signature", "Signing certificate revoked", Severity.Suspicious,
                Join(info.Publisher, "Certificates are usually revoked after being stolen or abused.")),
            SignatureState.Distrusted => new Detection("Code signature", "Publisher is blocked on this PC", Severity.Malicious, info.Publisher),
            SignatureState.Expired => new Detection("Code signature", "Signing certificate expired", Severity.Info, info.Publisher),
            _ => new Detection("Code signature", "Signature could not be verified", Severity.Info, info.Detail),
        };
    }

    private static string Join(string? publisher, string text) =>
        string.IsNullOrEmpty(publisher) ? text : $"Signed by “{publisher}”. {text}";
}

/// <summary>Flags files whose Mark-of-the-Web says they came from a known malware-distribution host.</summary>
public sealed class DownloadSourceEngine(IHostBlocklist blocklist) : IScanEngine
{
    public string Name => "Download source";

    public Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken) =>
        Task.FromResult(blocklist.Count == 0
            ? new EngineStatus(false, "Malware host list not downloaded yet.")
            : new EngineStatus(true, $"{blocklist.Count:N0} known malware hosts (URLhaus)"));

    public Task<IReadOnlyList<EngineResult>> ScanAsync(IReadOnlyList<ScanTarget> batch, CancellationToken cancellationToken)
    {
        IReadOnlyList<EngineResult> results = [.. batch.Select(target =>
        {
            foreach (string? url in new[] { target.Origin?.HostUrl, target.Origin?.ReferrerUrl })
            {
                if (Uri.TryCreate(url, UriKind.Absolute, out Uri? uri) && blocklist.IsBlocked(uri.IdnHost))
                {
                    return new EngineResult([new Detection("Download source", "Downloaded from a known malware site", Severity.Malicious, uri.Host)]);
                }
            }

            return EngineResult.Clean;
        })];
        return Task.FromResult(results);
    }
}

public interface IHostBlocklist
{
    int Count { get; }

    bool IsBlocked(string host);
}
