using System.Text.RegularExpressions;

namespace Agamemnon.Core.Protection;

/// <summary>Why copied text looks like a "paste this to fix it" malware command.</summary>
public enum PasteDanger
{
    /// <summary>Downloads something from the internet and runs it straight away.</summary>
    DownloadAndRun,

    /// <summary>Runs a hidden (encoded) PowerShell command.</summary>
    HiddenCommand,

    /// <summary>Opens a web page as a program (mshta with a link).</summary>
    RemoteHta,

    /// <summary>Pretends to be a "verify you are human" step.</summary>
    FakeVerification,
}

/// <summary>
/// The paste-command guard (ClickFix). Fake CAPTCHA, "fix this error" and fake update pages tell
/// people to press Win+R and paste a command. Agamemnon looks at the shape of text when it is
/// copied, on this PC only, and warns before it can be pasted. Well-known installers fetched
/// from their official sites over HTTPS are left alone.
/// </summary>
public static partial class ClipboardCommandGuard
{
    public const int MinimumLength = 12;
    public const int MaximumLength = 64 * 1024;

    private static readonly string[] TrustedInstallers =
    [
        "community.chocolatey.org/install.ps1", "get.scoop.sh", "astral.sh/uv/install.ps1", "bun.sh/install.ps1",
        "deno.land/install.ps1", "claude.ai/install.ps1", "dot.net/v1/dotnet-install.ps1", "win.rustup.rs",
        "aka.ms/install-powershell.ps1", "raw.githubusercontent.com/microsoft/",
    ];

    /// <summary>The danger in copied text, or null when it looks harmless.</summary>
    public static PasteDanger? Assess(string? text)
    {
        if (text is null || text.Length < MinimumLength || text.Length > MaximumLength)
        {
            return null;
        }

        // cmd's ^ escapes and PowerShell's backticks are used to break up words.
        string normalized = text.Replace("^", string.Empty, StringComparison.Ordinal).Replace("`", string.Empty, StringComparison.Ordinal);
        bool runsShell = Shell().IsMatch(normalized);

        if (runsShell && FakeVerificationComment().IsMatch(normalized))
        {
            return PasteDanger.FakeVerification;
        }

        if (MshtaLink().IsMatch(normalized))
        {
            return PasteDanger.RemoteHta;
        }

        if (runsShell && EncodedCommand().IsMatch(normalized))
        {
            return PasteDanger.HiddenCommand;
        }

        string lower = normalized.ToLowerInvariant();
        bool trusted = TrustedInstallers.Any(t => lower.Contains(t, StringComparison.Ordinal))
                       && !lower.Contains("http://", StringComparison.Ordinal);
        if (!trusted && (DownloadThenInvoke().IsMatch(normalized) || DownloadThenStart().IsMatch(normalized)))
        {
            return PasteDanger.DownloadAndRun;
        }

        return null;
    }

    [GeneratedRegex(@"\b(powershell|pwsh|cmd(\.exe)?\s*/[ck]|conhost|mshta|wscript|cscript|rundll32|msiexec)\b", RegexOptions.IgnoreCase)]
    private static partial Regex Shell();

    // "# I am not a robot - reCAPTCHA Verification ID: 1234" at the end of the command hides it in the Run box.
    [GeneratedRegex(@"#.{0,80}(not a robot|i am human|i'm human|captcha|verification|verify|ben robot değilim|doğrulama)", RegexOptions.IgnoreCase)]
    private static partial Regex FakeVerificationComment();

    [GeneratedRegex(@"\bmshta(\.exe)?\b[^\n]{0,40}(https?:|\\\\)", RegexOptions.IgnoreCase)]
    private static partial Regex MshtaLink();

    [GeneratedRegex(@"\s-(e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedcommand)\s+[A-Za-z0-9+/=]{24,}", RegexOptions.IgnoreCase)]
    private static partial Regex EncodedCommand();

    [GeneratedRegex(@"(iwr|irm|curl|wget|invoke-webrequest|invoke-restmethod|downloadstring|downloaddata|net\.webclient|start-bitstransfer)[^\n]{0,300}(\|\s*iex\b|\|\s*invoke-expression|iex\s*\(|invoke-expression\s*\(|&\s*\(|\.invoke\(\))|(iex|invoke-expression)\s*\(?\s*\(?\s*(iwr|irm|new-object|invoke-webrequest|invoke-restmethod)", RegexOptions.IgnoreCase)]
    private static partial Regex DownloadThenInvoke();

    [GeneratedRegex(@"(curl|wget|iwr|invoke-webrequest|certutil[^\n]{0,20}-urlcache|bitsadmin[^\n]{0,20}/transfer)[^\n]{0,300}(&&|&|;|\|)\s*(start\b|start-process\b|saps\b|msiexec\b|rundll32\b|regsvr32\b|\.\\|%temp%|\$env:temp)", RegexOptions.IgnoreCase)]
    private static partial Regex DownloadThenStart();
}
