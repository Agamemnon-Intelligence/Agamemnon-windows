using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;

namespace Agamemnon.Core.Scanning;

/// <summary>
/// Undoes the tricks Windows malware scripts use to hide their real commands from simple string
/// matching, so the checks can see them:
/// <list type="bullet">
/// <item>cmd's <c>^</c> and PowerShell's backtick escapes inside words (<c>p^o^w^e^r</c>, <c>i`e`x</c>);</item>
/// <item>strings split up and glued back together (<c>'Down'+'load'</c>, <c>"cu" &amp; "rl"</c>);</item>
/// <item>base64 blobs, as UTF-8 or UTF-16 (PowerShell's <c>-EncodedCommand</c>), also reversed,
/// and gzip or deflate data inside base64;</item>
/// <item>long hex strings, <c>\xNN</c>, <c>\uNNNN</c> and <c>%NN</c> escapes;</item>
/// <item>character-code lists (<c>[char]105+[char]101</c>, <c>String.fromCharCode(…)</c>, <c>Chr(…)</c>).</item>
/// </list>
/// Only decodes; never runs anything. Results that don't look like text are dropped, so
/// random data (hashes, embedded images) can't feed the checks garbage.
/// </summary>
public static partial class Deobfuscator
{
    public const int MaxLevels = 3;
    public const int MaxOutputChars = 4 * 1024 * 1024;

    /// <summary>Everything decoded from <paramref name="text"/>, lower-cased and joined by newlines; empty when nothing was hidden.</summary>
    public static string Reveal(string text) => Reveal(text, out _);

    /// <param name="text">The script.</param>
    /// <param name="deepestLevel">How many layers of hiding were found (0 when none).</param>
    public static string Reveal(string text, out int deepestLevel)
    {
        deepestLevel = 0;
        var output = new StringBuilder();
        var queue = new Stack<(string Text, int Level)>();
        queue.Push((text, 0));
        var seen = new HashSet<string>(StringComparer.Ordinal);
        while (queue.Count > 0)
        {
            (string current, int level) = queue.Pop();
            foreach (string piece in DecodeOnce(current))
            {
                if (output.Length + piece.Length > MaxOutputChars)
                {
                    return output.ToString();
                }

                if (!seen.Add(piece))
                {
                    continue;
                }

                deepestLevel = Math.Max(deepestLevel, level + 1);
                output.Append('\n').Append(piece);
                if (level + 1 < MaxLevels)
                {
                    queue.Push((piece, level + 1));
                }
            }
        }

        return output.ToString();
    }

    private static IEnumerable<string> DecodeOnce(string text)
    {
        var pieces = new List<string>();
        if (RemoveEscapes(text) is { } unescaped)
        {
            pieces.Add(unescaped);
        }

        if (JoinConcatenations(text) is { } joined)
        {
            pieces.Add(joined);
        }

        pieces.AddRange(Base64Blobs(text));
        pieces.AddRange(HexBlobs(text));
        if (Unescape(text) is { } escaped)
        {
            pieces.Add(escaped);
        }

        pieces.AddRange(CharCodeLists(text));
        return pieces.Where(IsMostlyText).Select(p => p.ToLowerInvariant());
    }

    /// <summary><c>p^o^w^e^r^s^h^e^l^l</c> and <c>i`e`x</c>: only when used a lot, since both are normal now and then.</summary>
    private static string? RemoveEscapes(string text)
    {
        int carets = EscapedLetter().Count(text);
        if (carets < 6)
        {
            return null;
        }

        return EscapedLetter().Replace(text, "$1");
    }

    /// <summary><c>'Down' + 'load'</c> → <c>'Download'</c>. A couple of these is normal code; malware splits dozens of words.</summary>
    private static string? JoinConcatenations(string text)
    {
        if (text.Length > 4 * 1024 * 1024 || Concatenation().Count(text) < 6)
        {
            return null;
        }

        return Concatenation().Replace(text, string.Empty);
    }

    private static IEnumerable<string> Base64Blobs(string text)
    {
        foreach (Match match in Base64Run().Matches(text).Take(200))
        {
            string blob = match.Value;
            if (blob.All(char.IsAsciiHexDigit))
            {
                continue; // pure hex is handled by HexBlobs
            }

            string padded = blob.TrimEnd('=');
            padded += new string('=', (4 - (padded.Length % 4)) % 4);
            string reversed = new([.. blob.TrimStart('=').Reverse()]);
            reversed = reversed.TrimEnd('=') + new string('=', (4 - (reversed.TrimEnd('=').Length % 4)) % 4);
            foreach (string candidate in new[] { padded, reversed })
            {
                if (DecodeBase64(candidate) is { } decoded)
                {
                    yield return decoded;
                    break;
                }
            }
        }
    }

    private static string? DecodeBase64(string candidate)
    {
        byte[] bytes;
        try
        {
            bytes = Convert.FromBase64String(candidate);
        }
        catch (FormatException)
        {
            return null;
        }

        bytes = Inflate(bytes) ?? bytes;

        // PowerShell's -EncodedCommand is UTF-16LE: every other byte is zero.
        if (bytes.Length >= 8 && bytes.Where((_, i) => i % 2 == 1).Count(b => b == 0) * 10 >= bytes.Length / 2 * 9)
        {
            return Encoding.Unicode.GetString(bytes);
        }

        return Encoding.UTF8.GetString(bytes);
    }

    /// <summary>gzip or raw deflate (PowerShell's IO.Compression.DeflateStream), or null.</summary>
    private static byte[]? Inflate(byte[] data)
    {
        if (data.Length < 10)
        {
            return null;
        }

        bool gzip = data[0] == 0x1F && data[1] == 0x8B;
        try
        {
            using var input = new MemoryStream(data);
            using Stream inflater = gzip ? new GZipStream(input, CompressionMode.Decompress) : new DeflateStream(input, CompressionMode.Decompress);
            using var output = new MemoryStream();
            byte[] buffer = new byte[8192];
            int read;
            while ((read = inflater.Read(buffer)) > 0)
            {
                output.Write(buffer, 0, read);
                if (output.Length > MaxOutputChars)
                {
                    return null;
                }
            }

            return output.Length > 0 ? output.ToArray() : null;
        }
        catch (InvalidDataException)
        {
            return null;
        }
    }

    private static IEnumerable<string> HexBlobs(string text)
    {
        foreach (Match match in HexRun().Matches(text).Take(200))
        {
            byte[] bytes = Convert.FromHexString(match.Value.Length % 2 == 0 ? match.Value : match.Value[..^1]);
            yield return Encoding.UTF8.GetString(bytes);
        }
    }

    private static string? Unescape(string text)
    {
        MatchCollection runs = EscapeRun().Matches(text);
        if (runs.Count == 0)
        {
            return null;
        }

        var output = new StringBuilder();
        foreach (Match run in runs.Take(500))
        {
            string value = run.Value;
            for (int i = 0; i < value.Length;)
            {
                if (value[i] == '\\' && i + 3 < value.Length && value[i + 1] == 'x' && IsHex(value, i + 2, 2))
                {
                    output.Append((char)Convert.ToInt32(value.Substring(i + 2, 2), 16));
                    i += 4;
                }
                else if (value[i] == '\\' && i + 5 < value.Length && value[i + 1] == 'u' && IsHex(value, i + 2, 4))
                {
                    output.Append((char)Convert.ToInt32(value.Substring(i + 2, 4), 16));
                    i += 6;
                }
                else if (value[i] == '%' && i + 2 < value.Length && IsHex(value, i + 1, 2))
                {
                    output.Append((char)Convert.ToInt32(value.Substring(i + 1, 2), 16));
                    i += 3;
                }
                else
                {
                    i++;
                }
            }

            output.Append(' ');
        }

        return output.Length == 0 ? null : output.ToString();
    }

    private static bool IsHex(string text, int start, int count) =>
        start + count <= text.Length && !text.AsSpan(start, count).ContainsAnyExcept(HexDigits);

    private static readonly System.Buffers.SearchValues<char> HexDigits = System.Buffers.SearchValues.Create("0123456789abcdefABCDEF");

    /// <summary>Every 2–3 digit number near character-code calls, kept when printable, in order.</summary>
    private static IEnumerable<string> CharCodeLists(string text)
    {
        MatchCollection calls = CharCodeCall().Matches(text);
        if (calls.Count == 0)
        {
            yield break;
        }

        int start = calls[0].Index;
        int end = start;
        for (int i = 1; i <= calls.Count; i++)
        {
            if (i < calls.Count && calls[i].Index - end <= 4000)
            {
                end = calls[i].Index;
                continue;
            }

            int length = Math.Min(end + 4000, text.Length) - start;
            var builder = new StringBuilder();
            foreach (Match number in Number().Matches(text.Substring(start, length)))
            {
                int value = int.Parse(number.Value, System.Globalization.CultureInfo.InvariantCulture);
                if (value is >= 9 and <= 126)
                {
                    builder.Append((char)value);
                }
            }

            if (builder.Length >= 8)
            {
                yield return builder.ToString();
            }

            if (i < calls.Count)
            {
                start = end = calls[i].Index;
            }
        }
    }

    /// <summary>At least 85% printable ASCII or whitespace, and long enough to matter.</summary>
    public static bool IsMostlyText(string text)
    {
        if (text.Length < 8)
        {
            return false;
        }

        int sample = Math.Min(text.Length, 4096);
        int printable = 0;
        for (int i = 0; i < sample; i++)
        {
            char c = text[i];
            if (c is (>= ' ' and < (char)0x7F) or '\t' or '\n' or '\r')
            {
                printable++;
            }
        }

        return printable * 100 >= sample * 85;
    }

    [GeneratedRegex(@"[\^`]([a-zA-Z])")]
    private static partial Regex EscapedLetter();

    [GeneratedRegex(@"([""'])\s*(?:&|\+|\.)?\s*\1")]
    private static partial Regex Concatenation();

    [GeneratedRegex(@"[A-Za-z0-9+/]{40,}={0,2}")]
    private static partial Regex Base64Run();

    [GeneratedRegex(@"(?:[0-9a-fA-F]{2}){24,}")]
    private static partial Regex HexRun();

    [GeneratedRegex(@"(?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|%[0-9a-fA-F]{2}){8,}")]
    private static partial Regex EscapeRun();

    [GeneratedRegex(@"(?:fromcharcode|\[char\]|chrw?\$?|chararray)\s*\(?\s*\d{2,3}", RegexOptions.IgnoreCase)]
    private static partial Regex CharCodeCall();

    [GeneratedRegex(@"\b\d{2,3}\b")]
    private static partial Regex Number();
}

/// <summary>
/// "Hidden scripts": decodes scripts (and shortcuts' and HTML applications' text) with the
/// <see cref="Deobfuscator"/>, then looks at what was hidden. Hiding a command that downloads
/// and runs code is something real software has no reason to do.
/// </summary>
public sealed partial class HiddenScriptEngine : IScanEngine
{
    public const long MaxBytes = 4 * 1024 * 1024;

    public string Name => "Hidden scripts";

    public Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken) =>
        Task.FromResult(new EngineStatus(true, "Decodes base64, hex, escapes and split strings in scripts"));

    public async Task<IReadOnlyList<EngineResult>> ScanAsync(IReadOnlyList<ScanTarget> batch, CancellationToken cancellationToken)
    {
        var results = new EngineResult[batch.Count];
        for (int i = 0; i < batch.Count; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ScanTarget target = batch[i];
            if (target.Kind is not (FileKind.Script or FileKind.Shortcut) || target.Size > MaxBytes)
            {
                results[i] = EngineResult.Clean;
                continue;
            }

            try
            {
                byte[] bytes = await File.ReadAllBytesAsync(target.Path, cancellationToken).ConfigureAwait(false);
                results[i] = Inspect(DecodeText(bytes, target.Kind));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                results[i] = EngineResult.Failed($"Hidden scripts: {ex.Message}");
            }
        }

        return results;
    }

    /// <summary>Scripts are UTF-8 or UTF-16; a shortcut's arguments are UTF-16 inside binary data.</summary>
    internal static string DecodeText(byte[] bytes, FileKind kind)
    {
        bool utf16 = kind == FileKind.Shortcut || (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE);
        return utf16 ? Encoding.Unicode.GetString(bytes) : Encoding.UTF8.GetString(bytes);
    }

    internal static EngineResult Inspect(string script)
    {
        string revealed = Deobfuscator.Reveal(script, out int levels);
        if (levels == 0)
        {
            return EngineResult.Clean;
        }

        if (DownloadAndRun().IsMatch(revealed))
        {
            return new EngineResult([new Detection("Hidden scripts", "Hidden command that downloads and runs code", Severity.Malicious,
                levels > 1 ? $"Hidden under {levels} layers of encoding." : null)]);
        }

        if (levels >= 2 && Invokes().IsMatch(revealed))
        {
            return new EngineResult([new Detection("Hidden scripts", "Command hidden under several layers of encoding", Severity.Suspicious)]);
        }

        return EngineResult.Clean;
    }

    [GeneratedRegex(@"(downloadstring|downloaddata|downloadfile|invoke-webrequest|invoke-restmethod|\biwr\b|\birm\b|net\.webclient|start-bitstransfer|msxml2\.xmlhttp|winhttp\.winhttprequest)[\s\S]{0,400}(\biex\b|invoke-expression|start-process|\.run\(|shellexecute|\.exec\(|\[reflection\.assembly\]::load)", RegexOptions.IgnoreCase)]
    private static partial Regex DownloadAndRun();

    [GeneratedRegex(@"(\biex\b|invoke-expression|start-process|\.run\(|shellexecute|\.exec\(|\[reflection\.assembly\]::load|eval\()", RegexOptions.IgnoreCase)]
    private static partial Regex Invokes();
}
