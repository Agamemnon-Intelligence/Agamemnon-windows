using System.Security.Cryptography;
using System.Text;
using Agamemnon.Core.Util;

namespace Agamemnon.Core.Scanning;

/// <summary>
/// YARA rule matching using the bundled yara/yarac command-line tools. Rules from every rule
/// directory are compiled once (cached by content fingerprint) and files are scanned in batches
/// with --scan-list so a full-disk scan doesn't start one process per file.
/// Rules tagged <c>malicious</c> produce a Malicious detection; all others are Suspicious.
/// </summary>
public sealed class YaraEngine(
    string yaraPath,
    string yaracPath,
    IReadOnlyList<string> ruleDirectories,
    string cacheDirectory,
    IProcessRunner? runner = null) : IScanEngine, IDisposable
{
    private readonly IProcessRunner _runner = runner ?? ProcessRunner.Instance;
    private readonly SemaphoreSlim _compileLock = new(1, 1);
    private string? _compiledRules;
    private string? _compiledFingerprint;

    public string Name => "YARA";

    public async Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(yaraPath) || !File.Exists(yaracPath))
        {
            return new EngineStatus(false, "YARA isn't installed.");
        }

        IReadOnlyList<string> sources = FindRuleFiles();
        if (sources.Count == 0)
        {
            return new EngineStatus(false, "No YARA rules found.");
        }

        try
        {
            await EnsureCompiledAsync(cancellationToken).ConfigureAwait(false);
            return new EngineStatus(true, $"{sources.Count} YARA rule file(s)");
        }
        catch (EngineException ex)
        {
            return new EngineStatus(false, ex.Message);
        }
    }

    public async Task<IReadOnlyList<EngineResult>> ScanAsync(IReadOnlyList<ScanTarget> batch, CancellationToken cancellationToken)
    {
        string rules = await EnsureCompiledAsync(cancellationToken).ConfigureAwait(false);
        string listFile = Path.Combine(cacheDirectory, $"scanlist-{Guid.NewGuid():N}.txt");
        await File.WriteAllLinesAsync(listFile, batch.Select(t => t.Path), new UTF8Encoding(false), cancellationToken).ConfigureAwait(false);
        try
        {
            ProcessResult result = await _runner.RunAsync(
                yaraPath,
                ["--compiled-rules", "--print-tags", "--no-warnings", "--timeout=60", "--threads=2", "--scan-list", rules, listFile],
                TimeSpan.FromMinutes(10),
                cancellationToken).ConfigureAwait(false);
            return ParseOutput(batch, result.StandardOutput, result.StandardError);
        }
        finally
        {
            TryDelete(listFile);
        }
    }

    /// <summary>Parses "RuleName [tag1,tag2] C:\path\file" lines (and "error scanning PATH: reason" on stderr).</summary>
    internal static IReadOnlyList<EngineResult> ParseOutput(IReadOnlyList<ScanTarget> batch, string stdout, string stderr)
    {
        var detections = batch.Select(_ => new List<Detection>()).ToArray();
        var errors = new string?[batch.Count];

        // Longest paths first so "C:\a b\c.exe" can't be mistaken for a match on "c.exe".
        int[] order = [.. Enumerable.Range(0, batch.Count).OrderByDescending(i => batch[i].Path.Length)];

        foreach (string rawLine in stdout.Split('\n'))
        {
            string line = rawLine.TrimEnd('\r');
            if (line.Length == 0)
            {
                continue;
            }

            foreach (int i in order)
            {
                string suffix = " " + batch[i].Path;
                if (!line.EndsWith(suffix, StringComparison.Ordinal))
                {
                    continue;
                }

                string head = line[..^suffix.Length];
                string rule = head;
                string[] tags = [];
                int bracket = head.IndexOf(" [", StringComparison.Ordinal);
                if (bracket > 0 && head.EndsWith(']'))
                {
                    rule = head[..bracket];
                    tags = head[(bracket + 2)..^1].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                }

                Severity severity = tags.Contains("malicious", StringComparer.OrdinalIgnoreCase) ? Severity.Malicious : Severity.Suspicious;
                detections[i].Add(new Detection("YARA", rule, severity));
                break;
            }
        }

        foreach (string rawLine in stderr.Split('\n'))
        {
            string line = rawLine.TrimEnd('\r');
            foreach (int i in order)
            {
                if (errors[i] is null && line.Contains(batch[i].Path, StringComparison.Ordinal))
                {
                    errors[i] = "YARA: " + line.Trim();
                    break;
                }
            }
        }

        return [.. detections.Select((d, i) => new EngineResult(d, errors[i]))];
    }

    private IReadOnlyList<string> FindRuleFiles() =>
        [.. ruleDirectories
            .Where(Directory.Exists)
            .SelectMany(d => Directory.EnumerateFiles(d, "*.*", SearchOption.AllDirectories))
            .Where(f => f.EndsWith(".yar", StringComparison.OrdinalIgnoreCase) || f.EndsWith(".yara", StringComparison.OrdinalIgnoreCase))
            .Order(StringComparer.OrdinalIgnoreCase)];

    private async Task<string> EnsureCompiledAsync(CancellationToken cancellationToken)
    {
        IReadOnlyList<string> sources = FindRuleFiles();
        string fingerprint = Fingerprint(sources);
        if (_compiledFingerprint == fingerprint && _compiledRules is not null && File.Exists(_compiledRules))
        {
            return _compiledRules;
        }

        await _compileLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            Directory.CreateDirectory(cacheDirectory);
            string output = Path.Combine(cacheDirectory, $"rules-{fingerprint}.yarc");
            if (!File.Exists(output))
            {
                var arguments = new List<string> { "--no-warnings" };
                var usedNamespaces = new HashSet<string>(StringComparer.Ordinal);
                foreach (string source in sources)
                {
                    // Always give a namespace: it keeps rule names from different packs apart, and
                    // stops yarac from reading the "C" of "C:\..." as a namespace.
                    string ns = Namespace(source, usedNamespaces);
                    arguments.Add($"{ns}:{source}");
                }

                arguments.Add(output);
                ProcessResult result = await _runner.RunAsync(yaracPath, arguments, TimeSpan.FromMinutes(2), cancellationToken).ConfigureAwait(false);
                if (result.ExitCode != 0 || !File.Exists(output))
                {
                    string message = (result.StandardError + result.StandardOutput).Trim();
                    throw new EngineException($"YARA rules failed to compile: {message}");
                }

                foreach (string stale in Directory.EnumerateFiles(cacheDirectory, "rules-*.yarc").Where(f => f != output))
                {
                    TryDelete(stale);
                }
            }

            _compiledRules = output;
            _compiledFingerprint = fingerprint;
            return output;
        }
        finally
        {
            _compileLock.Release();
        }
    }

    public void Dispose() => _compileLock.Dispose();

    private static string Namespace(string source, HashSet<string> used)
    {
        var builder = new StringBuilder();
        foreach (char c in Path.GetFileNameWithoutExtension(source))
        {
            builder.Append(char.IsAsciiLetterOrDigit(c) ? c : '_');
        }

        if (builder.Length == 0 || char.IsAsciiDigit(builder[0]))
        {
            builder.Insert(0, "r_");
        }

        string candidate = builder.ToString();
        for (int n = 2; !used.Add(candidate); n++)
        {
            candidate = $"{builder}_{n}";
        }

        return candidate;
    }

    private static string Fingerprint(IReadOnlyList<string> sources)
    {
        var text = new StringBuilder();
        foreach (string source in sources)
        {
            var info = new FileInfo(source);
            text.Append(source).Append('|').Append(info.Length).Append('|').Append(info.LastWriteTimeUtc.Ticks).Append('\n');
        }

        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text.ToString())))[..16];
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
        catch (UnauthorizedAccessException)
        {
        }
    }
}
