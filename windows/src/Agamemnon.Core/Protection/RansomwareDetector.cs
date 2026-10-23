namespace Agamemnon.Core.Protection;

/// <summary>Why the ransomware shield thinks files are being encrypted.</summary>
public enum RansomwareSign
{
    /// <summary>Changed files no longer start like their type (a .jpg that isn't a JPEG any more).</summary>
    ContentScrambled,

    /// <summary>Many files got the same new, unknown extension (photo.jpg.locked).</summary>
    MassRenamed,

    /// <summary>Ransom notes appeared while many files were changing.</summary>
    RansomNote,
}

public sealed record RansomwareVerdict(RansomwareSign Sign, int FilesAffected, string? Extension = null, string? Note = null);

/// <summary>
/// The decision part of the ransomware shield, shared by the app and the tests. The shield
/// records every file changed in a protected folder; once at least <see cref="BurstFiles"/>
/// change within <see cref="Window"/>, <see cref="Analyse"/> looks at them. Normal work
/// (copying, exporting, syncing) leaves files valid, so a burst alone is never enough.
/// </summary>
public sealed class RansomwareDetector(TimeProvider? time = null)
{
    public const int BurstFiles = 25;
    public static readonly TimeSpan Window = TimeSpan.FromSeconds(15);

    /// <summary>Files checked per burst, and how many of them must fail the type check.</summary>
    public const int SampleSize = 40;
    public const int MinimumChecked = 8;
    public const double ScrambledShare = 0.6;
    public const int MinimumRenamed = 10;

    private static readonly string[] RansomNoteNames =
    [
        "readme_decrypt", "how_to_decrypt", "how_to_recover", "decrypt_instructions", "restore_files", "recover_files",
        "how_to_restore", "_readme.txt", "read_me_now", "your_files_are_encrypted", "files_encrypted", "decrypt-files",
        "restore-my-files", "!!!",
    ];

    private static readonly HashSet<string> KnownExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".heic", ".webp", ".pdf", ".doc", ".docx", ".xls", ".xlsx",
        ".ppt", ".pptx", ".odt", ".ods", ".odp", ".txt", ".rtf", ".csv", ".md", ".json", ".xml", ".html", ".htm", ".zip",
        ".mp3", ".mp4", ".mov", ".m4a", ".wav", ".avi", ".mkv", ".psd", ".ai", ".svg", ".epub", ".7z", ".rar",
    };

    /// <summary>Extensions that programs legitimately add on top of another one while saving.</summary>
    private static readonly HashSet<string> HarmlessAddedExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".tmp", ".bak", ".old", ".orig", ".crdownload", ".part", ".partial", ".download", ".lnk", ".url", ".zip", ".7z",
        ".gz", ".backup", ".swp", ".lock",
    };

    private readonly TimeProvider _time = time ?? TimeProvider.System;
    private readonly Dictionary<string, DateTimeOffset> _recent = new(StringComparer.OrdinalIgnoreCase);
    private readonly Lock _gate = new();
    private DateTimeOffset _lastIncident = DateTimeOffset.MinValue;

    /// <summary>Records a change in a protected folder. Office lock files and hidden temp files are ignored.</summary>
    public void Record(string path)
    {
        string name = path[(path.LastIndexOfAny(['\\', '/']) + 1)..];
        if (name.Length == 0 || name.StartsWith("~$", StringComparison.Ordinal) || name.StartsWith('.')
            || name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase) || name.Equals("thumbs.db", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        lock (_gate)
        {
            _recent[path] = _time.GetUtcNow();
        }
    }

    /// <summary>
    /// The files changed within the window when they form a burst worth analysing, else null.
    /// After an incident the shield waits two minutes before looking again.
    /// </summary>
    public IReadOnlyList<string>? TakeBurst()
    {
        DateTimeOffset now = _time.GetUtcNow();
        lock (_gate)
        {
            foreach (string stale in _recent.Where(kv => now - kv.Value > Window).Select(kv => kv.Key).ToList())
            {
                _recent.Remove(stale);
            }

            if (_recent.Count < BurstFiles || now - _lastIncident < TimeSpan.FromMinutes(2))
            {
                return null;
            }

            return [.. _recent.Keys];
        }
    }

    /// <summary>Called when a burst turned out to be an attack: clears the list and starts the quiet period.</summary>
    public void MarkIncident()
    {
        lock (_gate)
        {
            _recent.Clear();
            _lastIncident = _time.GetUtcNow();
        }
    }

    /// <summary>Looks at a burst of changed files; null means "normal work".</summary>
    public static RansomwareVerdict? Analyse(IReadOnlyList<string> paths, Func<string, byte[]?> readHead)
    {
        string? note = paths.Select(Path.GetFileName).FirstOrDefault(n => n is not null && IsRansomNote(n));

        // Renamed: many files ending in the same unknown extension after a known one.
        var renamed = paths
            .Select(p => (Outer: Path.GetExtension(p), Inner: Path.GetExtension(Path.GetFileNameWithoutExtension(p))))
            .Where(e => e.Outer.Length is > 1 and <= 16 && !KnownExtensions.Contains(e.Outer) && !HarmlessAddedExtensions.Contains(e.Outer)
                        && KnownExtensions.Contains(e.Inner))
            .GroupBy(e => e.Outer, StringComparer.OrdinalIgnoreCase)
            .MaxBy(g => g.Count());
        if (renamed is not null && renamed.Count() >= MinimumRenamed)
        {
            return new RansomwareVerdict(RansomwareSign.MassRenamed, renamed.Count(), renamed.Key, note);
        }

        int checkedFiles = 0;
        int failed = 0;
        foreach (string path in paths.Take(SampleSize * 3))
        {
            if (checkedFiles >= SampleSize)
            {
                break;
            }

            byte[]? head = readHead(path);
            if (head is null || ContentMatchesType(Path.GetExtension(path), head) is not { } matches)
            {
                continue;
            }

            checkedFiles++;
            if (!matches)
            {
                failed++;
            }
        }

        if (checkedFiles >= MinimumChecked && failed >= checkedFiles * ScrambledShare)
        {
            return new RansomwareVerdict(RansomwareSign.ContentScrambled, failed, null, note);
        }

        return note is not null && failed >= MinimumChecked / 2
            ? new RansomwareVerdict(RansomwareSign.RansomNote, failed, null, note)
            : null;
    }

    public static bool IsRansomNote(string fileName)
    {
        string lower = fileName.ToLowerInvariant();
        return RansomNoteNames.Any(n => lower.Contains(n, StringComparison.Ordinal))
               && (lower.EndsWith(".txt", StringComparison.Ordinal) || lower.EndsWith(".html", StringComparison.Ordinal)
                   || lower.EndsWith(".hta", StringComparison.Ordinal) || lower.EndsWith(".url", StringComparison.Ordinal));
    }

    /// <summary>Whether a file still starts like its extension says; null for types we can't check.</summary>
    public static bool? ContentMatchesType(string extension, ReadOnlySpan<byte> head)
    {
        string ext = extension.TrimStart('.').ToLowerInvariant();
        if (head.Length == 0)
        {
            return null; // empty files are being written right now; nothing to judge
        }

        return ext switch
        {
            "jpg" or "jpeg" => StartsWith(head, [0xFF, 0xD8, 0xFF]),
            "png" => StartsWith(head, [0x89, 0x50, 0x4E, 0x47]),
            "gif" => StartsWith(head, "GIF8"u8),
            "bmp" => StartsWith(head, "BM"u8),
            "pdf" => StartsWith(head, "%PDF"u8),
            "zip" or "docx" or "xlsx" or "pptx" or "odt" or "ods" or "odp" or "epub" => StartsWith(head, "PK"u8),
            "doc" or "xls" or "ppt" => StartsWith(head, [0xD0, 0xCF, 0x11, 0xE0]),
            "7z" => StartsWith(head, [0x37, 0x7A, 0xBC, 0xAF]),
            "rar" => StartsWith(head, "Rar!"u8),
            "mp4" or "mov" or "m4a" or "heic" => head.Length >= 8 && head[4..8].SequenceEqual("ftyp"u8),
            "mp3" => StartsWith(head, "ID3"u8) || StartsWith(head, [0xFF, 0xFB]) || StartsWith(head, [0xFF, 0xF3]) || StartsWith(head, [0xFF, 0xF2]),
            "wav" or "avi" => StartsWith(head, "RIFF"u8),
            "psd" => StartsWith(head, "8BPS"u8),
            "rtf" => StartsWith(head, "{\\rtf"u8),
            "txt" or "md" or "csv" or "json" or "xml" or "html" or "htm" or "svg" => LooksLikeText(head),
            _ => null,
        };
    }

    private static bool StartsWith(ReadOnlySpan<byte> head, ReadOnlySpan<byte> magic) =>
        head.Length >= magic.Length && head[..magic.Length].SequenceEqual(magic);

    /// <summary>Text files: UTF-16 with a BOM, or UTF-8 (encrypted data almost never is) with few control characters.</summary>
    private static bool LooksLikeText(ReadOnlySpan<byte> head)
    {
        if (StartsWith(head, [0xFF, 0xFE]) || StartsWith(head, [0xFE, 0xFF]))
        {
            return true;
        }

        ReadOnlySpan<byte> sample = head.Length > 512 ? head[..512] : head;
        int control = 0;
        foreach (byte b in sample)
        {
            if (b < 32 && b is not (9 or 10 or 13))
            {
                control++;
            }
        }

        if (control * 20 >= sample.Length)
        {
            return false;
        }

        // The sample may end in the middle of a multi-byte character.
        var utf8 = new System.Text.UTF8Encoding(false, throwOnInvalidBytes: true);
        for (int cut = 0; cut <= 3 && cut < sample.Length; cut++)
        {
            try
            {
                utf8.GetCharCount(sample[..^cut]);
                return true;
            }
            catch (System.Text.DecoderFallbackException)
            {
            }
        }

        return false;
    }
}
