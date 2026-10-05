using System.Collections.Concurrent;

namespace Agamemnon.Core.Downloads;

/// <summary>
/// Watches download folders and raises <see cref="FileReady"/> once a new file is complete: the
/// browser has renamed it from its partial name, its size has stopped changing and nobody holds
/// it open for writing.
/// </summary>
public sealed class DownloadWatcher : IDisposable
{
    private static readonly HashSet<string> PartialExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".crdownload", ".part", ".partial", ".download", ".opdownload", ".tmp", ".!ut", ".aria2", ".filepart",
        ".agamemnon-restoring",
    };

    private readonly List<FileSystemWatcher> _watchers = [];
    private readonly ConcurrentDictionary<string, DateTimeOffset> _pending = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DateTimeOffset> _recentlyReported = new(StringComparer.OrdinalIgnoreCase);
    private readonly TimeSpan _settle;
    private readonly Timer _timer;
    private int _polling;

    public DownloadWatcher(IEnumerable<string> folders, TimeSpan? settleTime = null)
    {
        _settle = settleTime ?? TimeSpan.FromSeconds(2);
        foreach (string folder in folders.Distinct(StringComparer.OrdinalIgnoreCase).Where(Directory.Exists))
        {
            var watcher = new FileSystemWatcher(folder)
            {
                IncludeSubdirectories = false,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.Size | NotifyFilters.LastWrite,
                InternalBufferSize = 64 * 1024,
            };
            watcher.Created += (_, e) => Track(e.FullPath);
            watcher.Changed += (_, e) => Track(e.FullPath);
            watcher.Renamed += (_, e) => Track(e.FullPath);
            watcher.Error += (_, _) => RescanAll(folder);
            _watchers.Add(watcher);
        }

        _timer = new Timer(_ => Poll(), null, Timeout.Infinite, Timeout.Infinite);
    }

    public event EventHandler<string>? FileReady;

    public IReadOnlyList<string> Folders => [.. _watchers.Select(w => w.Path)];

    public void Start()
    {
        foreach (FileSystemWatcher watcher in _watchers)
        {
            watcher.EnableRaisingEvents = true;
        }

        _timer.Change(TimeSpan.FromMilliseconds(500), TimeSpan.FromMilliseconds(500));
    }

    public static bool IsPartialDownload(string path)
    {
        string name = Path.GetFileName(path);
        return name.StartsWith("~$", StringComparison.Ordinal)
            || name.StartsWith(".com.google.Chrome.", StringComparison.Ordinal)
            || PartialExtensions.Contains(Path.GetExtension(name))
            || name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)
            || name.EndsWith(":Zone.Identifier", StringComparison.OrdinalIgnoreCase);
    }

    private void Track(string path)
    {
        if (!IsPartialDownload(path))
        {
            _pending[path] = DateTimeOffset.UtcNow;
        }
    }

    private void RescanAll(string folder)
    {
        // The watcher's buffer overflowed: re-examine anything modified in the last few minutes.
        try
        {
            foreach (string file in Directory.EnumerateFiles(folder))
            {
                if (DateTime.UtcNow - File.GetLastWriteTimeUtc(file) < TimeSpan.FromMinutes(5))
                {
                    Track(file);
                }
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private void Poll()
    {
        if (Interlocked.Exchange(ref _polling, 1) == 1)
        {
            return;
        }

        try
        {
            PollOnce();
        }
        finally
        {
            Volatile.Write(ref _polling, 0);
        }
    }

    private void PollOnce()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        foreach ((string path, DateTimeOffset lastEvent) in _pending)
        {
            if (now - lastEvent < _settle)
            {
                continue;
            }

            if (!File.Exists(path))
            {
                _pending.TryRemove(path, out _);
                continue;
            }

            if (!IsComplete(path))
            {
                _pending[path] = now; // still being written: check again later
                continue;
            }

            if (!_pending.TryRemove(new KeyValuePair<string, DateTimeOffset>(path, lastEvent)))
            {
                continue; // a newer event arrived meanwhile
            }

            // Browsers touch a finished file several times (rename, MOTW stream); report once.
            if (_recentlyReported.TryGetValue(path, out DateTimeOffset reported) && now - reported < TimeSpan.FromSeconds(30))
            {
                continue;
            }

            _recentlyReported[path] = now;
            foreach (var stale in _recentlyReported.Where(kv => now - kv.Value > TimeSpan.FromMinutes(5)))
            {
                _recentlyReported.TryRemove(stale);
            }

            FileReady?.Invoke(this, path);
        }
    }

    private static bool IsComplete(string path)
    {
        try
        {
            // Succeeds only if no other process has the file open for writing.
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            return true;
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }

    public void Dispose()
    {
        _timer.Dispose();
        foreach (FileSystemWatcher watcher in _watchers)
        {
            watcher.Dispose();
        }
    }
}
