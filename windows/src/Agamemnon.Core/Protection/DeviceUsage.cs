namespace Agamemnon.Core.Protection;

public enum PrivacyDevice
{
    Camera,
    Microphone,
}

/// <summary>
/// One app's use of the camera or microphone, as Windows records it under
/// HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore. An app
/// that is using the device right now has a start time and no stop time.
/// </summary>
public sealed record DeviceUse(PrivacyDevice Device, string AppKey, bool NonPackaged, long LastStart, long LastStop)
{
    public bool InUse => LastStart > 0 && LastStop == 0;

    /// <summary>"C:#Program Files#Zoom#bin#Zoom.exe" → "C:\Program Files\Zoom\bin\Zoom.exe"; Store apps keep their package name.</summary>
    public string AppPath => NonPackaged ? AppKey.Replace('#', '\\') : AppKey;

    /// <summary>A short name to show: the program's file name, or the package's name without its publisher suffix.</summary>
    public string AppName
    {
        get
        {
            if (NonPackaged)
            {
                return Path.GetFileName(AppPath.Replace('\\', Path.DirectorySeparatorChar));
            }

            int underscore = AppKey.IndexOf('_', StringComparison.Ordinal);
            string package = underscore > 0 ? AppKey[..underscore] : AppKey;
            int dot = package.LastIndexOf('.');
            return dot >= 0 && dot < package.Length - 1 ? package[(dot + 1)..] : package;
        }
    }
}

/// <summary>Notices when an app starts using the camera or microphone (unlike macOS, Windows says which app).</summary>
public sealed class DeviceUsageTracker(TimeProvider? time = null)
{
    private readonly TimeProvider _time = time ?? TimeProvider.System;
    private readonly HashSet<(PrivacyDevice, string)> _inUse = [];
    private readonly Dictionary<(PrivacyDevice, string), DateTimeOffset> _lastAlert = [];
    private bool _primed;

    /// <summary>At most one alert per app and device in this period, so calls don't spam.</summary>
    public static readonly TimeSpan QuietPeriod = TimeSpan.FromMinutes(30);

    /// <summary>
    /// Takes the latest readings and returns the uses that just started and should be reported.
    /// The first call only learns what is already in use.
    /// </summary>
    public IReadOnlyList<DeviceUse> Update(IEnumerable<DeviceUse> readings)
    {
        DateTimeOffset now = _time.GetUtcNow();
        var current = readings.Where(r => r.InUse).ToList();
        var started = new List<DeviceUse>();
        foreach (DeviceUse use in current)
        {
            var key = (use.Device, use.AppKey);
            if (_inUse.Contains(key) || !_primed)
            {
                continue;
            }

            if (_lastAlert.TryGetValue(key, out DateTimeOffset last) && now - last < QuietPeriod)
            {
                continue;
            }

            _lastAlert[key] = now;
            started.Add(use);
        }

        _inUse.Clear();
        foreach (DeviceUse use in current)
        {
            _inUse.Add((use.Device, use.AppKey));
        }

        _primed = true;
        return started;
    }
}
