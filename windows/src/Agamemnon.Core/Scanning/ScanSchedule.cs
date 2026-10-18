using Agamemnon.Core.Settings;

namespace Agamemnon.Core.Scanning;

/// <summary>When the automatic quick scan is due, from the chosen frequency and the last finished scan.</summary>
public static class ScanSchedule
{
    public static TimeSpan? Interval(AutoScanFrequency frequency) => frequency switch
    {
        AutoScanFrequency.Daily => TimeSpan.FromDays(1),
        AutoScanFrequency.Weekly => TimeSpan.FromDays(7),
        _ => null,
    };

    /// <summary>True when automatic scans are on and no scan has finished within the interval.</summary>
    public static bool IsDue(AutoScanFrequency frequency, DateTimeOffset? lastScan, DateTimeOffset now) =>
        Interval(frequency) is { } interval && (lastScan is not { } last || now - last >= interval);

    /// <summary>The next automatic scan, or null when they are off. A scan that is already due is "now".</summary>
    public static DateTimeOffset? Next(AutoScanFrequency frequency, DateTimeOffset? lastScan, DateTimeOffset now) =>
        Interval(frequency) is not { } interval ? null
        : lastScan is { } last && last + interval > now ? last + interval
        : now;
}
