namespace Agamemnon.Core.Checkup;

public enum CheckState
{
    Good,
    Warning,
    Bad,

    /// <summary>Couldn't be read (e.g. the setting doesn't exist on this edition of Windows).</summary>
    Unknown,
}

/// <summary>
/// One line of the Security Checkup. <see cref="Id"/> picks the translated title and advice
/// ("checkup.&lt;id&gt;.title", "checkup.&lt;id&gt;.&lt;state&gt;"); <see cref="FixUri"/> opens the
/// Windows Settings page that changes it. Agamemnon only reads these settings, it never changes them.
/// </summary>
public sealed record SecurityCheck(string Id, CheckState State, string? FixUri, string? Value = null);

/// <summary>Wi-Fi encryption of the current connection, from the native Wi-Fi API.</summary>
public enum WifiSecurity
{
    NotConnected,
    Open,
    Wep,
    Wpa,
    Wpa2,
    Wpa3,
    Unknown,
}

/// <summary>Raw values read from the PC by the service (as SYSTEM, so every setting is readable).</summary>
public sealed record SecuritySnapshot
{
    public int WindowsBuild { get; init; }

    /// <summary>Registry EditionID: "Professional", "Core", "Enterprise", "Education"…</summary>
    public string? Edition { get; init; }

    public bool? DefenderRealTime { get; init; }

    public DateTimeOffset? DefenderSignaturesUpdated { get; init; }

    public bool? TamperProtection { get; init; }

    public bool? ControlledFolderAccess { get; init; }

    public bool? SmartScreen { get; init; }

    /// <summary>Domain, private and public firewall profiles that are on, out of 3.</summary>
    public int? FirewallProfilesOn { get; init; }

    public bool? UacEnabled { get; init; }

    /// <summary>ConsentPromptBehaviorAdmin = 0: administrators are elevated without being asked.</summary>
    public bool? UacSilentForAdmins { get; init; }

    public bool? SystemDriveEncrypted { get; init; }

    public bool? SecureBoot { get; init; }

    public bool? MemoryIntegrity { get; init; }

    public bool? LsaProtection { get; init; }

    public bool? RemoteDesktop { get; init; }

    public bool? Smb1 { get; init; }

    public bool? AutomaticUpdatesDisabledByPolicy { get; init; }

    public WifiSecurity Wifi { get; init; } = WifiSecurity.Unknown;

    public string? WifiName { get; init; }
}

/// <summary>Turns a <see cref="SecuritySnapshot"/> into the checkup list. Pure, so it is unit-tested.</summary>
public static class SecurityCheckup
{
    /// <summary>
    /// End of security updates per Windows release, for Home/Pro and for Enterprise/Education.
    /// Builds newer than the last one are assumed supported.
    /// </summary>
    private static readonly (int Build, string Name, DateOnly Consumer, DateOnly Enterprise)[] Releases =
    [
        (19045, "Windows 10 22H2", new(2025, 10, 14), new(2025, 10, 14)),
        (22621, "Windows 11 22H2", new(2025, 10, 14), new(2025, 10, 14)),
        (22631, "Windows 11 23H2", new(2025, 11, 11), new(2026, 11, 10)),
        (26100, "Windows 11 24H2", new(2026, 10, 13), new(2027, 10, 12)),
        (26200, "Windows 11 25H2", new(2027, 10, 12), new(2028, 10, 10)),
    ];

    public static IReadOnlyList<SecurityCheck> Evaluate(SecuritySnapshot s, DateTimeOffset now)
    {
        var checks = new List<SecurityCheck>
        {
            WindowsSupport(s, DateOnly.FromDateTime(now.UtcDateTime)),
            new("defender", s.DefenderRealTime switch { true => CheckState.Good, false => CheckState.Bad, _ => CheckState.Unknown }, "windowsdefender://threat"),
            new("signatures", s.DefenderSignaturesUpdated is not { } updated ? CheckState.Unknown
                : now - updated > TimeSpan.FromDays(7) ? CheckState.Bad
                : now - updated > TimeSpan.FromDays(2) ? CheckState.Warning : CheckState.Good, "windowsdefender://threatsettings"),
            Flag("tamper", s.TamperProtection, CheckState.Warning, "windowsdefender://threatsettings"),
            Flag("ransomware", s.ControlledFolderAccess, CheckState.Warning, "windowsdefender://ransomwareprotection"),
            Flag("smartscreen", s.SmartScreen, CheckState.Bad, "windowsdefender://appbrowser"),
            new("firewall", s.FirewallProfilesOn switch { 3 => CheckState.Good, 0 => CheckState.Bad, null => CheckState.Unknown, _ => CheckState.Warning },
                "windowsdefender://network", s.FirewallProfilesOn?.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            new("uac", s.UacEnabled == false ? CheckState.Bad : s.UacSilentForAdmins == true ? CheckState.Warning
                : s.UacEnabled is null ? CheckState.Unknown : CheckState.Good, "ms-settings:"),
            Flag("encryption", s.SystemDriveEncrypted, CheckState.Warning, "ms-settings:deviceencryption"),
            Flag("secureBoot", s.SecureBoot, CheckState.Warning, "windowsdefender://devicesecurity"),
            Flag("memoryIntegrity", s.MemoryIntegrity, CheckState.Warning, "windowsdefender://coreisolation"),
            Flag("lsa", s.LsaProtection, CheckState.Warning, "windowsdefender://coreisolation"),
            Inverted("remoteDesktop", s.RemoteDesktop, CheckState.Warning, "ms-settings:remotedesktop"),
            Inverted("smb1", s.Smb1, CheckState.Bad, "ms-settings:optionalfeatures"),
            Inverted("updates", s.AutomaticUpdatesDisabledByPolicy, CheckState.Bad, "ms-settings:windowsupdate"),
            Wifi(s),
        };
        return checks;
    }

    /// <summary>Overall: Bad if anything is bad, Warning if anything needs a look, otherwise Good.</summary>
    public static CheckState Overall(IEnumerable<SecurityCheck> checks)
    {
        CheckState worst = CheckState.Good;
        foreach (SecurityCheck check in checks)
        {
            if (check.State == CheckState.Bad)
            {
                return CheckState.Bad;
            }

            if (check.State == CheckState.Warning)
            {
                worst = CheckState.Warning;
            }
        }

        return worst;
    }

    internal static SecurityCheck WindowsSupport(SecuritySnapshot s, DateOnly today)
    {
        if (s.WindowsBuild <= 0)
        {
            return new SecurityCheck("windows", CheckState.Unknown, "ms-settings:windowsupdate");
        }

        bool enterprise = s.Edition is { } e && (e.Contains("Enterprise", StringComparison.OrdinalIgnoreCase) || e.Contains("Education", StringComparison.OrdinalIgnoreCase));
        (int Build, string Name, DateOnly Consumer, DateOnly Enterprise) release = Releases.LastOrDefault(r => r.Build <= s.WindowsBuild);
        if (release.Build == 0)
        {
            return new SecurityCheck("windows", CheckState.Bad, "ms-settings:windowsupdate", $"build {s.WindowsBuild}");
        }

        // A release newer than the table knows about is still being supported.
        bool newerThanKnown = s.WindowsBuild >= Releases[^1].Build + 100;
        DateOnly end = enterprise ? release.Enterprise : release.Consumer;
        CheckState state = newerThanKnown || today <= end.AddDays(-90) ? CheckState.Good
            : today <= end ? CheckState.Warning
            : CheckState.Bad;
        return new SecurityCheck("windows", state, "ms-settings:windowsupdate", release.Name);
    }

    private static SecurityCheck Wifi(SecuritySnapshot s) => new("wifi", s.Wifi switch
    {
        WifiSecurity.Open or WifiSecurity.Wep => CheckState.Bad,
        WifiSecurity.Wpa => CheckState.Warning,
        WifiSecurity.Wpa2 or WifiSecurity.Wpa3 or WifiSecurity.NotConnected => CheckState.Good,
        _ => CheckState.Unknown,
    }, "ms-settings:network-wifi", s.WifiName);

    private static SecurityCheck Flag(string id, bool? on, CheckState whenOff, string fix) =>
        new(id, on switch { true => CheckState.Good, false => whenOff, _ => CheckState.Unknown }, fix);

    private static SecurityCheck Inverted(string id, bool? on, CheckState whenOn, string fix) =>
        new(id, on switch { false => CheckState.Good, true => whenOn, _ => CheckState.Unknown }, fix);
}
