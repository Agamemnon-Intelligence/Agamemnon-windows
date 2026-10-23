using System.Management;
using System.Runtime.InteropServices;
using Agamemnon.Core.Checkup;
using Microsoft.Win32;

namespace Agamemnon.Platform.Windows;

/// <summary>
/// Reads the settings behind the Security Checkup. Runs in the LocalSystem service, where
/// BitLocker, Defender and the firewall policy are all readable; it never changes anything.
/// Every value that can't be read is left null and shows as "couldn't check".
/// </summary>
public static partial class SecuritySnapshotReader
{
    public static SecuritySnapshot Read()
    {
        (bool? realTime, DateTimeOffset? signatures, bool? tamper) = Defender();
        (WifiSecurity wifi, string? ssid) = WifiNetwork.CurrentSecurity();
        return new SecuritySnapshot
        {
            WindowsBuild = int.TryParse(Machine(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuildNumber") as string, out int build) ? build : 0,
            Edition = Machine(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "EditionID") as string,
            DefenderRealTime = realTime,
            DefenderSignaturesUpdated = signatures,
            TamperProtection = tamper,
            ControlledFolderAccess = ControlledFolderAccess(),
            SmartScreen = SmartScreen(),
            FirewallProfilesOn = FirewallProfiles(),
            UacEnabled = Dword(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA") is int lua ? lua != 0 : null,
            UacSilentForAdmins = Dword(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin") is int prompt ? prompt == 0 : null,
            SystemDriveEncrypted = SystemDriveEncrypted(),
            SecureBoot = Dword(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled") is int sb ? sb == 1 : null,
            MemoryIntegrity = (Dword(@"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", "Enabled") ?? 0) == 1,
            LsaProtection = (Dword(@"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL") ?? 0) is 1 or 2,
            RemoteDesktop = Dword(@"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections") is int deny ? deny == 0 : null,
            Smb1 = Smb1Enabled(),
            AutomaticUpdatesDisabledByPolicy = (Dword(@"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate") ?? 0) == 1,
            Wifi = wifi,
            WifiName = ssid,
        };
    }

    private static (bool? RealTime, DateTimeOffset? Signatures, bool? Tamper) Defender()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(@"root\Microsoft\Windows\Defender",
                "SELECT RealTimeProtectionEnabled, AntivirusSignatureLastUpdated, IsTamperProtected FROM MSFT_MpComputerStatus");
            foreach (ManagementBaseObject status in searcher.Get())
            {
                using (status)
                {
                    DateTimeOffset? updated = status["AntivirusSignatureLastUpdated"] is string dmtf
                        ? new DateTimeOffset(ManagementDateTimeConverter.ToDateTime(dmtf))
                        : null;
                    return (status["RealTimeProtectionEnabled"] as bool?, updated, status["IsTamperProtected"] as bool?);
                }
            }
        }
        catch (Exception ex) when (ex is ManagementException or COMException or UnauthorizedAccessException or ArgumentOutOfRangeException)
        {
            // Another antivirus replaced Defender (its WMI provider is gone), or Defender is broken.
        }

        return (null, null, null);
    }

    private static bool? ControlledFolderAccess()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(@"root\Microsoft\Windows\Defender", "SELECT EnableControlledFolderAccess FROM MSFT_MpPreference");
            foreach (ManagementBaseObject preference in searcher.Get())
            {
                using (preference)
                {
                    return Convert.ToInt32(preference["EnableControlledFolderAccess"] ?? 0, System.Globalization.CultureInfo.InvariantCulture) == 1;
                }
            }
        }
        catch (Exception ex) when (ex is ManagementException or COMException or UnauthorizedAccessException or InvalidCastException)
        {
        }

        return null;
    }

    private static bool? SmartScreen()
    {
        if (Dword(@"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen") is int policy)
        {
            return policy != 0;
        }

        return Machine(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled") is string value
            ? !value.Equals("Off", StringComparison.OrdinalIgnoreCase)
            : true; // on unless someone turned it off
    }

    private static int? FirewallProfiles()
    {
        int on = 0;
        bool any = false;
        foreach ((string profile, string policy) in new[] { ("DomainProfile", "DomainProfile"), ("StandardProfile", "PrivateProfile"), ("PublicProfile", "PublicProfile") })
        {
            int? value = Dword($@"SOFTWARE\Policies\Microsoft\WindowsFirewall\{policy}", "EnableFirewall")
                         ?? Dword($@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{profile}", "EnableFirewall");
            if (value is int v)
            {
                any = true;
                on += v != 0 ? 1 : 0;
            }
        }

        return any ? on : null;
    }

    private static bool? SystemDriveEncrypted()
    {
        string drive = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows))?.TrimEnd('\\') ?? "C:";
        try
        {
            using var searcher = new ManagementObjectSearcher(@"root\CIMV2\Security\MicrosoftVolumeEncryption",
                $"SELECT ProtectionStatus FROM Win32_EncryptableVolume WHERE DriveLetter = '{drive}'");
            foreach (ManagementBaseObject volume in searcher.Get())
            {
                using (volume)
                {
                    return Convert.ToInt32(volume["ProtectionStatus"] ?? 0, System.Globalization.CultureInfo.InvariantCulture) == 1;
                }
            }

            return false;
        }
        catch (Exception ex) when (ex is ManagementException or COMException or UnauthorizedAccessException or InvalidCastException)
        {
            return null; // editions without BitLocker or device encryption
        }
    }

    private static bool? Smb1Enabled()
    {
        using RegistryKey? client = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\mrxsmb10");
        if (client is null)
        {
            return Dword(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1") is int server ? server != 0 : false;
        }

        return client.GetValue("Start") is int start && start != 4;
    }

    private static object? Machine(string key, string name)
    {
        try
        {
            using RegistryKey? k = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64).OpenSubKey(key);
            return k?.GetValue(name);
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            return null;
        }
    }

    private static int? Dword(string key, string name) => Machine(key, name) is int value ? value : null;
}
