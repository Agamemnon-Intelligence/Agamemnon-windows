using System.Management;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Agamemnon.Core.Recovery;
using Microsoft.Win32.SafeHandles;

namespace Agamemnon.Platform.Windows;

/// <summary>
/// Windows restore points (volume shadow copies) through WMI. Creating, listing and reading them
/// needs administrator rights, so this runs in the LocalSystem service.
/// </summary>
public static class ShadowCopies
{
    public static IReadOnlyList<RestorePoint> List(IReadOnlySet<string> agamemnonIds)
    {
        var letters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        using (var volumes = new ManagementObjectSearcher("SELECT DeviceID, DriveLetter FROM Win32_Volume"))
        {
            foreach (ManagementBaseObject volume in volumes.Get())
            {
                using (volume)
                {
                    if (volume["DeviceID"] is string id && volume["DriveLetter"] is string letter && letter.Length >= 2)
                    {
                        letters[id] = letter[..2] + "\\";
                    }
                }
            }
        }

        var points = new List<RestorePoint>();
        using var searcher = new ManagementObjectSearcher("SELECT ID, InstallDate, VolumeName, DeviceObject FROM Win32_ShadowCopy");
        foreach (ManagementBaseObject shadow in searcher.Get())
        {
            using (shadow)
            {
                if (shadow["ID"] is not string id || shadow["DeviceObject"] is not string device
                    || shadow["VolumeName"] is not string volumeName || !letters.TryGetValue(volumeName, out string? drive))
                {
                    continue;
                }

                DateTimeOffset created = shadow["InstallDate"] is string date
                    ? new DateTimeOffset(ManagementDateTimeConverter.ToDateTime(date))
                    : DateTimeOffset.MinValue;
                points.Add(new RestorePoint(id, created, drive, device, agamemnonIds.Contains(id)));
            }
        }

        return [.. points.OrderByDescending(p => p.CreatedAt)];
    }

    /// <summary>Takes a restore point of a drive ("C:\") and returns its ID.</summary>
    public static string Create(string volume)
    {
        using var shadowClass = new ManagementClass("Win32_ShadowCopy");
        using ManagementBaseObject parameters = shadowClass.GetMethodParameters("Create");
        parameters["Volume"] = volume;
        parameters["Context"] = "ClientAccessible";
        using ManagementBaseObject result = shadowClass.InvokeMethod("Create", parameters, null);
        uint code = Convert.ToUInt32(result["ReturnValue"], System.Globalization.CultureInfo.InvariantCulture);
        if (code != 0 || result["ShadowID"] is not string id)
        {
            throw new IOException(code switch
            {
                3 => "Windows doesn't have room for another restore point.",
                5 => "Windows' Volume Shadow Copy service is busy. Try again in a few minutes.",
                8 or 9 or 10 => "Restore points aren't available on this drive.",
                _ => $"Windows couldn't take a restore point (error {code}).",
            });
        }

        return id;
    }

    public static void Delete(string id)
    {
        using var searcher = new ManagementObjectSearcher($"SELECT * FROM Win32_ShadowCopy WHERE ID = '{id.Replace("'", string.Empty, StringComparison.Ordinal)}'");
        foreach (ManagementObject shadow in searcher.Get().Cast<ManagementObject>())
        {
            using (shadow)
            {
                shadow.Delete();
            }
        }
    }
}

/// <summary>
/// Asks Windows whether a caller (identified, not impersonated, through the service pipe) could
/// read a file, from the file's own permissions. The service only hands out earlier copies of
/// files their owner could open anyway.
/// </summary>
public static partial class FileAccessCheck
{
    private const uint FileGenericRead = 0x120089;

    public static bool CanRead(FileSystemSecurity security, SafeAccessTokenHandle clientToken)
    {
        byte[] descriptor = security.GetSecurityDescriptorBinaryForm();
        var mapping = new GenericMapping { Read = 0x120089, Write = 0x120116, Execute = 0x1200A0, All = 0x1F01FF };
        byte[] privileges = new byte[256];
        uint privilegesLength = (uint)privileges.Length;
        return AccessCheck(descriptor, clientToken, FileGenericRead, ref mapping, privileges, ref privilegesLength, out uint granted, out int status)
               && status != 0 && (granted & FileGenericRead) == FileGenericRead;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct GenericMapping
    {
        public uint Read;
        public uint Write;
        public uint Execute;
        public uint All;
    }

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool AccessCheck(byte[] securityDescriptor, SafeAccessTokenHandle clientToken, uint desiredAccess,
        ref GenericMapping mapping, byte[] privilegeSet, ref uint privilegeSetLength, out uint grantedAccess, out int accessStatus);
}

/// <summary>Who is calling, captured while the service pipe identifies the client.</summary>
public sealed class PipeCaller(WindowsIdentity identity) : IDisposable
{
    public SecurityIdentifier Sid => identity.User!;

    public SafeAccessTokenHandle Token => identity.AccessToken;

    public void Dispose() => identity.Dispose();
}
