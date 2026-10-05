using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Agamemnon.Core.Dns;
using Agamemnon.Core.Quarantine;
using Agamemnon.Core.Scanning;
using Agamemnon.Core.Settings;

namespace Agamemnon.Platform.Windows;

/// <summary>Reads the Mark-of-the-Web that browsers and mail clients attach to downloaded files.</summary>
public static class MarkOfTheWeb
{
    public static FileOrigin? Read(string path)
    {
        try
        {
            return FileOrigin.Parse(File.ReadAllText(path + ":Zone.Identifier"));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException or ArgumentException)
        {
            return null;
        }
    }
}

/// <summary>DPAPI, bound to the signed-in Windows user.</summary>
public sealed class DpapiKeyProtector(DataProtectionScope scope = DataProtectionScope.CurrentUser) : IKeyProtector
{
    private static readonly byte[] Entropy = "Agamemnon quarantine key v1"u8.ToArray();

    public byte[] Protect(byte[] secret) => ProtectedData.Protect(secret, Entropy, scope);

    public byte[] Unprotect(byte[] protectedSecret) => ProtectedData.Unprotect(protectedSecret, Entropy, scope);
}

/// <summary>API keys, DPAPI-encrypted for the current user in a small JSON file.</summary>
public sealed class DpapiSecretStore(string path) : ISecretStore
{
    private static readonly byte[] Entropy = "Agamemnon secrets v1"u8.ToArray();
    private readonly Lock _gate = new();

    public string? GetSecret(string name)
    {
        lock (_gate)
        {
            Dictionary<string, string> all = Load();
            if (!all.TryGetValue(name, out string? blob))
            {
                return null;
            }

            try
            {
                return Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(blob), Entropy, DataProtectionScope.CurrentUser));
            }
            catch (Exception ex) when (ex is CryptographicException or FormatException)
            {
                return null;
            }
        }
    }

    public void SetSecret(string name, string? value)
    {
        lock (_gate)
        {
            Dictionary<string, string> all = Load();
            if (string.IsNullOrWhiteSpace(value))
            {
                all.Remove(name);
            }
            else
            {
                byte[] blob = ProtectedData.Protect(Encoding.UTF8.GetBytes(value.Trim()), Entropy, DataProtectionScope.CurrentUser);
                all[name] = Convert.ToBase64String(blob);
            }

            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, JsonSerializer.Serialize(all));
        }
    }

    private Dictionary<string, string> Load()
    {
        try
        {
            return File.Exists(path)
                ? JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(path)) ?? []
                : [];
        }
        catch (Exception ex) when (ex is JsonException or IOException)
        {
            return [];
        }
    }
}

/// <summary>TXT lookups through the Windows DNS client (DnsQuery_W), bypassing its cache.</summary>
public sealed partial class WindowsTxtResolver : ISystemTxtResolver
{
    private const ushort DnsTypeText = 16;
    private const uint DnsQueryBypassCache = 0x00000008;
    private const int DnsErrorNameError = 9003;
    private const int DnsInfoNoRecords = 9501;

    public Task<IReadOnlyList<IReadOnlyList<string>>> QueryTxtAsync(string name, CancellationToken cancellationToken) =>
        Task.Run(() => Query(name), cancellationToken);

    private static IReadOnlyList<IReadOnlyList<string>> Query(string name)
    {
        int status = DnsQuery_W(name, DnsTypeText, DnsQueryBypassCache, IntPtr.Zero, out IntPtr records, IntPtr.Zero);
        if (status is DnsErrorNameError or DnsInfoNoRecords)
        {
            return [];
        }

        if (status != 0)
        {
            throw new IOException($"DNS lookup of {name} failed (error {status}).");
        }

        var results = new List<IReadOnlyList<string>>();
        try
        {
            // DNS_RECORDW: pNext, pName, WORD wType, WORD wDataLength, DWORD Flags, DWORD dwTtl, DWORD dwReserved, then Data.
            int dataOffset = (2 * IntPtr.Size) + 16;
            for (IntPtr record = records; record != IntPtr.Zero; record = Marshal.ReadIntPtr(record))
            {
                if ((ushort)Marshal.ReadInt16(record, 2 * IntPtr.Size) != DnsTypeText)
                {
                    continue;
                }

                // DNS_TXT_DATAW: DWORD dwStringCount; PWSTR pStringArray[] (pointer-aligned).
                int count = Marshal.ReadInt32(record, dataOffset);
                var strings = new List<string>(count);
                for (int i = 0; i < count; i++)
                {
                    IntPtr text = Marshal.ReadIntPtr(record, dataOffset + IntPtr.Size + (i * IntPtr.Size));
                    strings.Add(Marshal.PtrToStringUni(text) ?? string.Empty);
                }

                results.Add(strings);
            }
        }
        finally
        {
            DnsFree(records, 1 /* DnsFreeRecordList */);
        }

        return results;
    }

    [LibraryImport("dnsapi.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int DnsQuery_W(string name, ushort type, uint options, IntPtr extra, out IntPtr results, IntPtr reserved);

    [LibraryImport("dnsapi.dll")]
    private static partial void DnsFree(IntPtr data, int freeType);
}

/// <summary>Name (SSID) of the Wi-Fi network this PC is connected to, via the native Wi-Fi API.</summary>
public static partial class WifiNetwork
{
    public static string? CurrentSsid()
    {
        if (WlanOpenHandle(2, IntPtr.Zero, out _, out IntPtr client) != 0)
        {
            return null; // no WLAN service (e.g. desktop without Wi-Fi)
        }

        try
        {
            if (WlanEnumInterfaces(client, IntPtr.Zero, out IntPtr list) != 0)
            {
                return null;
            }

            try
            {
                // WLAN_INTERFACE_INFO_LIST: DWORD count, DWORD index, then WLAN_INTERFACE_INFO[] (GUID, WCHAR[256], state) = 532 bytes each.
                int count = Marshal.ReadInt32(list);
                for (int i = 0; i < count; i++)
                {
                    IntPtr info = list + 8 + (i * 532);
                    const int Connected = 1;
                    if (Marshal.ReadInt32(info, 16 + 512) != Connected)
                    {
                        continue;
                    }

                    Guid interfaceGuid = Marshal.PtrToStructure<Guid>(info);
                    if (WlanQueryInterface(client, ref interfaceGuid, 7 /* current_connection */, IntPtr.Zero, out _, out IntPtr attributes, out _) != 0)
                    {
                        continue;
                    }

                    try
                    {
                        // WLAN_CONNECTION_ATTRIBUTES: state, mode, WCHAR profile[256], then DOT11_SSID { ULONG length; UCHAR ssid[32]; }.
                        int length = Marshal.ReadInt32(attributes, 8 + 512);
                        if (length is <= 0 or > 32)
                        {
                            continue;
                        }

                        byte[] ssid = new byte[length];
                        Marshal.Copy(attributes + 8 + 512 + 4, ssid, 0, length);
                        return Encoding.UTF8.GetString(ssid);
                    }
                    finally
                    {
                        WlanFreeMemory(attributes);
                    }
                }

                return null;
            }
            finally
            {
                WlanFreeMemory(list);
            }
        }
        finally
        {
            _ = WlanCloseHandle(client, IntPtr.Zero);
        }
    }

    [LibraryImport("wlanapi.dll")]
    private static partial uint WlanOpenHandle(uint clientVersion, IntPtr reserved, out uint negotiatedVersion, out IntPtr clientHandle);

    [LibraryImport("wlanapi.dll")]
    private static partial uint WlanCloseHandle(IntPtr clientHandle, IntPtr reserved);

    [LibraryImport("wlanapi.dll")]
    private static partial uint WlanEnumInterfaces(IntPtr clientHandle, IntPtr reserved, out IntPtr interfaceList);

    [LibraryImport("wlanapi.dll")]
    private static partial uint WlanQueryInterface(IntPtr clientHandle, ref Guid interfaceGuid, int opCode, IntPtr reserved, out uint dataSize, out IntPtr data, out int opcodeValueType);

    [LibraryImport("wlanapi.dll")]
    private static partial void WlanFreeMemory(IntPtr memory);
}
