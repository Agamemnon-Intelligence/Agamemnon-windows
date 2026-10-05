using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Agamemnon.Core.Scanning;
using Microsoft.Win32.SafeHandles;

namespace Agamemnon.Platform.Windows;

/// <summary>
/// Verifies Authenticode signatures with WinVerifyTrust, the same check Windows uses before
/// running a downloaded program. Files without an embedded signature are looked up in the
/// system security catalogs, so catalog-signed Windows components count as signed.
/// </summary>
public sealed partial class AuthenticodeVerifier : ISignatureVerifier
{
    private const int TrustENoSignature = unchecked((int)0x800B0100);
    private const int TrustESubjectFormUnknown = unchecked((int)0x800B0003);
    private const int TrustEProviderUnknown = unchecked((int)0x800B0001);
    private const int TrustESubjectNotTrusted = unchecked((int)0x800B0004);
    private const int TrustEExplicitDistrust = unchecked((int)0x800B0111);
    private const int TrustEBadDigest = unchecked((int)0x80096010);
    private const int CertEUntrustedRoot = unchecked((int)0x800B0109);
    private const int CertEChaining = unchecked((int)0x800B010A);
    private const int CertEUntrustedTestRoot = unchecked((int)0x800B010D);
    private const int CertERevoked = unchecked((int)0x800B010C);
    private const int CertEExpired = unchecked((int)0x800B0101);
    private const int CertERevocationFailure = unchecked((int)0x800B010E);
    private const int CryptEBadMsg = unchecked((int)0x8009200D);

    private const uint WtdUiNone = 2;
    private const uint WtdRevokeNone = 0;
    private const uint WtdRevokeWholeChain = 1;
    private const uint WtdChoiceFile = 1;
    private const uint WtdChoiceCatalog = 2;
    private const uint WtdStateActionVerify = 1;
    private const uint WtdStateActionClose = 2;
    private const uint WtdRevocationCheckChainExcludeRoot = 0x80;
    private const uint WtdCacheOnlyUrlRetrieval = 0x1000;

    private static Guid s_genericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    public SignatureInfo Verify(string path, bool onlineRevocationCheck)
    {
        int result = VerifyEmbedded(path, onlineRevocationCheck);
        if (result is TrustENoSignature or TrustESubjectFormUnknown or TrustEProviderUnknown)
        {
            (int catalogResult, string? catalogFile) = VerifyCatalog(path, onlineRevocationCheck);
            if (catalogFile is null)
            {
                return new SignatureInfo(SignatureState.Unsigned);
            }

            return Map(catalogResult, Publisher(catalogFile));
        }

        return Map(result, Publisher(path));
    }

    private static SignatureInfo Map(int result, string? publisher) => result switch
    {
        0 => new SignatureInfo(SignatureState.Trusted, publisher),
        TrustENoSignature or TrustESubjectFormUnknown or TrustEProviderUnknown => new SignatureInfo(SignatureState.Unsigned),
        CertEUntrustedRoot or CertEChaining or CertEUntrustedTestRoot or TrustESubjectNotTrusted => new SignatureInfo(SignatureState.UntrustedRoot, publisher),
        TrustEBadDigest or CryptEBadMsg => new SignatureInfo(SignatureState.Invalid, publisher),
        CertERevoked => new SignatureInfo(SignatureState.Revoked, publisher),
        CertEExpired => new SignatureInfo(SignatureState.Expired, publisher),
        TrustEExplicitDistrust => new SignatureInfo(SignatureState.Distrusted, publisher),
        CertERevocationFailure => new SignatureInfo(SignatureState.Unknown, publisher, "Couldn't check whether the certificate was revoked."),
        _ => new SignatureInfo(SignatureState.Unknown, publisher, $"WinVerifyTrust returned 0x{result:X8}"),
    };

    private static string? Publisher(string signedFile)
    {
        try
        {
#pragma warning disable SYSLIB0057 // Reading the signer of a signed file, not loading a certificate file.
            using X509Certificate signer = X509Certificate.CreateFromSignedFile(signedFile);
#pragma warning restore SYSLIB0057
            using var certificate = new X509Certificate2(signer);
            return certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            return null;
        }
    }

    private static uint ProviderFlags(bool online) =>
        WtdRevocationCheckChainExcludeRoot | (online ? 0 : WtdCacheOnlyUrlRetrieval);

    private static unsafe int VerifyEmbedded(string path, bool online)
    {
        fixed (char* filePath = path)
        {
            var fileInfo = new WinTrustFileInfo
            {
                CbStruct = (uint)sizeof(WinTrustFileInfo),
                FilePath = (IntPtr)filePath,
            };
            var data = new WinTrustData
            {
                CbStruct = (uint)sizeof(WinTrustData),
                UiChoice = WtdUiNone,
                RevocationChecks = online ? WtdRevokeWholeChain : WtdRevokeNone,
                UnionChoice = WtdChoiceFile,
                Union = (IntPtr)(&fileInfo),
                StateAction = WtdStateActionVerify,
                ProvFlags = ProviderFlags(online),
            };
            return VerifyAndClose(ref data);
        }
    }

    private static unsafe (int Result, string? CatalogFile) VerifyCatalog(string path, bool online)
    {
        using SafeFileHandle file = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        foreach (string algorithm in (string[])["SHA256", "SHA1"])
        {
            if (!CryptCATAdminAcquireContext2(out IntPtr admin, IntPtr.Zero, algorithm, IntPtr.Zero, 0))
            {
                continue;
            }

            try
            {
                uint hashLength = 0;
                CryptCATAdminCalcHashFromFileHandle2(admin, file.DangerousGetHandle(), ref hashLength, null, 0);
                if (hashLength == 0)
                {
                    continue;
                }

                byte[] hash = new byte[hashLength];
                fixed (byte* hashPtr = hash)
                {
                    if (!CryptCATAdminCalcHashFromFileHandle2(admin, file.DangerousGetHandle(), ref hashLength, hashPtr, 0))
                    {
                        continue;
                    }

                    IntPtr catalog = CryptCATAdminEnumCatalogFromHash(admin, hashPtr, hashLength, 0, IntPtr.Zero);
                    if (catalog == IntPtr.Zero)
                    {
                        continue;
                    }

                    try
                    {
                        var info = new CatalogInfo { CbStruct = (uint)sizeof(CatalogInfo) };
                        if (!CryptCATCatalogInfoFromContext(catalog, ref info, 0))
                        {
                            continue;
                        }

                        string catalogFile = new(info.CatalogFile, 0, 260);
                        catalogFile = catalogFile[..Math.Max(0, catalogFile.IndexOf('\0', StringComparison.Ordinal))];
                        string memberTag = Convert.ToHexString(hash);
                        fixed (char* catalogPath = catalogFile)
                        fixed (char* tag = memberTag)
                        fixed (char* memberPath = path)
                        {
                            var catalogData = new WinTrustCatalogInfo
                            {
                                CbStruct = (uint)sizeof(WinTrustCatalogInfo),
                                CatalogFilePath = (IntPtr)catalogPath,
                                MemberTag = (IntPtr)tag,
                                MemberFilePath = (IntPtr)memberPath,
                                MemberFile = file.DangerousGetHandle(),
                                CalculatedFileHash = (IntPtr)hashPtr,
                                CalculatedFileHashLength = hashLength,
                                CatAdmin = admin,
                            };
                            var data = new WinTrustData
                            {
                                CbStruct = (uint)sizeof(WinTrustData),
                                UiChoice = WtdUiNone,
                                RevocationChecks = online ? WtdRevokeWholeChain : WtdRevokeNone,
                                UnionChoice = WtdChoiceCatalog,
                                Union = (IntPtr)(&catalogData),
                                StateAction = WtdStateActionVerify,
                                ProvFlags = ProviderFlags(online),
                            };
                            return (VerifyAndClose(ref data), catalogFile);
                        }
                    }
                    finally
                    {
                        CryptCATAdminReleaseCatalogContext(admin, catalog, 0);
                    }
                }
            }
            finally
            {
                CryptCATAdminReleaseContext(admin, 0);
            }
        }

        return (TrustENoSignature, null);
    }

    private static int VerifyAndClose(ref WinTrustData data)
    {
        int result = WinVerifyTrust(new IntPtr(-1), ref s_genericVerifyV2, ref data);
        data.StateAction = WtdStateActionClose;
        WinVerifyTrust(new IntPtr(-1), ref s_genericVerifyV2, ref data);
        return result;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustFileInfo
    {
        public uint CbStruct;
        public IntPtr FilePath;
        public IntPtr File;
        public IntPtr KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustCatalogInfo
    {
        public uint CbStruct;
        public uint CatalogVersion;
        public IntPtr CatalogFilePath;
        public IntPtr MemberTag;
        public IntPtr MemberFilePath;
        public IntPtr MemberFile;
        public IntPtr CalculatedFileHash;
        public uint CalculatedFileHashLength;
        public IntPtr CatalogContext;
        public IntPtr CatAdmin;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
    {
        public uint CbStruct;
        public IntPtr PolicyCallbackData;
        public IntPtr SipClientData;
        public uint UiChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public IntPtr Union;
        public uint StateAction;
        public IntPtr StateData;
        public IntPtr UrlReference;
        public uint ProvFlags;
        public uint UiContext;
        public IntPtr SignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct CatalogInfo
    {
        public uint CbStruct;
        public fixed char CatalogFile[260];
    }

    [LibraryImport("wintrust.dll")]
    private static partial int WinVerifyTrust(IntPtr hwnd, ref Guid actionId, ref WinTrustData data);

    [LibraryImport("wintrust.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CryptCATAdminAcquireContext2(out IntPtr catAdmin, IntPtr subsystem, string hashAlgorithm, IntPtr strongHashPolicy, uint flags);

    [LibraryImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool CryptCATAdminCalcHashFromFileHandle2(IntPtr catAdmin, IntPtr file, ref uint hashLength, byte* hash, uint flags);

    [LibraryImport("wintrust.dll", SetLastError = true)]
    private static unsafe partial IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr catAdmin, byte* hash, uint hashLength, uint flags, IntPtr previousCatalog);

    [LibraryImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CryptCATCatalogInfoFromContext(IntPtr catalog, ref CatalogInfo info, uint flags);

    [LibraryImport("wintrust.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CryptCATAdminReleaseCatalogContext(IntPtr catAdmin, IntPtr catalog, uint flags);

    [LibraryImport("wintrust.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CryptCATAdminReleaseContext(IntPtr catAdmin, uint flags);
}
