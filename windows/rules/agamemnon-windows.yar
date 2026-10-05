/*
    Agamemnon starter rules for Windows threats.

    Tags decide how a match is reported:
      malicious   → shown as a threat and quarantined automatically for downloads
      suspicious  → shown as a warning for the user to judge

    These are deliberately narrow: they look for combinations that legitimate software rarely
    has. Add your own rule files (.yar/.yara) to %LOCALAPPDATA%\Agamemnon\Rules.
    License: GPL-2.0, like the rest of Agamemnon.
*/

rule Agamemnon_EICAR_Test_File : malicious
{
    meta:
        description = "EICAR anti-virus test file (harmless; used to check that scanning works)"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar at 0 and filesize < 256
}

rule Agamemnon_PowerShell_Download_And_Execute : suspicious
{
    meta:
        description = "PowerShell that downloads code and runs it straight from memory"
    strings:
        $exec1 = "IEX" fullword ascii wide
        $exec2 = "Invoke-Expression" nocase ascii wide
        $exec3 = "iex(" nocase ascii wide
        $dl1 = "DownloadString" nocase ascii wide
        $dl2 = "DownloadData" nocase ascii wide
        $dl3 = "Net.WebClient" nocase ascii wide
        $dl4 = "Invoke-WebRequest" nocase ascii wide
        $dl5 = "Invoke-RestMethod" nocase ascii wide
        $dl6 = "Start-BitsTransfer" nocase ascii wide
    condition:
        filesize < 5MB and any of ($exec*) and any of ($dl*)
}

rule Agamemnon_PowerShell_Hidden_Encoded_Command : suspicious
{
    meta:
        description = "Launches PowerShell hidden with a base64-encoded command, a common malware launcher"
    strings:
        $ps = "powershell" nocase ascii wide
        $enc1 = /-e(nc|ncodedcommand)?\s+[A-Za-z0-9+\/]{40,}/ nocase ascii wide
        $hidden1 = /-w(indowstyle)?\s+h(idden)?\b/ nocase ascii wide
        $hidden2 = "-nop" nocase ascii wide
        $hidden3 = "-noni" nocase ascii wide
    condition:
        filesize < 10MB and $ps and $enc1 and any of ($hidden*)
}

rule Agamemnon_PowerShell_Shellcode_Runner : suspicious
{
    meta:
        description = "PowerShell script that allocates executable memory and starts a thread in it"
    strings:
        $a1 = "VirtualAlloc" ascii wide nocase
        $a2 = "CreateThread" ascii wide nocase
        $a3 = "GetDelegateForFunctionPointer" ascii wide nocase
        $b1 = "System.Runtime.InteropServices" ascii wide nocase
        $b2 = "Add-Type" ascii wide nocase
        $b3 = "[DllImport" ascii wide nocase
    condition:
        filesize < 5MB and uint16(0) != 0x5A4D and 2 of ($a*) and any of ($b*)
}

rule Agamemnon_AMSI_Bypass : suspicious
{
    meta:
        description = "Tries to switch off the Antimalware Scan Interface so scripts can't be inspected"
    strings:
        $a = "AmsiUtils" ascii wide nocase
        $b = "amsiInitFailed" ascii wide nocase
        $c = "AmsiScanBuffer" ascii wide nocase
        $patch = "VirtualProtect" ascii wide nocase
    condition:
        filesize < 10MB and (($a and $b) or ($c and $patch and uint16(0) != 0x5A4D))
}

rule Agamemnon_Defender_Tampering : suspicious
{
    meta:
        description = "Turns off Microsoft Defender protection or excludes whole drives from it"
    strings:
        $set = "Set-MpPreference" ascii wide nocase
        $add = "Add-MpPreference" ascii wide nocase
        $off1 = "-DisableRealtimeMonitoring" ascii wide nocase
        $off2 = "-DisableBehaviorMonitoring" ascii wide nocase
        $off3 = "-DisableIOAVProtection" ascii wide nocase
        $excl = /-ExclusionPath\s+["']?[A-Za-z]:\\?["']?(\s|$|;)/ ascii wide nocase
    condition:
        filesize < 20MB and (($set and any of ($off*)) or ($add and $excl))
}

rule Agamemnon_Shadow_Copy_Deletion : suspicious
{
    meta:
        description = "Deletes Windows backups and recovery options, the opening move of most ransomware"
    strings:
        $v1 = /vssadmin(\.exe)?\s+delete\s+shadows/ nocase ascii wide
        $v2 = /wmic(\.exe)?\s+shadowcopy\s+delete/ nocase ascii wide
        $v3 = /bcdedit(\.exe)?\s+\/set\s+\{default\}\s+recoveryenabled\s+no/ nocase ascii wide
        $v4 = /wbadmin(\.exe)?\s+delete\s+catalog/ nocase ascii wide
        $v5 = "Win32_ShadowCopy" ascii wide nocase
        $v6 = ".Delete()" ascii wide
    condition:
        filesize < 30MB and (any of ($v1, $v2, $v3, $v4) or ($v5 and $v6))
}

rule Agamemnon_Browser_Credential_Stealer : suspicious
{
    meta:
        description = "Program that reads saved browser passwords and cookies and has a way to send them out"
    strings:
        $p1 = "\\User Data\\Default\\Login Data" ascii wide nocase
        $p2 = "\\User Data\\Local State" ascii wide nocase
        $p3 = "\\Network\\Cookies" ascii wide nocase
        $p4 = "logins.json" ascii wide
        $p5 = "key4.db" ascii wide
        $p6 = "encrypted_key" ascii wide
        $x1 = "api.telegram.org/bot" ascii wide nocase
        $x2 = "discord.com/api/webhooks" ascii wide nocase
        $x3 = "discordapp.com/api/webhooks" ascii wide nocase
        $x4 = "multipart/form-data" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and filesize < 30MB and 3 of ($p*) and any of ($x*)
}

rule Agamemnon_Discord_Token_Grabber : suspicious
{
    meta:
        description = "Reads Discord's local storage for login tokens and posts them to a webhook"
    strings:
        $store = "\\discord\\Local Storage\\leveldb" ascii wide nocase
        $token = /\[\\w-\]\{24\}\\\.\[\\w-\]\{6\}\\\.\[\\w-\]\{27\}/ ascii wide
        $hook1 = "discord.com/api/webhooks" ascii wide nocase
        $hook2 = "discordapp.com/api/webhooks" ascii wide nocase
    condition:
        filesize < 30MB and $store and ($token or any of ($hook*))
}

rule Agamemnon_Mimikatz : malicious
{
    meta:
        description = "Mimikatz credential-dumping tool"
        reference = "https://github.com/gentilkiwi/mimikatz"
    strings:
        $s1 = "sekurlsa::logonpasswords" ascii wide nocase
        $s2 = "lsadump::sam" ascii wide nocase
        $s3 = "gentilkiwi" ascii wide nocase
        $s4 = "privilege::debug" ascii wide nocase
        $s5 = "kerberos::golden" ascii wide nocase
    condition:
        filesize < 20MB and 3 of them
}

rule Agamemnon_Script_Downloader : suspicious
{
    meta:
        description = "VBScript/JScript that downloads a file, saves it and runs it"
    strings:
        $http1 = "MSXML2.XMLHTTP" ascii wide nocase
        $http2 = "WinHttp.WinHttpRequest" ascii wide nocase
        $http3 = "MSXML2.ServerXMLHTTP" ascii wide nocase
        $save = "ADODB.Stream" ascii wide nocase
        $run1 = "WScript.Shell" ascii wide nocase
        $run2 = "Shell.Application" ascii wide nocase
    condition:
        filesize < 2MB and uint16(0) != 0x5A4D and any of ($http*) and $save and any of ($run*)
}

rule Agamemnon_Shortcut_Launching_Interpreter : suspicious
{
    meta:
        description = "Windows shortcut (.lnk) that runs a script interpreter with arguments, a common phishing payload"
    strings:
        $i1 = "powershell" ascii wide nocase
        $i2 = "mshta" ascii wide nocase
        $i3 = "wscript" ascii wide nocase
        $i4 = "cscript" ascii wide nocase
        $i5 = "rundll32" ascii wide nocase
        $i6 = "regsvr32" ascii wide nocase
        $i7 = "certutil" ascii wide nocase
        $i8 = "bitsadmin" ascii wide nocase
        $arg1 = "http" ascii wide nocase
        $arg2 = "-enc" ascii wide nocase
        $arg3 = "javascript:" ascii wide nocase
        $arg4 = "/c " ascii wide nocase
    condition:
        uint32(0) == 0x0000004C and uint32(4) == 0x00021401 and filesize < 1MB and any of ($i*) and any of ($arg*)
}

rule Agamemnon_HTA_Executes_Code : suspicious
{
    meta:
        description = "HTML application (.hta) that runs commands or PowerShell"
    strings:
        $hta = "<hta:application" ascii wide nocase
        $x1 = "WScript.Shell" ascii wide nocase
        $x2 = "powershell" ascii wide nocase
        $x3 = ".Run(" ascii wide nocase
        $x4 = "GetObject(" ascii wide nocase
    condition:
        filesize < 5MB and $hta and 2 of ($x*)
}

rule Agamemnon_Office_Remote_Template : suspicious
{
    meta:
        description = "Office document that fetches a template from the internet when opened (template injection)"
    strings:
        $rel = "relationships/attachedTemplate" ascii
        $remote = /Target="https?:\/\/[^"]+"/ ascii
        $external = "TargetMode=\"External\"" ascii
    condition:
        filesize < 1MB and $rel and $remote and $external
}

rule Agamemnon_LOLBin_Payload_Fetch : suspicious
{
    meta:
        description = "Uses built-in Windows tools (certutil, bitsadmin, mshta, regsvr32) to fetch or run remote code"
    strings:
        $c1 = /certutil(\.exe)?\s+(-|\/)urlcache\s+(-|\/)(split\s+(-|\/))?f\s+https?:/ nocase ascii wide
        $c2 = /bitsadmin(\.exe)?\s+\/transfer\s+\S+\s+https?:/ nocase ascii wide
        $c3 = /mshta(\.exe)?\s+["']?https?:/ nocase ascii wide
        $c4 = /regsvr32(\.exe)?\s+\/s\s+\/n\s+\/u\s+\/i:https?:/ nocase ascii wide
        $c5 = /certutil(\.exe)?\s+(-|\/)decode\s/ nocase ascii wide
    condition:
        filesize < 10MB and any of them
}
