<#
.SYNOPSIS
  Authenticode-signs files with the certificate in $env:AGAMEMNON_SIGN_PFX / $env:AGAMEMNON_SIGN_PASSWORD.
  Without a certificate it warns and leaves the files unsigned.
#>
param([Parameter(Mandatory, ValueFromRemainingArguments)][string[]]$Files)
$ErrorActionPreference = 'Stop'

if (-not $env:AGAMEMNON_SIGN_PFX) {
    Write-Warning 'AGAMEMNON_SIGN_PFX not set: skipping Authenticode signing.'
    return
}
$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" |
    Sort-Object FullName -Descending | Select-Object -First 1
& $signtool.FullName sign /fd SHA256 /td SHA256 /tr 'http://timestamp.digicert.com' `
    /f $env:AGAMEMNON_SIGN_PFX /p $env:AGAMEMNON_SIGN_PASSWORD /d 'Agamemnon' $Files
if ($LASTEXITCODE -ne 0) { throw 'signing failed' }
