<#
.SYNOPSIS
  Builds the signed Agamemnon MSI.

  1. Publishes the app and the service (self-contained, win-x64) into one folder.
  2. Adds the ClamAV and YARA engines (build/fetch-deps.ps1). The bundled YARA rules come
     with the app's publish output.
  3. Authenticode-signs Agamemnon's own executables and DLLs.
  4. Builds the MSI with WiX and signs it.

  Signing uses a code-signing certificate from a PFX file:
    $env:AGAMEMNON_SIGN_PFX      path to the .pfx
    $env:AGAMEMNON_SIGN_PASSWORD its password
  Without them the build still completes, unsigned, with a warning (fine for testing,
  not for distribution: SmartScreen warns about unsigned installers).
#>
param(
    [string]$Version = '1.0.0',
    [switch]$AllowUnpinned
)
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$publish = Join-Path $root 'artifacts\publish'
$output = Join-Path $root 'artifacts'
if (Test-Path $publish) { Remove-Item -Recurse -Force $publish }

foreach ($project in 'src\Agamemnon.App', 'src\Agamemnon.Service') {
    dotnet publish (Join-Path $root $project) -c Release -r win-x64 --self-contained `
        -p:Version=$Version -p:PublishReadyToRun=true -p:DebugType=none -o $publish
    if ($LASTEXITCODE -ne 0) { throw "publish of $project failed" }
}

& (Join-Path $PSScriptRoot 'fetch-deps.ps1') -AllowUnpinned:$AllowUnpinned
Copy-Item -Recurse (Join-Path $root 'deps\clamav') (Join-Path $publish 'engines\clamav')
Copy-Item -Recurse (Join-Path $root 'deps\yara') (Join-Path $publish 'engines\yara')
if (-not (Test-Path (Join-Path $publish 'rules\agamemnon-windows.yar'))) { throw 'bundled YARA rules missing from publish output' }

function Invoke-Sign([string[]]$Files) {
    if (-not $env:AGAMEMNON_SIGN_PFX) {
        Write-Warning 'AGAMEMNON_SIGN_PFX not set: skipping Authenticode signing.'
        return
    }
    $signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" |
        Sort-Object FullName -Descending | Select-Object -First 1
    & $signtool.FullName sign /fd SHA256 /td SHA256 /tr 'http://timestamp.digicert.com' `
        /f $env:AGAMEMNON_SIGN_PFX /p $env:AGAMEMNON_SIGN_PASSWORD /d 'Agamemnon' $Files
    if ($LASTEXITCODE -ne 0) { throw 'signing failed' }
}

Invoke-Sign @(Get-ChildItem $publish -Filter 'Agamemnon*' -Include '*.exe', '*.dll' -Recurse | ForEach-Object FullName)

dotnet build (Join-Path $root 'installer\Agamemnon.Installer.wixproj') -c Release `
    -p:Version=$Version -p:PublishDir="$publish\" -o $output
if ($LASTEXITCODE -ne 0) { throw 'MSI build failed' }

$msi = Join-Path $output "Agamemnon-$Version-x64.msi"
Invoke-Sign @($msi)
Write-Host "Built $msi"
