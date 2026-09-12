$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (!(Test-Path ".\nvngx.dll")) {
    throw "nvngx.dll is missing"
}
if (!(Test-Path ".\nvngx_dlssnr.dll")) {
    throw "Copy the same nvngx_dlssnr.dll that worked in NeuralScreen into this folder."
}
if (!(Test-Path ".\magpie-dlssnr-bridge-client.exe")) {
    throw "magpie-dlssnr-bridge-client.exe is missing"
}

Remove-Item ".\magpie-dlssnr-worker-bridge.log" -ErrorAction SilentlyContinue

& ".\magpie-dlssnr-bridge-client.exe"
$rc = $LASTEXITCODE

Write-Host ""
Write-Host "client exit code:" $rc
Write-Host "worker log:" (Join-Path $PSScriptRoot "magpie-dlssnr-worker-bridge.log")
exit $rc
